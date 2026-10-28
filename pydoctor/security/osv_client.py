"""
pydoctor/security/osv_client.py
────────────────────────────────
OSV (Open Source Vulnerabilities) API client.

Queries the OSV.dev batch API to find known vulnerabilities for a set of
installed Python packages.

API documentation: https://google.github.io/osv.dev/api/

Design
──────
- Uses the ``/v1/querybatch`` endpoint for efficiency (one HTTP call for
  all packages rather than N sequential calls).
- Caches results per package+version pair via ``CacheManager``.
- Responses are normalised into a flat ``VulnerabilityRecord`` dataclass.
"""

from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests
from packaging.version import InvalidVersion, Version

from pydoctor.cache.cache_manager import CacheManager
from pydoctor.config.settings import (
    MAX_WORKERS,
    OSV_API_URL,
    OSV_BATCH_SIZE,
    REQUEST_TIMEOUT,
)
from pydoctor.security.cvss import base_score, rating

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"

# Bump when the parsed record format or severity logic changes, so results
# cached by an older PyDoctor are not reused.
_CACHE_SCHEMA = "v2"

# ──────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────


@dataclass
class VulnerabilityRecord:
    """
    Normalised representation of a single vulnerability from OSV.

    Attributes
    ----------
    vuln_id:     OSV / CVE / GHSA identifier (e.g. "GHSA-xxxx-yyyy").
    package:     Affected package name.
    version:     Installed version being flagged.
    summary:     Short one-line description.
    severity:    CVSS severity string (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN).
    aliases:     Alternative identifiers (CVE, GHSA …).
    fixed_in:    Version in which the issue was fixed (empty if not yet fixed).
    references:  Advisory / patch URLs.
    """

    vuln_id: str
    package: str
    version: str
    summary: str
    severity: str = "UNKNOWN"
    aliases: list[str] = field(default_factory=list)
    fixed_in: str = ""
    references: list[str] = field(default_factory=list)
    cvss_score: float | None = None

    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id,
            "package": self.package,
            "version": self.version,
            "summary": self.summary,
            "severity": self.severity,
            "aliases": self.aliases,
            "fixed_in": self.fixed_in,
            "references": self.references,
            "cvss_score": self.cvss_score,
        }


# ──────────────────────────────────────────────────────────────
# OSV Client
# ──────────────────────────────────────────────────────────────


class OSVClient:
    """
    Client for the OSV vulnerability database.

    Parameters
    ----------
    cache: CacheManager instance (optional — creates one if not provided).
    timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        cache: CacheManager | None = None,
        timeout: int = REQUEST_TIMEOUT,
        read_cache: bool = True,
    ) -> None:
        self._cache = cache or CacheManager()
        self._timeout = timeout
        # False for --no-cache: ignore cached results but still refresh them.
        self._read_cache = read_cache
        self._session = requests.Session()
        # Packages whose OSV lookup could not be completed (network error,
        # timeout, or a non-2xx response after all retries). Callers must
        # check this: an empty result list does NOT mean "no vulnerabilities"
        # when this list is non-empty.
        self.failed_packages: list[str] = []
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    # ── Public API ─────────────────────────────────────────────

    def query_packages(
        self,
        packages: dict[str, str],
    ) -> list[VulnerabilityRecord]:
        """
        Query OSV for vulnerabilities in all given packages.

        Parameters
        ----------
        packages: dict[str, str]
            Mapping of {package_name: installed_version}.

        Returns
        -------
        list[VulnerabilityRecord]
            All vulnerabilities found. Packages that could not be checked
            are recorded in ``self.failed_packages``.
        """
        self.failed_packages = []
        if not packages:
            return []

        records: list[VulnerabilityRecord] = []
        items = list(packages.items())

        # Process in batches to stay within API limits
        for i in range(0, len(items), OSV_BATCH_SIZE):
            batch = dict(items[i : i + OSV_BATCH_SIZE])
            records.extend(self._query_batch(batch))

        return records

    # ── Private helpers ────────────────────────────────────────

    def _cache_key(self, name: str, version: str) -> str:
        """Build a deterministic cache key for a package+version pair."""
        raw = f"osv:{_CACHE_SCHEMA}:{name}:{version}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _query_batch(  # noqa: C901
        self,
        packages: dict[str, str],
    ) -> list[VulnerabilityRecord]:
        """
        Query the OSV batch endpoint for a dict of packages.

        First checks the cache for each package; only uncached packages are
        sent to the API. Results are written back to the cache.
        """
        records: list[VulnerabilityRecord] = []
        to_fetch: list[tuple[str, str]] = []  # (name, version) pairs not in cache

        # Check cache first
        for name, version in packages.items():
            key = self._cache_key(name, version)
            cached = self._cache.get(key) if self._read_cache else None
            if cached is not None:
                records.extend([VulnerabilityRecord(**v) for v in cached])
            else:
                to_fetch.append((name, version))

        if not to_fetch:
            return records

        # Build OSV batch payload
        payload = {
            "queries": [
                {
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version,
                }
                for name, version in to_fetch
            ]
        }

        # Try with retries
        retries = 3
        results = []
        for attempt in range(retries):
            try:
                response = self._session.post(
                    OSV_API_URL,
                    data=json.dumps(payload),
                    timeout=self._timeout,
                )
                response.raise_for_status()
                results = response.json().get("results", [])
                break
            except (requests.RequestException, ValueError):
                if attempt == retries - 1:
                    # Final attempt failed. Record the packages we could not
                    # check so the scanner can report an incomplete scan
                    # instead of a clean bill of health.
                    self.failed_packages.extend(name for name, _ in to_fetch)
                    return records
                # Simple exponential backoff: 1s, 2s, 4s...
                time.sleep(2**attempt)

        # The batch endpoint often returns only ids. Fetch the full advisories
        # in parallel (one request per unique id), not one at a time.
        sparse_ids = {
            v["id"]
            for result in results
            for v in result.get("vulns", [])
            if "id" in v and "summary" not in v and "details" not in v
        }
        full = self._fetch_advisories(sorted(sparse_ids))

        # Parse results — one result entry per queried package (in order)
        for (name, version), result in zip(to_fetch, results, strict=False):
            parsed = []
            for v in result.get("vulns", []):
                v = full.get(v.get("id", ""), v)
                if v.get("withdrawn"):
                    continue
                parsed.append(self._parse_vuln(v, name, version))

            records.extend(parsed)

            # Cache the parsed results (as dicts for JSON-serialisability)
            key = self._cache_key(name, version)
            self._cache.set(key, [p.to_dict() for p in parsed], save=False)

        self._cache.save()
        return records

    def _fetch_advisories(self, ids: list[str]) -> dict[str, dict]:
        """Fetch full OSV records for ``ids`` concurrently; failures are skipped."""

        def fetch(vuln_id: str) -> tuple[str, dict | None]:
            try:
                resp = self._session.get(OSV_VULN_URL.format(id=vuln_id), timeout=self._timeout)
                if resp.status_code == 200:
                    return vuln_id, resp.json()
            except (requests.RequestException, ValueError):
                pass
            return vuln_id, None

        if not ids:
            return {}
        with ThreadPoolExecutor(max_workers=max(1, min(MAX_WORKERS, len(ids)))) as pool:
            return {vid: data for vid, data in pool.map(fetch, ids) if data}

    def _parse_vuln(
        self,
        raw: dict,
        package: str,
        version: str,
    ) -> VulnerabilityRecord:
        """
        Parse a single OSV vulnerability JSON object into a VulnerabilityRecord.
        """
        vuln_id = raw.get("id", "UNKNOWN")

        # Safely extract and format a readable summary
        summary = raw.get("summary")
        if not summary:
            details = raw.get("details", "")
            if not details:
                summary = "No detailed description provided by the advisory."
            else:
                summary = " ".join(details.split())
                if len(summary) > 120:
                    summary = summary[:117] + "..."
        else:
            summary = " ".join(summary.split())

        aliases = raw.get("aliases", [])
        refs = [r.get("url", "") for r in raw.get("references", []) if r.get("url")]

        # Determine severity from database_specific or CVSS data
        severity, score = _extract_severity(raw)

        # Find fixed version from affected → ranges
        fixed_in = _extract_fixed_version(raw, package, version)

        return VulnerabilityRecord(
            vuln_id=vuln_id,
            package=package,
            version=version,
            summary=summary,
            severity=severity,
            aliases=aliases,
            fixed_in=fixed_in,
            references=refs[:5],  # cap at 5 references for display
            cvss_score=score,
        )


# ──────────────────────────────────────────────────────────────
# Helper functions (module-level)
# ──────────────────────────────────────────────────────────────


def _extract_severity(raw: dict) -> tuple[str, float | None]:
    """
    Return ``(severity_label, cvss_score)`` for an OSV record.

    Order: the advisory database's own label (GHSA records carry one), then
    the CVSS v3 base score computed from the vector. CVSS v4 and v2 vectors
    aren't scored; without a database label they are reported as UNKNOWN
    rather than guessed.
    """
    score = None
    for sev_entry in raw.get("severity", []):
        if sev_entry.get("type") == "CVSS_V3":
            score = base_score(sev_entry.get("score", ""))
            if score is not None:
                break

    db_specific = raw.get("database_specific") or {}
    if label := db_specific.get("severity"):
        label = str(label).upper()
        return ("MEDIUM" if label == "MODERATE" else label), score

    if score is not None:
        return rating(score), score
    return "UNKNOWN", None


def _parse_version(value: str) -> Version | None:
    try:
        return Version(value)
    except (InvalidVersion, TypeError):
        return None


def _normalise(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _range_events(rng: dict) -> list[tuple[Version, str]]:
    """Parseable (version, kind) events of one range, sorted by version."""
    events = []
    for ev in rng.get("events", []):
        for kind in ("introduced", "fixed", "last_affected"):
            if kind in ev:
                ver = Version("0") if ev[kind] == "0" else _parse_version(ev[kind])
                if ver is not None:
                    events.append((ver, kind))
    return sorted(events, key=lambda e: e[0])


def _pairs_from_events(events: list[tuple[Version, str]]) -> list[tuple[Version, Version | None]]:
    """Turn sorted events into (introduced, fixed-or-None) intervals."""
    pairs: list[tuple[Version, Version | None]] = []
    start: Version | None = None
    for ver, kind in events:
        if kind == "introduced":
            start = ver if start is None else start
        elif start is not None:
            pairs.append((start, ver if kind == "fixed" else None))
            start = None
    if start is not None:
        pairs.append((start, None))
    return pairs


def _ranges_for(raw: dict, package: str) -> list[tuple[Version, Version | None]]:
    """(introduced, fixed) pairs for ``package`` from ECOSYSTEM ranges."""
    pairs: list[tuple[Version, Version | None]] = []
    for affected in raw.get("affected", []):
        pkg_info = affected.get("package", {})
        if pkg_info.get("ecosystem", "").lower() != "pypi":
            continue
        if pkg_info.get("name") and _normalise(pkg_info["name"]) != _normalise(package):
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):  # GIT ranges use commit hashes
                pairs.extend(_pairs_from_events(_range_events(rng)))
    return pairs


def _extract_fixed_version(raw: dict, package: str, installed: str) -> str:
    """
    Return the first fixed version for the range that contains ``installed``.

    An advisory often lists one fix per release line (for example 4.2.17,
    5.0.10 and 5.1.4). Returning the first "fixed" event, as earlier
    versions did, pointed Django 5.1.2 users at 4.2.17. If no range contains
    the installed version, the lowest fixed version above it is used.
    Returns "" when no fix is known.
    """
    ranges = _ranges_for(raw, package)
    fixes = [fixed for _, fixed in ranges if fixed is not None]
    current = _parse_version(installed)
    if current is None:
        return str(min(fixes)) if fixes else ""
    for start, fixed in ranges:
        if start <= current and (fixed is None or current < fixed):
            return str(fixed) if fixed is not None else ""
    later = [f for f in fixes if f > current]
    return str(min(later)) if later else ""
