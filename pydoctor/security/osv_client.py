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
from dataclasses import dataclass, field
from typing import Optional

import requests

from pydoctor.cache.cache_manager import CacheManager
from pydoctor.config.settings import (
    OSV_API_URL,
    REQUEST_TIMEOUT,
    OSV_BATCH_SIZE,
)


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

    def to_dict(self) -> dict:
        return {
            "id": self.vuln_id,
            "package": self.package,
            "version": self.version,
            "summary": self.summary,
            "severity": self.severity,
            "aliases": self.aliases,
            "fixed_in": self.fixed_in,
            "references": self.references,
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
        cache: Optional[CacheManager] = None,
        timeout: int = REQUEST_TIMEOUT,
    ) -> None:
        self._cache = cache or CacheManager()
        self._timeout = timeout
        self._session = requests.Session()
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
            All vulnerabilities found.  Empty list if none / network error.
        """
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
        raw = f"osv:{name}:{version}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _query_batch(
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
            cached = self._cache.get(key)
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

        try:
            response = self._session.post(
                OSV_API_URL,
                data=json.dumps(payload),
                timeout=self._timeout,
            )
            response.raise_for_status()
            results = response.json().get("results", [])
        except (requests.RequestException, ValueError):
            # Network error — return whatever we got from cache
            return records

        # Parse results — one result entry per queried package (in order)
        for (name, version), result in zip(to_fetch, results):
            vulns = result.get("vulns", [])
            parsed = [self._parse_vuln(v, name, version) for v in vulns]
            records.extend(parsed)

            # Cache the parsed results (as dicts for JSON-serialisability)
            key = self._cache_key(name, version)
            self._cache.set(key, [p.to_dict() for p in parsed])

        return records

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
        summary = raw.get("summary", raw.get("details", "No description.")[:120])
        aliases = raw.get("aliases", [])
        refs = [r.get("url", "") for r in raw.get("references", []) if r.get("url")]

        # Determine severity from database_specific or CVSS data
        severity = _extract_severity(raw)

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
        )


# ──────────────────────────────────────────────────────────────
# Helper functions (module-level)
# ──────────────────────────────────────────────────────────────


def _extract_severity(raw: dict) -> str:
    """
    Extract a human-readable severity level from the OSV vuln JSON.

    OSV severities live in various places depending on the source database.
    We try several paths and default to "UNKNOWN".
    """
    # Try database_specific (common for GHSA)
    db_specific = raw.get("database_specific", {})
    if severity := db_specific.get("severity"):
        return str(severity).upper()

    # Try CVSS v3 via "severity" array
    for sev_entry in raw.get("severity", []):
        score_type = sev_entry.get("type", "")
        score_str = sev_entry.get("score", "")
        if "CVSS" in score_type and score_str:
            # score_str is like "CVSS:3.1/AV:N/AC:L/..."
            return _cvss_to_label(score_str)

    return "UNKNOWN"


def _cvss_to_label(cvss_vector: str) -> str:
    """
    Map a CVSS base score extracted from a vector string to a severity label.

    This is a rough approximation based on the CVSS v3 severity bands.
    """
    # CVSS vectors don't contain the base score inline; use the vector prefix
    # qualifiers as a rough indicator (AV:N + AC:L = higher risk)
    if "AV:N" in cvss_vector and "PR:N" in cvss_vector:
        return "HIGH"
    if "AV:N" in cvss_vector:
        return "MEDIUM"
    return "LOW"


def _extract_fixed_version(raw: dict, package: str, installed: str) -> str:
    """
    Scan the OSV ``affected[].ranges`` for a ``FIXED`` event version.

    Returns the fixed version string or empty string if not found.
    """
    for affected in raw.get("affected", []):
        pkg_info = affected.get("package", {})
        if pkg_info.get("ecosystem", "").lower() != "pypi":
            continue
        # Walk ranges for a FIXED event
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return ""
