"""
pydoctor/core/baseline.py
──────────────────────────
Baselines: accept today's issues so CI only fails on new ones.

A project with dozens of existing findings can't turn on a pydoctor CI gate
without it failing on every run. ``pydoctor baseline`` records the current
issues in ``.pydoctor-baseline.json``; later scans hide issues whose
fingerprint is in that file and report how many were hidden. Fixed issues
drop out naturally, and the file can be refreshed at any time.

Problems with the scan itself (an unreadable environment, an unreachable
vulnerability database, a crashed scanner) are never baselined: accepting
them would turn a broken scan into a passing one.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from pathlib import Path

from pydoctor.config.settings import Severity
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.reports.fingerprint import fingerprint

BASELINE_FILE = ".pydoctor-baseline.json"
BASELINE_FORMAT = 1

# Never accepted into a baseline.
NEVER_BASELINE = {"ENV_PACKAGES_UNAVAILABLE", "SEC_SCAN_INCOMPLETE", "SCANNER_ERROR"}
_IGNORED_SEVERITIES = {Severity.OK, Severity.INFO}


class BaselineError(Exception):
    """The baseline file exists but can't be used."""


@dataclass
class BaselineResult:
    path: Path
    suppressed: int = 0
    stale: int = 0
    suppressed_codes: dict[str, int] = field(default_factory=dict)


def _root(report: DiagnosisReport) -> Path:
    return Path(report.ctx.root) if report.ctx is not None else Path(report.scan_path)


def baselinable(issue: Issue) -> bool:
    return issue.severity not in _IGNORED_SEVERITIES and issue.code not in NEVER_BASELINE


def default_path(report: DiagnosisReport) -> Path:
    return _root(report) / BASELINE_FILE


def write_baseline(
    report: DiagnosisReport, path: Path, version: str, scanned_categories: set[str] | None = None
) -> int:
    """
    Record every baselinable issue in ``report``. Returns how many are in the file.

    When ``scanned_categories`` is given (a partial scan such as
    `pydoctor baseline --ci`), entries for categories that weren't scanned are
    kept from the existing file instead of being dropped.
    """
    root = _root(report)
    entries: dict[str, dict] = {}
    if scanned_categories is not None and path.is_file():
        try:
            previous = json.loads(path.read_text(encoding="utf-8")).get("issues", [])
        except (OSError, ValueError):
            previous = []
        for e in previous:
            if e.get("category") not in scanned_categories and "fingerprint" in e:
                entries[e["fingerprint"]] = e
    for issue in report.issues:
        if not baselinable(issue):
            continue
        fp = fingerprint(issue, root)
        entries[fp] = {
            "fingerprint": fp,
            "code": issue.code,
            "category": issue.category,
            "severity": issue.severity,
            "title": issue.title,
        }
    data = {
        "format": BASELINE_FORMAT,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "pydoctor_version": version,
        "issues": sorted(entries.values(), key=lambda e: (e["code"], e["title"])),
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(entries)


def load_fingerprints(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"{path} couldn't be read: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != BASELINE_FORMAT:
        raise BaselineError(
            f"{path} isn't a pydoctor baseline (format {BASELINE_FORMAT}). "
            "Recreate it with `pydoctor baseline`."
        )
    return {e["fingerprint"] for e in data.get("issues", []) if "fingerprint" in e}


def apply_baseline(
    report: DiagnosisReport, path: Path, scanned_categories: set[str]
) -> BaselineResult:
    """
    Remove issues recorded in the baseline from ``report``.

    ``scanned_categories`` limits stale-entry counting to what this scan
    actually checked: `scan-security` can't tell whether a baselined secret
    still exists.
    """
    known = load_fingerprints(path)
    root = _root(report)
    result = BaselineResult(path=path)
    seen: set[str] = set()
    kept: list[Issue] = []
    for issue in report.issues:
        fp = fingerprint(issue, root) if baselinable(issue) else None
        if fp is not None and fp in known:
            seen.add(fp)
            result.suppressed += 1
            result.suppressed_codes[issue.code] = result.suppressed_codes.get(issue.code, 0) + 1
            continue
        kept.append(issue)
    report.issues = kept

    try:
        entries = json.loads(path.read_text(encoding="utf-8")).get("issues", [])
    except (OSError, ValueError):
        entries = []
    result.stale = sum(
        1
        for e in entries
        if e.get("fingerprint") not in seen and e.get("category") in scanned_categories
    )
    report.scanner_meta["baseline"] = {
        "file": str(path),
        "suppressed": result.suppressed,
        "stale": result.stale,
    }
    return result
