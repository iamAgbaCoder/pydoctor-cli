"""
pydoctor/core/report.py
────────────────────────
Canonical data model for diagnostic issues produced by any scanner.

All scanners must return a list of ``Issue`` objects.  The report engine
then collects and aggregates those into a ``DiagnosisReport``.

Data classes are used intentionally — they are lightweight, introspectable,
and serialise well to JSON.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional

from pydoctor.config.settings import Severity

# ──────────────────────────────────────────────────────────────
# Issue — atomic diagnostic finding
# ──────────────────────────────────────────────────────────────


@dataclass
class Issue:
    """
    Represents a single diagnostic finding produced by any scanner.

    Attributes
    ----------
    category:       Top-level grouping (e.g. "environment", "security").
    code:           Short machine-readable identifier (e.g. "PKG_OUTDATED").
    severity:       One of Severity.* constants.
    title:          A concise, human-readable title.
    description:    Full detail explaining the problem.
    recommendation: Actionable fix suggestion shown to the developer.
    package:        Optional package name this issue pertains to.
    extra:          Any additional metadata (version info, CVE ids, etc.).
    """

    category: str
    code: str
    severity: str
    title: str
    description: str
    recommendation: str
    package: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize the issue to a plain dictionary suitable for JSON output."""
        return {
            "category": self.category,
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "package": self.package,
            "extra": self.extra,
        }


# ──────────────────────────────────────────────────────────────
# DiagnosisReport — aggregated result of all scans
# ──────────────────────────────────────────────────────────────


@dataclass
class DiagnosisReport:
    """
    Top-level container that holds all issues found during a scan session.

    Attributes
    ----------
    issues:       Flat list of every ``Issue`` found.
    scan_path:    The project path that was scanned.
    scanned_at:   UTC timestamp of when the scan was performed.
    scan_duration_ms:  How long the full scan took in milliseconds.
    scanner_meta: Optional extra metadata per scanner (timing, counts …).
    """

    issues: list[Issue] = field(default_factory=list)
    scan_path: str = "."
    scanned_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    scan_duration_ms: float = 0.0
    scanner_meta: dict = field(default_factory=dict)

    # ── Convenience helpers ────────────────────────────────────

    def add(self, issue: Issue) -> None:
        """Append a single issue to the report."""
        self.issues.append(issue)

    def extend(self, issues: list[Issue]) -> None:
        """Append multiple issues at once."""
        self.issues.extend(issues)

    @property
    def has_errors(self) -> bool:
        """True if any issue has severity ERROR or CRITICAL."""
        return any(i.severity in (Severity.ERROR, Severity.CRITICAL) for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        """True if any issue has severity WARNING."""
        return any(i.severity == Severity.WARNING for i in self.issues)

    def by_category(self) -> dict[str, list[Issue]]:
        """Return issues grouped by category."""
        result: dict[str, list[Issue]] = {}
        for issue in self.issues:
            result.setdefault(issue.category, []).append(issue)
        return result

    def by_severity(self) -> dict[str, list[Issue]]:
        """Return issues grouped by severity."""
        result: dict[str, list[Issue]] = {}
        for issue in self.issues:
            result.setdefault(issue.severity, []).append(issue)
        return result

    def summary_counts(self) -> dict[str, int]:
        """Return a count of issues per severity level."""
        counts: dict[str, int] = {
            Severity.OK: 0,
            Severity.INFO: 0,
            Severity.WARNING: 0,
            Severity.ERROR: 0,
            Severity.CRITICAL: 0,
        }
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        """Serialize the full report to a plain dictionary for JSON output."""
        return {
            "scan_path": self.scan_path,
            "scanned_at": self.scanned_at,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "summary": self.summary_counts(),
            "issues": [i.to_dict() for i in self.issues],
            "meta": self.scanner_meta,
        }
