"""
pydoctor/analysis/health_score.py
──────────────────────────────────
Calculates the numerical project health score and verdict.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from pydoctor.core.report import DiagnosisReport, Issue


@dataclass
class HealthMetrics:
    score: int
    verdict: str
    message: str


# Each category can cost at most this many points. Within a category every
# extra issue still lowers the score, but by less (diminishing returns), so
# fixing issues in a project with dozens of them visibly moves the score.
CATEGORY_CAPS: dict[str, float] = {
    "security": 60,
    "ci": 50,
    "dependencies": 40,
    "environment": 30,
    "outdated": 15,
    "unused": 10,
}

# A project with any critical issue can't be rated Good or Excellent.
CRITICAL_CEILING = 69

# Issues that mean part of the scan didn't run.
INCOMPLETE_CODES = {"ENV_PACKAGES_UNAVAILABLE", "SEC_SCAN_INCOMPLETE"}


def calculate_health(report: DiagnosisReport) -> HealthMetrics:
    """
    Calculate project health score (0-100) based on identified issues.
    """
    score = _compute_score(report)
    categories = list({i.category for i in report.issues if i.code not in INCOMPLETE_CODES})
    metrics = _get_verdict(score, categories)
    if any(i.code in INCOMPLETE_CODES for i in report.issues):
        metrics.verdict = "Incomplete"
        metrics.message = (
            "Some checks couldn't run, so this score only covers what was checked. "
            "See the errors above."
        )
    return metrics


def _compute_score(report: DiagnosisReport) -> int:
    raw: dict[str, float] = {}
    # One upgrade usually fixes every advisory for a package, so a package
    # costs the penalty of its worst advisory, not one penalty per advisory.
    per_package: dict[str, int] = {}
    for issue in report.issues:
        penalty = _calculate_issue_penalty(issue)
        if issue.code == "SEC_VULNERABILITY" and issue.package:
            per_package[issue.package] = max(per_package.get(issue.package, 0), penalty)
            continue
        raw[issue.category] = raw.get(issue.category, 0) + penalty
    if per_package:
        raw["security"] = raw.get("security", 0) + sum(per_package.values())
    lost = 0.0
    for category, points in raw.items():
        cap = CATEGORY_CAPS.get(category)
        lost += cap * (1 - math.exp(-points / cap)) if cap else points
    score = max(0, round(100 - lost))
    if any(i.severity.lower() == "critical" for i in report.issues):
        score = min(score, CRITICAL_CEILING)
    return score


def _calculate_issue_penalty(issue: Issue) -> int:
    sev = issue.severity.lower()
    if sev in ("ok", "info"):
        return 0

    if issue.category == "security":
        if sev == "critical":
            return 25  # Increased penalty for security
        if sev == "error":
            return 12
        return 6
    if issue.category == "dependencies":
        return 8
    if issue.category == "outdated":
        return 3
    if issue.category == "unused":
        return 2
    if issue.category == "environment":
        return 15 if sev in ("error", "critical") else 5
    if issue.category == "ci":
        return 20 if sev == "critical" else 10
    return 0


def _get_verdict(score: int, categories: list[str]) -> HealthMetrics:
    is_partial = len(categories) == 1
    cat_name = categories[0].capitalize() if is_partial else "Project"

    if score >= 90:
        verdict = "Excellent"
        message = (
            f"Your {cat_name} is healthy and ready for production."
            if is_partial
            else "Your project is healthy and ready for production."
        )
    elif score >= 70:
        verdict = "Good"
        message = f"Your {cat_name} is functional but has some minor issues to clear up."
    elif score >= 50:
        verdict = "Needs Attention"
        message = f"Your {cat_name} has notable risks. Consider addressing warnings carefully."
    else:
        verdict = "Critical"
        message = f"Your {cat_name} contains severe risks that should be fixed before production deployment."

    return HealthMetrics(score=score, verdict=verdict, message=message)
