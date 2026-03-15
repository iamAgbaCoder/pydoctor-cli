"""
pydoctor/analysis/health_score.py
──────────────────────────────────
Calculates the numerical project health score and verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydoctor.core.report import DiagnosisReport, Issue


@dataclass
class HealthMetrics:
    score: int
    verdict: str
    message: str


def calculate_health(report: DiagnosisReport) -> HealthMetrics:
    """
    Calculate project health score (0-100) based on identified issues.
    """
    score = _compute_score(report)
    categories = list({i.category for i in report.issues})
    return _get_verdict(score, categories)


def _compute_score(report: DiagnosisReport) -> int:
    score = 100
    for issue in report.issues:
        score -= _calculate_issue_penalty(issue)
    return max(0, score)


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
