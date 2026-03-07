"""
pydoctor/analysis/health_score.py
──────────────────────────────────
Calculates the numerical project health score and verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydoctor.core.report import DiagnosisReport


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
    return _get_verdict(score)


def _compute_score(report: DiagnosisReport) -> int:
    score = 100
    for issue in report.issues:
        if issue.severity in ("ok", "info"):
            continue
        if issue.category == "security":
            score -= 3
        elif issue.category == "dependencies":
            score -= 5
        elif issue.category == "outdated":
            score -= 2
        elif issue.category == "unused":
            score -= 1
        elif issue.category == "environment":
            if issue.severity in ("error", "critical"):
                score -= 5
            elif issue.severity == "warning":
                score -= 2
    return max(0, score)


def _get_verdict(score: int) -> HealthMetrics:
    if score >= 90:
        verdict = "Excellent"
        message = "Your project is healthy and ready for production."
    elif score >= 70:
        verdict = "Good"
        message = "Your project is functional but has some minor issues to clear up."
    elif score >= 50:
        verdict = "Needs Attention"
        message = "Your project has notable risks. Consider addressing warnings carefully."
    else:
        verdict = "Critical"
        message = (
            "Your project contains severe risks that should be fixed before production deployment."
        )

    return HealthMetrics(score=score, verdict=verdict, message=message)
