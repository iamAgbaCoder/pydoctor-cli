"""
pydoctor/reports/table_formatter.py
─────────────────────────────────────
Rich-powered terminal report formatter.
"""

from __future__ import annotations

import math
from typing import Dict, List, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn
from rich import box
from rich.rule import Rule

from pydoctor.config.settings import Severity
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.analysis.health_score import calculate_health
from pydoctor.reports.terminal_colors import (
    PYDOCTOR_THEME,
    severity_icon,
    severity_style,
    ICON_STETHOSCOPE,
)

console = Console(theme=PYDOCTOR_THEME)

CATEGORY_LABELS: dict[str, str] = {
    "environment": "Environment",
    "dependencies": "Dependencies",
    "outdated": "Outdated Packages",
    "security": "Security",
    "unused": "Unused Packages",
}


def render_report(report: DiagnosisReport, verbose: bool = False) -> None:
    """Render the UX-improved diagnostic report."""
    console.print()
    _render_banner()

    # Render grouped issues in verbose mode, else summary
    console.print(Rule("[section]Results[/]", style="rule"))
    _render_simple_summary(report)

    # Auto-expand details if we are in a targeted scan (only one category) or verbose
    categories = {
        i.category
        for i in report.issues
        if i.severity not in (Severity.OK, Severity.INFO)
    }

    if verbose or len(categories) == 1:
        if verbose or "security" in categories:
            console.print()
            _render_detailed_security(report)
        if verbose or "unused" in categories:
            console.print()
            _render_detailed_unused(report)
        if verbose or "outdated" in categories:
            console.print()
            _render_detailed_outdated(report)
        if verbose or "environment" in categories:
            console.print()
            _render_detailed_environment(report)
        if verbose or "dependencies" in categories:
            console.print()
            _render_detailed_dependencies(report)

    console.print()
    _render_health_score(report)

    console.print()
    _render_verdict(report)

    console.print()
    _render_recommendations(report, verbose=verbose)

    console.print()
    _render_next_steps(verbose=verbose)

    console.print(
        f"\n[dim_text]Scan completed in {report.scan_duration_ms / 1000.0:.2f} seconds[/]"
    )
    console.print()


def _render_banner() -> None:
    banner = Text(f"{ICON_STETHOSCOPE} PyDoctor Diagnosis Report", style="header")
    console.print(banner)
    console.print()


def _render_simple_summary(report: DiagnosisReport) -> None:
    """Renders the Results section compactly."""
    grouped = report.by_category()
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Category", style="section", width=20)
    table.add_column("Status")

    for key, label in CATEGORY_LABELS.items():
        if key not in grouped:
            continue

        issues = grouped[key]
        problems = [i for i in issues if i.severity not in (Severity.OK, Severity.INFO)]

        if not problems:
            text = Text(f"✔ Healthy", style="ok")
        else:
            if key == "security":
                text = Text(f"⚠ {len(problems)} vulnerabilities", style="warning")
            elif key == "unused":
                text = Text(f"⚠ {len(problems)} detected", style="warning")
            elif key == "outdated":
                text = Text(f"⚠ {len(problems)} detected", style="warning")
            elif key == "dependencies":
                text = Text(f"⚠ {len(problems)} conflicts", style="error")
            else:
                text = Text(f"⚠ {len(problems)} issues", style="warning")

        table.add_row(label, text)

    console.print(table)


def _render_health_score(report: DiagnosisReport) -> None:
    """Renders the health score progress bar."""
    health = calculate_health(report)

    console.print("[section]❤️  Project Health Score[/]")

    bar_width = 20
    filled = math.ceil((health.score / 100.0) * bar_width)
    empty = bar_width - filled

    bar = ("█" * filled) + ("░" * empty)

    color = "ok" if health.score >= 80 else "warning" if health.score >= 50 else "error"
    console.print(f"[{color}]{bar}[/] [b]{health.score}%[/]")


def _render_verdict(report: DiagnosisReport) -> None:
    health = calculate_health(report)
    console.print("[section]🩺 Doctor's Verdict[/]")
    console.print(health.message)


def _render_recommendations(report: DiagnosisReport, verbose: bool = False) -> None:
    console.print("[section]💡 Recommendations[/]")
    non_ok = [
        i
        for i in report.issues
        if i.severity not in (Severity.OK, Severity.INFO) and i.recommendation
    ]

    if not non_ok:
        console.print("[ok]No actions required. Keep up the good work![/]")
        return

    # In verbose mode, show ALL recommendations. In normal mode, limit to 10.
    limit = 10 if not verbose else 1000
    shown = 0
    for issue in non_ok[:limit]:
        console.print(
            f"{severity_icon(issue.severity)} [pkg]{issue.package or 'System'}[/] {issue.title}"
        )
        console.print(f"  Fix: [code]{issue.recommendation}[/]")
        shown += 1

    if not verbose and len(non_ok) > limit:
        console.print(
            f"\n[dim_text]... and {len(non_ok) - limit} more recommendations.[/]"
        )


def _render_next_steps(verbose: bool = False) -> None:
    console.print("[section]🚀 Next Steps[/]")
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Desc", style="dim_text")
    table.add_column("Cmd", style="code")

    if not verbose:
        table.add_row("Run full diagnosis:", "pydoctor diagnose --verbose")
        table.add_row("Check vulnerabilities:", "pydoctor scan-security")

    table.add_row("Auto-fix issues:", "pydoctor fix")
    console.print(table)


def _render_detailed_security(report: DiagnosisReport) -> None:
    """Group vulnerabilities by package for verbose output."""
    sec_issues = [
        i
        for i in report.issues
        if i.category == "security" and i.severity != Severity.OK
    ]
    if not sec_issues:
        return

    from collections import defaultdict

    grouped: dict[str, list[Issue]] = defaultdict(list)
    for issue in sec_issues:
        grouped[issue.package or "Unknown"].append(issue)

    console.print(Rule("[section]Security Vulnerabilities[/]", style="rule"))

    for pkg, issues in grouped.items():
        console.print(f"\n[pkg]{pkg}[/]")
        console.print(
            f"{severity_icon(Severity.WARNING)} [warning]{len(issues)} vulnerabilities detected[/]\n"
        )

        for issue in issues:
            c = "error" if issue.severity == Severity.CRITICAL else "warning"
            display_title = issue.title
            if issue.package and display_title.lower().startswith(
                issue.package.lower()
            ):
                display_title = display_title[len(issue.package) :].strip(" -—")
            console.print(f"  [{c}]{display_title}[/] - {issue.description}")


def _render_detailed_outdated(report: DiagnosisReport) -> None:
    """Show details for outdated packages."""
    outdated = [
        i
        for i in report.issues
        if i.category == "outdated" and i.severity != Severity.OK
    ]
    if not outdated:
        return

    console.print(Rule("[section]Outdated Packages[/]", style="rule"))
    table = Table(box=None, show_header=True, header_style="section")
    table.add_column("Package", style="pkg")
    table.add_column("Current")
    table.add_column("Latest", style="ok")

    for issue in outdated:
        table.add_row(
            issue.package or "Unknown",
            issue.extra.get("current_version", "?"),
            issue.extra.get("latest_version", "?"),
        )
    console.print(table)


def _render_detailed_unused(report: DiagnosisReport) -> None:
    """Show detailed unused with confidence."""
    unused = [
        i for i in report.issues if i.category == "unused" and i.severity != Severity.OK
    ]
    if not unused:
        return

    console.print(Rule("[section]Unused Packages[/]", style="rule"))
    for issue in unused:
        console.print(f"\n[pkg]{issue.package}[/]")
        console.print(f"{severity_icon(issue.severity)} [warning]Possibly unused[/]")
        # Parse confidence from description if present
        desc = issue.description.replace("\n", "  ")
        console.print(f"  [dim_text]{desc}[/]")


def _render_detailed_environment(report: DiagnosisReport) -> None:
    """Show detailed environment issues."""
    env_issues = [
        i
        for i in report.issues
        if i.category == "environment" and i.severity != Severity.OK
    ]
    if not env_issues:
        return
    console.print(Rule("[section]Environment Details[/]", style="rule"))
    for issue in env_issues:
        console.print(f"\n{severity_icon(issue.severity)} [b]{issue.title}[/]")
        console.print(f"  [dim_text]{issue.description}[/]")
        if issue.recommendation:
            console.print(f"  Fix: [code]{issue.recommendation}[/]")


def _render_detailed_dependencies(report: DiagnosisReport) -> None:
    """Show detailed dependency conflicts."""
    dep_issues = [
        i
        for i in report.issues
        if i.category == "dependencies" and i.severity != Severity.OK
    ]
    if not dep_issues:
        return
    console.print(Rule("[section]Dependency Conflicts[/]", style="rule"))
    for issue in dep_issues:
        console.print(
            f"\n{severity_icon(issue.severity)} [pkg]{issue.package or 'Package'}[/] {issue.title}"
        )
        console.print(f"  [dim_text]{issue.description}[/]")
        if issue.recommendation:
            console.print(f"  Fix: [code]{issue.recommendation}[/]")


def render_issue_detail(issue: Issue) -> None:
    pass
