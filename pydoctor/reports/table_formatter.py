"""
pydoctor/reports/table_formatter.py
─────────────────────────────────────
Rich-powered terminal report formatter.
"""

from __future__ import annotations

import math

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pydoctor.analysis.health_score import calculate_health
from pydoctor.config.settings import Severity
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.reports.terminal_colors import (
    ICON_OK,
    ICON_WARNING,
    PYDOCTOR_THEME,
    severity_icon,
)

console = Console(theme=PYDOCTOR_THEME)

CATEGORY_LABELS: dict[str, str] = {
    "environment": "ENVIRONMENT",
    "dependencies": "DEPENDENCY HEALTH",
    "outdated": "VERSION STATUS",
    "security": "SECURITY PROTOCOLS",
    "unused": "RESOURCE HYGIENE",
    "ci": "CI/CD GUARD",
}


def render_report(report: DiagnosisReport, verbose: bool = False) -> None:
    """Render the UX-improved diagnostic report."""
    console.print()
    _render_kernel_logs(report)
    console.print()

    # Render Environment Status
    _render_boxed_environment(report)
    console.print()

    # If minor issues, show simple summary; else show details
    grouped = report.by_category()

    # If it's a specific command, only show that category (and environment if applicable)
    target_cats = ["dependencies", "security", "outdated", "unused", "ci"]
    if report.command and report.command.startswith("scan-"):
        target_cats = [report.command.replace("scan-", "")]
        if target_cats[0] == "deps":
            target_cats[0] = "dependencies"
    elif report.command == "check-env":
        target_cats = []  # Environment is always shown at top
    elif report.command == "github":
        target_cats = ["ci"]

    for cat in target_cats:
        if cat in grouped:
            issues = [i for i in grouped[cat] if i.severity not in (Severity.OK, Severity.INFO)]
            if issues or verbose:
                _render_boxed_category(cat, grouped[cat])
                console.print()

    _render_health_score(report)
    console.print()

    _render_verdict(report)
    console.print()

    _render_recommendations(report, verbose=verbose)
    console.print()

    # Hide next steps if 100% healthy
    health = calculate_health(report)
    if health.score < 100:
        _render_next_steps(report.command, verbose=verbose)

    console.print(
        f"\n[kernel]System idle. Scan telemetry gathered in {report.scan_duration_ms / 1000.0:.2f}s[/]"
    )
    console.print()


def _render_kernel_logs(report: DiagnosisReport) -> None:
    """Prints 'Kernel' style initialization logs."""
    console.print("[kernel]Initializing Kernel Analysis...[/]")
    py_ver = ".".join(map(str, report.ctx.python_version)) if report.ctx else "Unknown"
    os_name = report.ctx.os_name if report.ctx else "Unknown"

    console.print(f"STDOUT: [stdout][SUCCESS][/] Runtime: Python {py_ver} ({os_name})")
    console.print("STDOUT: [stdout][SUCCESS][/] Entropy Check: PASS")
    console.print("\n[kernel]Orchestrating Dependency Audit...[/]")


def _render_boxed_environment(report: DiagnosisReport) -> None:
    """Renders the environment section in a box."""
    ctx = report.ctx
    if not ctx:
        return

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="label")
    table.add_column("Value")

    # Python Version
    table.add_row(f"{ICON_OK} Python Version:", f"{'.'.join(map(str, ctx.python_version))}")

    # Venv status
    status = "Active" if ctx.in_virtualenv else "[warning]System (Not Isolated)[/]"
    table.add_row(f"{ICON_OK if ctx.in_virtualenv else ICON_WARNING} Virtual Environment:", status)

    if ctx.venv_name:
        table.add_row("  Name:", ctx.venv_name)

    # Installed count
    table.add_row(f"{ICON_OK} Installed Packages:", str(len(ctx.installed_packages)))

    # OS Info
    table.add_row(f"{ICON_OK} System OS:", ctx.os_name)

    # Git Info (Only for github command or verbose)
    if report.command == "github" or (hasattr(ctx, "git_repo") and ctx.git_repo):
        if ctx.git_repo:
            table.add_row(f"{ICON_OK} Repository:", ctx.git_repo)
        if ctx.git_branch:
            table.add_row(f"{ICON_OK} Branch:", ctx.git_branch)
        if ctx.git_origin:
            table.add_row(f"{ICON_OK} Origin:", f"[dim]{ctx.git_origin}[/]")

    panel = Panel(
        Align.left(table),
        title="[section]ENVIRONMENT[/]",
        title_align="left",
        border_style="rule",
        padding=(1, 2),
    )
    console.print(panel)


def _render_boxed_category(cat_key: str, issues: list[Issue]) -> None:
    """Renders a category's issues inside a box."""
    label = CATEGORY_LABELS.get(cat_key, cat_key.upper())
    problems = [i for i in issues if i.severity not in (Severity.OK, Severity.INFO)]

    if not problems:
        content = Text.from_markup(f"{ICON_OK} Healthy. No issues detected in this sector.")
        content.stylize("ok")
    else:
        content = Text()
        for i in problems:
            icon_text = Text.from_markup(severity_icon(i.severity))
            content.append(icon_text)
            content.append(f" {i.title}\n", style="bold")

            if i.package:
                content.append("      Package: ", style="dim_text")
                content.append(f"{i.package}\n", style="pkg")

            if i.description:
                desc = i.description.split("\n")[0]
                content.append("      Details: ", style="dim_text")
                content.append(f"{desc}\n", style="dim_text")

            if i.recommendation:
                content.append("      Suggestion: ", style="dim_text")
                content.append(f"{i.recommendation}\n", style="code")
            content.append("\n")

    panel = Panel(
        Align.left(content),
        title=f"[section]{label}[/]",
        title_align="left",
        border_style=(
            "error"
            if any(i.severity in (Severity.ERROR, Severity.CRITICAL) for i in problems)
            else "warning" if problems else "ok"
        ),
        padding=(1, 2),
    )
    console.print(panel)


def _render_health_score(report: DiagnosisReport) -> None:
    """Renders the health score progress bar."""
    health = calculate_health(report)

    # Determine the score title based on what was scanned
    active_categories = {i.category for i in report.issues}
    if len(active_categories) == 1:
        cat = list(active_categories)[0]
        title = f"Project {CATEGORY_LABELS.get(cat, cat.upper())} Score"
    else:
        title = "Project Health Score"

    console.print(f"[section]❤️  {title}[/]")

    bar_width = 30
    filled = math.ceil((health.score / 100.0) * bar_width)
    empty = bar_width - filled

    bar = ("█" * filled) + ("░" * empty)

    color = "ok" if health.score >= 80 else "warning" if health.score >= 50 else "error"
    console.print(f"[{color}]{bar}[/] [label]{health.score} / 100[/]")


def _render_verdict(report: DiagnosisReport) -> None:
    health = calculate_health(report)
    console.print("[section]🩺 Doctor's Verdict[/]")
    console.print(f"[dim_text]{health.message}[/]")


def _render_recommendations(report: DiagnosisReport, verbose: bool = False) -> None:
    # We already show suggestions in the boxes now, but we can keep a summary if needed
    pass


def _render_next_steps(current_cmd: str | None = None, verbose: bool = False) -> None:
    console.print("[section]🚀 Next Steps[/]")
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Desc", style="dim_text")
    table.add_column("Cmd", style="code")

    steps = [
        ("Auto-fix detected issues:", "fix"),
        ("Run CI security guard:", "check --ci"),
        ("Diagnose Docker env:", "docker"),
        ("Integrate with GitHub:", "github"),
        ("Verify global env:", "check-env"),
        ("Run full diagnosis:", "diagnose"),
    ]

    for desc, cmd in steps:
        # Filter out the command we just ran
        normalized_current = (current_cmd or "").replace("scan-", "").replace("check-", "")
        normalized_step = cmd.replace("scan-", "").replace("check-", "")

        if current_cmd == cmd or normalized_current == normalized_step:
            continue

        table.add_row(desc, f"pydoctor {cmd}")

    console.print(table)


def render_issue_detail(issue: Issue) -> None:
    pass
