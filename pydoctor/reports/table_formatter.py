"""
pydoctor/reports/table_formatter.py
─────────────────────────────────────
Rich-powered terminal report formatter.

Renders a ``DiagnosisReport`` as a beautiful, doctor-themed CLI output
using Rich panels, tables, rules, and progress spinners.

Output sections:
  1. Banner / Header
  2. Summary counts panel
  3. Per-category issue tables
  4. Recommendations panel
  5. Timing footer (verbose mode)
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.rule import Rule

from pydoctor.config.settings import Severity
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.reports.terminal_colors import (
    PYDOCTOR_THEME,
    severity_icon,
    severity_style,
    ICON_STETHOSCOPE,
    ICON_ARROW,
    ICON_CLOCK,
    STYLE_HEADER,
    STYLE_SECTION,
    STYLE_DIM,
)

# Shared console with the custom theme
console = Console(theme=PYDOCTOR_THEME)


# ── Category display names ─────────────────────────────────────
CATEGORY_LABELS: dict[str, str] = {
    "environment": "🌍  Environment",
    "dependencies": "📦  Dependencies",
    "outdated": "🔄  Outdated Packages",
    "security": "🔒  Security Vulnerabilities",
    "unused": "🧹  Unused Packages",
}

# ── Which severities to show in the per-category tables ────────
VISIBLE_SEVERITIES = {
    Severity.WARNING,
    Severity.ERROR,
    Severity.CRITICAL,
    Severity.INFO,
}


def render_report(report: DiagnosisReport, verbose: bool = False) -> None:
    """
    Render the full diagnosis report to the terminal.

    Parameters
    ----------
    report:  The aggregated DiagnosisReport.
    verbose: Whether to include timing metadata.
    """
    console.print()
    _render_banner()
    console.print()
    _render_summary(report)
    console.print()
    _render_categories(report)
    console.print()
    _render_recommendations(report)

    if verbose and report.scanner_meta.get("timings_ms"):
        console.print()
        _render_timing(report)

    console.print()


# ──────────────────────────────────────────────────────────────
# Section renderers
# ──────────────────────────────────────────────────────────────


def _render_banner() -> None:
    """Print the PyDoctor diagnostic banner."""
    banner = Text()
    banner.append(f"\n  {ICON_STETHOSCOPE}  PyDoctor", style="header")
    banner.append("  Diagnosis Report\n", style="bright_white")

    console.print(
        Panel(
            banner,
            border_style="rule",
            padding=(0, 2),
        )
    )


def _render_summary(report: DiagnosisReport) -> None:
    """Print colour-coded summary counts for each severity level."""
    counts = report.summary_counts()

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("icon", no_wrap=True)
    table.add_column("label", no_wrap=True, style="section")
    table.add_column("count", no_wrap=True, justify="right")

    severity_display = [
        (Severity.CRITICAL, "Critical"),
        (Severity.ERROR, "Errors"),
        (Severity.WARNING, "Warnings"),
        (Severity.INFO, "Info"),
        (Severity.OK, "Passed"),
    ]

    for sev, label in severity_display:
        count = counts.get(sev, 0)
        if count == 0 and sev not in (Severity.OK,):
            continue
        table.add_row(
            severity_icon(sev),
            label,
            Text(str(count), style=severity_style(sev)),
        )

    console.print(
        Panel(
            table,
            title="[section]Summary[/]",
            border_style="rule",
            padding=(0, 1),
        )
    )


def _render_categories(report: DiagnosisReport) -> None:
    """
    Print a table of issues for each category.

    OK-only categories show a single green line.
    Categories with warnings/errors show a full table.
    """
    grouped = report.by_category()

    # Render in a fixed order
    ordered_keys = list(CATEGORY_LABELS.keys())
    # Add any unexpected categories at the end
    for k in grouped:
        if k not in ordered_keys:
            ordered_keys.append(k)

    for key in ordered_keys:
        if key not in grouped:
            continue
        issues = grouped[key]
        label = CATEGORY_LABELS.get(key, key.title())

        # Separate OK from everything else
        problems = [i for i in issues if i.severity != Severity.OK]
        oks = [i for i in issues if i.severity == Severity.OK]

        console.print(Rule(f"[section]{label}[/]", style="rule"))

        if not problems:
            # All clear in this category
            for ok in oks:
                console.print(f"  {severity_icon('ok')}  {ok.title}")
        else:
            tbl = _make_issue_table(problems)
            console.print(tbl)
            # Also show OKs below the table
            for ok in oks:
                console.print(f"  {severity_icon('ok')}  [dim_text]{ok.title}[/]")


def _make_issue_table(issues: list[Issue]) -> Table:
    """
    Build a Rich Table for a list of non-OK issues.
    """
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="section",
        show_edge=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("", width=3, no_wrap=True)
    table.add_column("Package", min_width=18, style="pkg")
    table.add_column("Issue", min_width=30)
    table.add_column("Severity", width=10, no_wrap=True)

    for issue in issues:
        table.add_row(
            severity_icon(issue.severity),
            issue.package or "—",
            issue.title,
            Text(issue.severity.upper(), style=severity_style(issue.severity)),
        )

    return table


def _render_recommendations(report: DiagnosisReport) -> None:
    """
    Print a consolidated Recommendations panel for all non-OK issues.
    """
    non_ok = [
        i
        for i in report.issues
        if i.severity not in (Severity.OK, Severity.INFO) and i.recommendation
    ]

    if not non_ok:
        console.print(
            Panel(
                f"  {severity_icon('ok')}  [ok]Your project looks healthy![/]",
                title="[section]Recommendations[/]",
                border_style="ok",
                padding=(0, 2),
            )
        )
        return

    lines = []
    for issue in non_ok[:15]:  # Cap at 15 recommendations for readability
        icon = severity_icon(issue.severity)
        lines.append(
            f"  {icon}  [pkg]{issue.package or 'General'}[/]  "
            f"{ICON_ARROW}  {issue.recommendation}"
        )

    if len(non_ok) > 15:
        lines.append(
            f"\n  [dim_text]… and {len(non_ok) - 15} more. "
            f"Run with --verbose for full details.[/]"
        )

    console.print(
        Panel(
            "\n".join(lines),
            title="[section]Recommendations[/]",
            border_style="warning",
            padding=(0, 1),
        )
    )


def _render_timing(report: DiagnosisReport) -> None:
    """Print per-scanner timing information (verbose mode only)."""
    timings: dict[str, float] = report.scanner_meta.get("timings_ms", {})
    if not timings:
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="section")
    table.add_column("Scanner")
    table.add_column("Time (ms)", justify="right")

    for name, ms in sorted(timings.items(), key=lambda x: -x[1]):
        table.add_row(name, f"{ms:.0f}")

    table.add_row(
        "Total",
        f"{report.scan_duration_ms:.0f}",
        style="section",
    )

    console.print(
        Panel(
            table,
            title=f"[section]{ICON_CLOCK}  Timing[/]",
            border_style="rule",
        )
    )


# ──────────────────────────────────────────────────────────────
# Verbose issue detail (used by --verbose CLI flag)
# ──────────────────────────────────────────────────────────────


def render_issue_detail(issue: Issue) -> None:
    """Print full detail for a single issue (used in verbose mode)."""
    icon = severity_icon(issue.severity)
    console.print(
        Panel(
            f"{icon}  [section]{issue.title}[/]\n\n"
            f"[dim_text]{issue.description}[/]\n\n"
            f"[section]Recommendation:[/] {issue.recommendation}",
            subtitle=f"[code]{issue.code}[/]  [dim_text]{issue.category}[/]",
            border_style=_border_for_severity(issue.severity),
            padding=(1, 2),
        )
    )


def _border_for_severity(severity: str) -> str:
    return {
        "ok": "ok",
        "info": "info",
        "warning": "warning",
        "error": "error",
        "critical": "critical",
    }.get(severity.lower(), "rule")
