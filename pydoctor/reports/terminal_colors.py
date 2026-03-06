"""
pydoctor/reports/terminal_colors.py
─────────────────────────────────────
Rich style constants used throughout the CLI output.

Centralising colours/styles here means the visual look of PyDoctor
can be adjusted in one place without touching display logic.
"""

from __future__ import annotations

from rich.style import Style
from rich.theme import Theme


# ── Severity colours ───────────────────────────────────────────
STYLE_OK = Style(color="bright_green", bold=True)
STYLE_INFO = Style(color="cyan", bold=False)
STYLE_WARNING = Style(color="yellow", bold=True)
STYLE_ERROR = Style(color="red", bold=True)
STYLE_CRITICAL = Style(color="bright_red", bold=True, underline=True)

# ── UI chrome ──────────────────────────────────────────────────
STYLE_HEADER = Style(color="bright_cyan", bold=True)
STYLE_SECTION = Style(color="bright_white", bold=True)
STYLE_DIM = Style(color="grey50")
STYLE_PACKAGE = Style(color="bright_blue")
STYLE_CODE = Style(color="magenta")

# ── Icons ──────────────────────────────────────────────────────
ICON_OK = "[bright_green]✔[/]"
ICON_INFO = "[cyan]ℹ[/]"
ICON_WARNING = "[yellow]⚠[/]"
ICON_ERROR = "[red]✖[/]"
ICON_CRITICAL = "[bright_red bold]✖✖[/]"
ICON_STETHOSCOPE = "🩺"
ICON_ARROW = "[dim]→[/]"
ICON_FIX = "🔧"
ICON_SCAN = "🔍"
ICON_LOCK = "🔒"
ICON_CLOCK = "⏱"

# ── Custom Rich theme (registered on the Console) ──────────────
PYDOCTOR_THEME = Theme(
    {
        "ok": "bright_green bold",
        "info": "cyan",
        "warning": "yellow bold",
        "error": "red bold",
        "critical": "bright_red bold underline",
        "header": "bright_cyan bold",
        "section": "bright_white bold",
        "dim_text": "grey50",
        "pkg": "bright_blue",
        "code": "magenta",
        "rule": "bright_cyan",
    }
)


def severity_icon(severity: str) -> str:
    """Return the Rich-markup icon string for a given severity level."""
    return {
        "ok": ICON_OK,
        "info": ICON_INFO,
        "warning": ICON_WARNING,
        "error": ICON_ERROR,
        "critical": ICON_CRITICAL,
    }.get(severity.lower(), ICON_INFO)


def severity_style(severity: str) -> Style:
    """Return the Rich Style object for a given severity level."""
    return {
        "ok": STYLE_OK,
        "info": STYLE_INFO,
        "warning": STYLE_WARNING,
        "error": STYLE_ERROR,
        "critical": STYLE_CRITICAL,
    }.get(severity.lower(), STYLE_INFO)
