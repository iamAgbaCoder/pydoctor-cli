"""
pydoctor/cli/main.py
─────────────────────
PyDoctor CLI — entry point for all commands.

Commands
────────
  diagnose        Run the full diagnosis suite.
  check-env       Check the Python environment only.
  scan-deps       Scan for dependency conflicts only.
  scan-security   Scan for known vulnerabilities only.
  scan-unused     Detect unused packages only.
  report          Alias for diagnose; outputs a clean report.
  fix             Apply automated fixes (upgrade / remove / venv).
  cache           Manage the local vulnerability cache.

Global flags
────────────
  --path TEXT     Project path to scan (default: current directory).
  --json          Output raw JSON instead of rich terminal display.
  --verbose       Show detailed information and timing data.
  --no-cache      Bypass the local cache for vulnerability lookups.
"""

from __future__ import annotations

import sys

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    BarColumn,
)
from rich.panel import Panel
from rich.prompt import Confirm

from pydoctor import __version__
from pydoctor.core.analyzer import Analyzer, SCANNER_REGISTRY
from pydoctor.core.report import DiagnosisReport
from pydoctor.reports.table_formatter import render_report, render_issue_detail, console
from pydoctor.reports.json_formatter import render_json
from pydoctor.cache.cache_manager import CacheManager
from pydoctor.config.settings import Severity, PYDOCTOR_HOME
from pydoctor.reports.terminal_colors import PYDOCTOR_THEME


_HELP_EPILOG = """
[b]Common Options (apply to most commands)[/b]:

  [blue]--path, -p[/] TEXT  Project directory to scan (default: current directory).

  [blue]--json, -j[/]       Output raw JSON instead of rich terminal display.

  [blue]--verbose, -v[/]    Show detailed information and timing data.
  
  [blue]--no-cache[/]       Bypass the local cache for vulnerability lookups.

[b]Examples[/b]:

  [dim]$ pydoctor diagnose[/]
  
  [dim]$ pydoctor diagnose --path C:\\Projects\\my-project[/]
  
  [dim]$ pydoctor fix --no-safe[/]

[b]Testing Another Project[/b]:

  To test PyDoctor on a different project on your PC, you can either:
  
  1. Navigate to the project folder and run `pydoctor diagnose`
  
  2. Use the path flag: `pydoctor diagnose --path C:\\path\\to\\other\\project`
"""

app = typer.Typer(
    name="pydoctor",
    help="🩺  PyDoctor — Python environment diagnostic assistant.\n\nUse this tool to find and fix environment misconfigurations, dependency conflicts, security vulnerabilities, and unused packages.",
    epilog=_HELP_EPILOG,
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

err_console = Console(stderr=True, theme=PYDOCTOR_THEME)


# ──────────────────────────────────────────────────────────────
# Shared option types
# ──────────────────────────────────────────────────────────────

_PATH_OPT = typer.Option(".", "--path", "-p", help="Project directory to scan.")
_JSON_FLAG = typer.Option(False, "--json", "-j", help="Output results as JSON.")
_VERBOSE_FLAG = typer.Option(
    False, "--verbose", "-v", help="Show detailed output and timing."
)
_NO_CACHE = typer.Option(
    False, "--no-cache", help="Bypass the local vulnerability cache."
)


# ──────────────────────────────────────────────────────────────
# Helper: run a scan with a spinner
# ──────────────────────────────────────────────────────────────


def _run_scan(
    scanners: list[str] | None = None,
    path: str = ".",
    verbose: bool = False,
    no_cache: bool = False,
) -> DiagnosisReport:
    """
    Run the Analyzer with a Rich progress spinner and return the report.
    """
    if no_cache:
        # Clear cache before scan so fresh network data is fetched
        CacheManager().clear()

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bright_cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("🩺  Diagnosing your project …", total=None)
        analyzer = Analyzer(
            project_path=path,
            scanners=scanners,
            verbose=verbose,
        )
        report = analyzer.run()
        progress.update(task, description="✔  Scan complete")

    return report


def _output(
    report: DiagnosisReport,
    as_json: bool,
    verbose: bool = False,
) -> None:
    """Print the report in the requested format."""
    if as_json:
        render_json(report)
    else:
        render_report(report, verbose=verbose)


def _exit_code(report: DiagnosisReport) -> int:
    """Return a non-zero exit code if any errors / criticals were found."""
    return 1 if report.has_errors else 0


# ──────────────────────────────────────────────────────────────
# diagnose — full scan
# ──────────────────────────────────────────────────────────────


@app.command()
def diagnose(
    path: str = _PATH_OPT,
    json: bool = _JSON_FLAG,
    verbose: bool = _VERBOSE_FLAG,
    no_cache: bool = _NO_CACHE,
) -> None:
    """
    🩺  Run a **full** diagnosis of your Python project.

    Checks the environment, dependency tree, outdated packages,
    security vulnerabilities, and unused imports.

    Examples\n
    ────────\n
    pydoctor diagnose\n
    pydoctor diagnose --path ./my-project\n
    pydoctor diagnose --json\n
    pydoctor diagnose --verbose\n
    """
    report = _run_scan(path=path, verbose=verbose, no_cache=no_cache)
    _output(report, as_json=json, verbose=verbose)

    if verbose and not json:
        _render_verbose_details(report)

    raise typer.Exit(code=_exit_code(report))


# ──────────────────────────────────────────────────────────────
# check-env
# ──────────────────────────────────────────────────────────────


@app.command(name="check-env")
def check_env(
    path: str = _PATH_OPT,
    json: bool = _JSON_FLAG,
    verbose: bool = _VERBOSE_FLAG,
) -> None:
    """
    🌍  Check the Python **environment** (version, venv, pip).
    """
    report = _run_scan(scanners=["environment"], path=path, verbose=verbose)
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report))


# ──────────────────────────────────────────────────────────────
# scan-deps
# ──────────────────────────────────────────────────────────────


@app.command(name="scan-deps")
def scan_deps(
    path: str = _PATH_OPT,
    json: bool = _JSON_FLAG,
    verbose: bool = _VERBOSE_FLAG,
) -> None:
    """
    📦  Scan for **dependency conflicts** and missing packages.
    """
    report = _run_scan(scanners=["dependencies"], path=path, verbose=verbose)
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report))


# ──────────────────────────────────────────────────────────────
# scan-security
# ──────────────────────────────────────────────────────────────


@app.command(name="scan-security")
def scan_security(
    path: str = _PATH_OPT,
    json: bool = _JSON_FLAG,
    verbose: bool = _VERBOSE_FLAG,
    no_cache: bool = _NO_CACHE,
) -> None:
    """
    🔒  Scan installed packages for known **security vulnerabilities** via OSV.
    """
    report = _run_scan(
        scanners=["security"],
        path=path,
        verbose=verbose,
        no_cache=no_cache,
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report))


# ──────────────────────────────────────────────────────────────
# scan-unused
# ──────────────────────────────────────────────────────────────


@app.command(name="scan-unused")
def scan_unused(
    path: str = _PATH_OPT,
    json: bool = _JSON_FLAG,
    verbose: bool = _VERBOSE_FLAG,
) -> None:
    """
    🧹  Detect **unused packages** via AST import analysis.
    """
    report = _run_scan(scanners=["unused"], path=path, verbose=verbose)
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report))


# ──────────────────────────────────────────────────────────────
# report — alias for diagnose
# ──────────────────────────────────────────────────────────────


@app.command()
def report(
    path: str = _PATH_OPT,
    json: bool = _JSON_FLAG,
    verbose: bool = _VERBOSE_FLAG,
    no_cache: bool = _NO_CACHE,
) -> None:
    """
    📋  Generate a **full diagnosis report** (alias for diagnose).
    """
    report_data = _run_scan(path=path, verbose=verbose, no_cache=no_cache)
    _output(report_data, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report_data))


# ──────────────────────────────────────────────────────────────
# fix — automated remediation
# ──────────────────────────────────────────────────────────────


@app.command()
def fix(
    path: str = _PATH_OPT,
    safe: bool = typer.Option(
        True,
        "--safe/--no-safe",
        help="Safe mode asks for confirmation before each action (default: on).",
    ),
    upgrade: bool = typer.Option(
        True, "--upgrade/--no-upgrade", help="Upgrade outdated packages."
    ),
    remove: bool = typer.Option(
        False, "--remove/--no-remove", help="Remove unused packages."
    ),
) -> None:
    """
    🔧  Apply **automated fixes** to common issues.

    By default, runs in safe mode — asking before each action.
    Use --no-safe to apply all fixes non-interactively.

    Examples\n
    ────────\n
    pydoctor fix\n
    pydoctor fix --no-safe\n
    pydoctor fix --remove\n
    """
    import subprocess

    console.print()
    console.print(
        Panel(
            "[section]🔧  PyDoctor Auto-Fix[/]\n\nScanning for fixable issues …",
            border_style="rule",
        )
    )

    report_data = _run_scan(path=path)
    actions_taken = 0

    # ── Upgrade outdated packages ──────────────────────────────
    if upgrade:
        outdated = [i for i in report_data.issues if i.code == "PKG_OUTDATED"]
        if outdated:
            console.print(
                f"\n[section]Found {len(outdated)} outdated package(s) to upgrade:[/]"
            )
            for issue in outdated:
                pkg = issue.package or issue.extra.get("name", "")
                latest = issue.extra.get("latest_version", "latest")

                if safe:
                    ok = Confirm.ask(f"  Upgrade [pkg]{pkg}[/] → {latest}?")
                    if not ok:
                        continue

                console.print(f"  [dim_text]Running: pip install --upgrade {pkg}[/]")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    console.print(f"  [ok]✔  {pkg} upgraded to {latest}[/]")
                    actions_taken += 1
                else:
                    err_console.print(
                        f"  [error]✖  Failed to upgrade {pkg}: {result.stderr.strip()[:100]}[/]"
                    )
        else:
            console.print("[ok]✔  No outdated packages to upgrade.[/]")

    # ── Remove unused packages ─────────────────────────────────
    if remove:
        unused = [i for i in report_data.issues if i.code == "UNUSED_PACKAGE"]
        if unused:
            console.print(
                f"\n[section]Found {len(unused)} possibly unused package(s):[/]"
            )
            for issue in unused:
                pkg = issue.package or ""
                if not pkg:
                    continue

                if safe:
                    ok = Confirm.ask(
                        f"  Remove [pkg]{pkg}[/]?  "
                        f"[dim_text](Note: may be a transitive or dynamic dep)[/]"
                    )
                    if not ok:
                        continue

                console.print(f"  [dim_text]Running: pip uninstall -y {pkg}[/]")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "uninstall", "-y", pkg],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    console.print(f"  [ok]✔  {pkg} removed.[/]")
                    actions_taken += 1
                else:
                    err_console.print(f"  [error]✖  Failed to remove {pkg}[/]")

    # ── Create virtualenv if missing ───────────────────────────
    no_venv = any(i.code == "ENV_NO_VENV" for i in report_data.issues)
    if no_venv:
        venv_path = Path(path) / ".venv"
        if not venv_path.exists():
            should_create = True
            if safe:
                should_create = Confirm.ask(
                    f"  Create a virtual environment at [code]{venv_path}[/]?"
                )
            if should_create:
                console.print(f"  [dim_text]Running: python -m venv {venv_path}[/]")
                result = subprocess.run(
                    [sys.executable, "-m", "venv", str(venv_path)],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    console.print(
                        f"  [ok]✔  Virtual environment created at {venv_path}[/]"
                    )
                    actions_taken += 1
                else:
                    err_console.print(f"  [error]✖  Failed to create venv[/]")

    console.print()
    if actions_taken:
        console.print(
            Panel(
                f"[ok]✔  {actions_taken} fix(es) applied successfully.[/]",
                border_style="ok",
            )
        )
    else:
        console.print(
            Panel(
                "[dim_text]No fixes were applied.[/]",
                border_style="rule",
            )
        )


# ──────────────────────────────────────────────────────────────
# cache — cache management
# ──────────────────────────────────────────────────────────────

cache_app = typer.Typer(help="Manage the PyDoctor local cache.")
app.add_typer(cache_app, name="cache")


@cache_app.command("clear")
def cache_clear() -> None:
    """🗑  Clear the entire vulnerability/dependency cache."""
    CacheManager().clear()
    console.print("[ok]✔  Cache cleared.[/]")


@cache_app.command("purge")
def cache_purge() -> None:
    """🧹  Purge only expired cache entries."""
    removed = CacheManager().purge_expired()
    console.print(
        f"[ok]✔  Purged {removed} expired cache entr{'y' if removed==1 else 'ies'}.[/]"
    )


@cache_app.command("info")
def cache_info() -> None:
    """ℹ  Show cache file location and size."""
    cache = CacheManager()
    f = cache._cache_file
    if f.is_file():
        size = f.stat().st_size
        console.print(f"  Cache file: [code]{f}[/]")
        console.print(f"  Size:       [section]{size:,} bytes[/]")
    else:
        console.print("[dim_text]No cache file found yet.[/]")


# ──────────────────────────────────────────────────────────────
# version
# ──────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """🏷  Print the PyDoctor version."""
    console.print(f"🩺  PyDoctor [section]{__version__}[/]")


# ──────────────────────────────────────────────────────────────
# Verbose detail renderer
# ──────────────────────────────────────────────────────────────


def _render_verbose_details(report: DiagnosisReport) -> None:
    """
    In verbose mode, print a full detail panel for every non-OK issue.
    """
    non_ok = [
        i for i in report.issues if i.severity not in (Severity.OK, Severity.INFO)
    ]
    if not non_ok:
        return
    console.print("\n[section]Detailed Issue Breakdown[/]\n")
    for issue in non_ok:
        render_issue_detail(issue)


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────


def main() -> None:
    """CLI entry point called by the ``pydoctor`` script."""
    app()


if __name__ == "__main__":
    main()
