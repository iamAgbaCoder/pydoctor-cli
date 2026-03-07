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

import subprocess
import sys
from typing import Annotated

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore
    except Exception:
        pass

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm

from pydoctor import __version__
from pydoctor.cache.cache_manager import CacheManager
from pydoctor.config.settings import Severity
from pydoctor.core.analyzer import Analyzer
from pydoctor.core.report import DiagnosisReport
from pydoctor.reports.json_formatter import render_json
from pydoctor.reports.table_formatter import (
    CATEGORY_LABELS,
    console,
    render_issue_detail,
    render_report,
)
from pydoctor.reports.terminal_colors import PYDOCTOR_THEME


def version_callback(value: bool):
    if value:
        console.print(f"🩺 [b]PyDoctor[/] version [cyan]{__version__}[/]")
        raise typer.Exit()


_HELP_EPILOG = """
[b]💊 PyDoctor Quick Start Guide[/b]

[blue]Step 1: Full Diagnosis[/]
  Perform a complete health check on your current project:
  [dim]$ pydoctor diagnose[/]

[blue]Step 2: Targeted Scans[/]
  Isolation-focused diagnostic commands:
  [dim]$ pydoctor scan-security[/]   [grey]— Check for CVEs & advisories[/]
  [dim]$ pydoctor scan-unused[/]     [grey]— Detect dead dependencies[/]
  [dim]$ pydoctor scan-deps[/]       [grey]— Find dependency conflicts[/]
  [dim]$ pydoctor check-env[/]       [grey]— Verify Python & venv setup[/]

[blue]Step 3: Automated Treatment[/]
  Let the doctor remediate issues automatically:
  [dim]$ pydoctor fix[/]               [grey]— Interactive remediation[/]
  [dim]$ pydoctor fix --no-safe[/]     [grey]— Professional auto-fix mode[/]

[b]🔧 Global Workflow Options[/b]
  [cyan]--path, -p[/] PATH       Target a specific project folder.
  [cyan]--json, -j[/]            Machine-readable output for CI/CD.
  [cyan]--verbose, -v[/]         Show full issue histories and trace.
  [cyan]--version[/]             Display current PyDoctor version.

[b]🏥 Community & Support[/b]
  Documentation: [u]https://github.com/iamAgbaCoder/pydoctor-cli[/u]
  Verdict: [i]Healthy code leads to healthy deployments.[/i]
"""

app = typer.Typer(
    name="pydoctor",
    help="🩺  PyDoctor — Professional Python Diagnostic Assistant.\n\nAutomate your environment audits, dependency security scans, and bloat detection in seconds.",
    epilog=_HELP_EPILOG,
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


@app.callback()
def main_callback(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
):
    """
    🩺 PyDoctor — Python environment diagnostic assistant.
    """
    pass


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
    as_json: bool = False,
) -> DiagnosisReport:
    """Run the Analyzer with Rich progress indicators."""
    if no_cache:
        CacheManager().clear()

    if not as_json:
        console.print("[section]Scanning project...[/]")

    def progress_callback(key: str) -> None:
        if not as_json:
            label = CATEGORY_LABELS.get(key, key.title())
            console.print(f"[ok]✔[/] Checking {label.lower().replace(' ', ' ')}")

    if as_json:
        # Avoid overriding stdout when generating JSON
        analyzer = Analyzer(project_path=path, scanners=scanners, verbose=verbose)
        return analyzer.run(on_progress=None)

    with Progress(
        SpinnerColumn("dots", style="bright_cyan"),
        TextColumn("[bright_cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("🩺 PyDoctor scanning project...", total=None)
        analyzer = Analyzer(
            project_path=path,
            scanners=scanners,
            verbose=verbose,
        )
        report = analyzer.run(on_progress=progress_callback)

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


def _exit_code(report: DiagnosisReport, path: str = ".") -> int:
    """
    Return a non-zero exit code if:
    1. Any CRITICAL or ERROR severity issues were found.
    2. The project health score is below the configured threshold.
    """
    if report.has_errors:
        return 1

    try:
        from pydoctor.analysis.health_score import calculate_health
        from pydoctor.core.project import ProjectContext

        ctx = ProjectContext.from_path(path)
        threshold = ctx.config.get("min_health_score", 0)

        if threshold > 0:
            metrics = calculate_health(report)
            if metrics.score < threshold:
                return 1
    except Exception:
        pass

    return 0


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
    report = _run_scan(path=path, verbose=verbose, no_cache=no_cache, as_json=json)
    _output(report, as_json=json, verbose=verbose)

    if verbose and not json:
        _render_verbose_details(report)

    raise typer.Exit(code=_exit_code(report, path))


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
    report = _run_scan(
        scanners=["environment"], path=path, verbose=verbose, as_json=json
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


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
    report = _run_scan(
        scanners=["dependencies"], path=path, verbose=verbose, as_json=json
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


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
        as_json=json,
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


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
    report = _run_scan(scanners=["unused"], path=path, verbose=verbose, as_json=json)
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


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
    report_data = _run_scan(path=path, verbose=verbose, no_cache=no_cache, as_json=json)
    _output(report_data, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report_data))


# ──────────────────────────────────────────────────────────────
# fix — automated remediation
# ──────────────────────────────────────────────────────────────


@app.command()
def fix(
    packages: Annotated[
        list[str] | None, typer.Argument(help="Specific packages to fix (optional).")
    ] = None,
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
    """
    console.print()
    console.print(
        Panel(
            "[section]🔧  PyDoctor Auto-Fix[/]\n\nScanning for fixable issues …",
            border_style="rule",
        )
    )

    report_data = _run_scan(path=path)
    if packages:
        _filter_issues_by_targets(report_data, packages)

    actions = 0
    actions += _fix_vulnerabilities(report_data, path, safe)

    if upgrade:
        actions += _fix_outdated(report_data, path, safe)

    if remove or packages:
        actions += _fix_unused(report_data, path, safe)

    actions += _fix_venv(report_data, path, safe)

    _render_fix_summary(actions)


def _filter_issues_by_targets(
    report_data: DiagnosisReport, packages: list[str]
) -> None:
    targets = {p.lower() for p in packages}
    report_data.issues = [
        i for i in report_data.issues if i.package and i.package.lower() in targets
    ]
    if not report_data.issues:
        console.print(
            f"\n[warning]No fixable issues found for packages: {', '.join(packages)}[/]"
        )
        raise typer.Exit()


def _fix_vulnerabilities(report: DiagnosisReport, path: str, safe: bool) -> int:
    vulnerable = [i for i in report.issues if i.category == "security"]
    if not vulnerable:
        return 0

    console.print(
        f"\n[section]Found {len(vulnerable)} security vulnerabilities to fix:[/]"
    )
    vulnerable_pkgs = {i.package: i for i in vulnerable if i.package}
    actions = 0

    for pkg in vulnerable_pkgs:
        if safe:
            if not Confirm.ask(f"  Fix vulnerability in [pkg]{pkg}[/] by upgrading?"):
                continue

        console.print(f"  [dim_text]Running: pip install --upgrade {pkg}[/]")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", pkg]
        )
        if result.returncode == 0:
            console.print(f"  [ok]✔  {pkg} upgraded successfully.[/]")
            actions += 1
        else:
            err_console.print(f"  [error]✖  Failed to fix {pkg}[/]")
    return actions


def _fix_outdated(report: DiagnosisReport, path: str, safe: bool) -> int:
    outdated = [i for i in report.issues if i.code == "PKG_OUTDATED"]
    if not outdated:
        return 0

    console.print(
        f"\n[section]Found {len(outdated)} outdated package(s) to upgrade:[/]"
    )
    actions = 0
    for issue in outdated:
        pkg = issue.package or issue.extra.get("name", "")
        if not pkg:
            continue
        latest = issue.extra.get("latest_version", "latest")
        if safe:
            if not Confirm.ask(f"  Upgrade [pkg]{pkg}[/] → {latest}?"):
                continue

        console.print(f"  [dim_text]Running: pip install --upgrade {pkg}[/]")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", pkg]
        )
        if result.returncode == 0:
            console.print(f"  [ok]✔  {pkg} upgraded to {latest}[/]")
            actions += 1
            from pydoctor.utils.pip_utils import update_requirements_file

            req_file = Path(path) / "requirements.txt"
            if req_file.is_file():
                update_requirements_file(req_file, pkg, f"=={latest}")
        else:
            err_console.print(f"  [error]✖  Failed to upgrade {pkg}[/]")
    return actions


def _fix_unused(report: DiagnosisReport, path: str, safe: bool) -> int:
    unused = [i for i in report.issues if i.code == "UNUSED_PACKAGE"]
    if not unused:
        return 0

    console.print(f"\n[section]Found {len(unused)} possibly unused package(s):[/]")
    actions = 0
    for issue in unused:
        pkg = issue.package or ""
        if not pkg:
            continue
        if safe:
            if not Confirm.ask(f"  Remove [pkg]{pkg}[/]?"):
                continue

        console.print(f"  [dim_text]Running: pip uninstall -y {pkg}[/]")
        result = subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", pkg])
        if result.returncode == 0:
            console.print(f"  [ok]✔  {pkg} removed.[/]")
            actions += 1
        else:
            err_console.print(f"  [error]✖  Failed to remove {pkg}[/]")
    return actions


def _fix_venv(report: DiagnosisReport, path: str, safe: bool) -> int:
    if not any(i.code == "ENV_NO_VENV" for i in report.issues):
        return 0

    venv_path = Path(path) / ".venv"
    if venv_path.exists():
        return 0

    if safe:
        if not Confirm.ask(f"  Create a virtual environment at [code]{venv_path}[/]?"):
            return 0

    console.print(f"  [dim_text]Running: python -m venv {venv_path}[/]")
    result = subprocess.run([sys.executable, "-m", "venv", str(venv_path)])
    if result.returncode == 0:
        console.print(f"  [ok]✔  Virtual environment created at {venv_path}[/]")
        return 1
    err_console.print("  [error]✖  Failed to create venv[/]")
    return 0


def _render_fix_summary(actions: int) -> None:
    console.print()
    if actions:
        console.print(
            Panel(
                f"[ok]✔  {actions} fix(es) applied successfully.[/]", border_style="ok"
            )
        )
    else:
        console.print(Panel("[dim_text]No fixes were applied.[/]", border_style="rule"))


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
    console.print(f"🩺 [b]PyDoctor[/] version [cyan]{__version__}[/]")


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
