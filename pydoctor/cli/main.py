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
from pydoctor.reports.table_formatter import (
    render_report,
    render_issue_detail,
    console,
    CATEGORY_LABELS,
)
from pydoctor.reports.json_formatter import render_json
from pydoctor.cache.cache_manager import CacheManager
from pydoctor.config.settings import Severity, PYDOCTOR_HOME
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
    version: Optional[bool] = typer.Option(
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
_VERBOSE_FLAG = typer.Option(False, "--verbose", "-v", help="Show detailed output and timing.")
_NO_CACHE = typer.Option(False, "--no-cache", help="Bypass the local vulnerability cache.")


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
        task = progress.add_task("🩺 PyDoctor scanning project...", total=None)
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
    report = _run_scan(path=path, verbose=verbose, no_cache=no_cache, as_json=json)
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
    report = _run_scan(scanners=["environment"], path=path, verbose=verbose, as_json=json)
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
    report = _run_scan(scanners=["dependencies"], path=path, verbose=verbose, as_json=json)
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
        as_json=json,
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
    report = _run_scan(scanners=["unused"], path=path, verbose=verbose, as_json=json)
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
    report_data = _run_scan(path=path, verbose=verbose, no_cache=no_cache, as_json=json)
    _output(report_data, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report_data))


# ──────────────────────────────────────────────────────────────
# fix — automated remediation
# ──────────────────────────────────────────────────────────────


@app.command()
def fix(
    packages: Optional[List[str]] = typer.Argument(
        None, help="Specific packages to fix (optional)."
    ),
    path: str = _PATH_OPT,
    safe: bool = typer.Option(
        True,
        "--safe/--no-safe",
        help="Safe mode asks for confirmation before each action (default: on).",
    ),
    upgrade: bool = typer.Option(True, "--upgrade/--no-upgrade", help="Upgrade outdated packages."),
    remove: bool = typer.Option(False, "--remove/--no-remove", help="Remove unused packages."),
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

    # Filter issues if specific packages were provided
    if packages:
        # Normalize package names for matching
        targets = {p.lower() for p in packages}
        report_data.issues = [
            i for i in report_data.issues if i.package and i.package.lower() in targets
        ]
        if not report_data.issues:
            console.print(
                f"\n[warning]No fixable issues found for packages: {', '.join(packages)}[/]"
            )
            raise typer.Exit()

    # ── Upgrade vulnerable packages ────────────────────────────
    vulnerable = [i for i in report_data.issues if i.category == "security"]
    if vulnerable:
        console.print(f"\n[section]Found {len(vulnerable)} security vulnerabilities to fix:[/]")
        # Group by package to avoid multiple upgrades for same package
        vulnerable_pkgs = {}
        for i in vulnerable:
            if i.package:
                vulnerable_pkgs[i.package] = i

        for pkg, issue in vulnerable_pkgs.items():
            if safe:
                ok = Confirm.ask(f"  Fix vulnerability in [pkg]{pkg}[/] by upgrading?")
                if not ok:
                    continue

            console.print(f"  [dim_text]Running: pip install --upgrade {pkg}[/]")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                console.print(f"  [ok]✔  {pkg} upgraded successfully.[/]")
                actions_taken += 1

                # Also try to update requirements.txt if it exists
                from pydoctor.utils.pip_utils import update_requirements_file

                req_file = Path(path) / "requirements.txt"
                if req_file.is_file():
                    # We don't have the exact version here easily, but we can assume latest was installed
                    # Actually, we should probably pass the target version if we knew it.
                    # For now just confirming success.
                    pass
            else:
                err_console.print(f"  [error]✖  Failed to fix {pkg}[/]")

    # ── Upgrade outdated packages ──────────────────────────────
    if upgrade:
        outdated = [i for i in report_data.issues if i.code == "PKG_OUTDATED"]
        if outdated:
            console.print(f"\n[section]Found {len(outdated)} outdated package(s) to upgrade:[/]")
            for issue in outdated:
                pkg = issue.package or issue.extra.get("name", "")
                if not pkg:
                    continue
                # Skip if already handled in vulnerability upgrade
                if pkg in vulnerable:
                    continue

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

                    # Also try to update requirements.txt if it exists
                    from pydoctor.utils.pip_utils import update_requirements_file

                    req_file = Path(path) / "requirements.txt"
                    if req_file.is_file():
                        if update_requirements_file(req_file, pkg, f"=={latest}"):
                            console.print(f"  [ok]✔  Updated {req_file.name}[/]")
                else:
                    err_console.print(f"  [error]✖  Failed to upgrade {pkg}[/]")
        else:
            if not packages:  # Only show "No outdated" if we aren't targeting specific pkgs
                console.print("[ok]✔  No outdated packages to upgrade.[/]")

    # ── Remove unused packages ─────────────────────────────────
    if remove or packages:  # If specific packages are targeted, we try to remove if they are unused
        unused = [i for i in report_data.issues if i.code == "UNUSED_PACKAGE"]
        if unused:
            console.print(f"\n[section]Found {len(unused)} possibly unused package(s):[/]")
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
                    console.print(f"  [ok]✔  Virtual environment created at {venv_path}[/]")
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
    console.print(f"[ok]✔  Purged {removed} expired cache entr{'y' if removed==1 else 'ies'}.[/]")


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
    non_ok = [i for i in report.issues if i.severity not in (Severity.OK, Severity.INFO)]
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
