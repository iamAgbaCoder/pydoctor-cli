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
from pathlib import Path
from typing import Annotated

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore
    except Exception:
        pass

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
from pydoctor.core.analyzer import Analyzer
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import DiagnosisReport
from pydoctor.reports.json_formatter import render_json
from pydoctor.reports.table_formatter import (
    CATEGORY_LABELS,
    console,
    render_report,
)
from pydoctor.reports.terminal_colors import PYDOCTOR_THEME
from pydoctor.utils.pip_utils import (
    remove_from_requirements_file,
    update_requirements_file,
)
from pydoctor.utils.subprocess_utils import run_pip_command


def version_callback(value: bool):
    if value:
        console.print(f"🩺 [b]PyDoctor[/] version [cyan]{__version__}[/]")
        raise typer.Exit()


_HELP_EPILOG = """
[section]🚀  QUICK START WORKFLOW[/]

  [dim]1.[/] [b]Full Diagnosis:[/]       [code]$ pydoctor diagnose[/]
  [dim]2.[/] [b]CI Security:[/]          [code]$ pydoctor check --ci[/]
  [dim]3.[/] [b]Auto-Remediation:[/]     [code]$ pydoctor fix[/]

[section]🏥  COMMUNITY & SUPPORT[/]

  [label]Docs:[/][pkg] https://pydoctor.vercel.app/docs[/]
  [label]Version:[/][info] v2.0.0 (Premium Kernel Edition)[/]

[kernel]Healthy code leads to healthy deployments. Keep your environment sterile.[/]
"""

app = typer.Typer(
    name="pydoctor",
    help="🩺 [bold white]PyDoctor[/] — [italic grey70]Python Environment Diagnostic Assistant[/]\n\n[dim]Automate your environment audits, dependency security scans, and bloat detection in seconds.[/]",
    epilog=_HELP_EPILOG,
    add_completion=False,
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

_PATH_ARG = typer.Option(..., "--path", "-p", help="Project directory to scan.")
_JSON_ARG = typer.Option(..., "--json", "-j", help="Output results as JSON.")
_VERBOSE_ARG = typer.Option(..., "--verbose", "-v", help="Show detailed output and timing.")
_NO_CACHE_ARG = typer.Option(..., "--no-cache", help="Bypass the local vulnerability cache.")


# ──────────────────────────────────────────────────────────────
# Helper: run a scan with a spinner
# ──────────────────────────────────────────────────────────────


def _run_scan(
    scanners: list[str] | None = None,
    path: str = ".",
    verbose: bool = False,
    no_cache: bool = False,
    as_json: bool = False,
    ci_mode: bool = False,
    command: str | None = None,
) -> DiagnosisReport:  # noqa: C901
    """Run the Analyzer with Rich progress indicators."""
    if no_cache:
        CacheManager().clear()

    if not as_json:
        console.print("[section]Scanning project...[/]")

    # If ci_mode is on, we force the ci scanner
    if ci_mode:
        if scanners is None:
            scanners = ["ci"]
        elif "ci" not in scanners:
            scanners.append("ci")

    def progress_callback(key: str) -> None:
        if not as_json:
            label = CATEGORY_LABELS.get(key, key.title())
            console.print(f"[kernel]»[/] Checking {label.lower().replace(' ', ' ')}")

    if as_json:
        analyzer = Analyzer(project_path=path, scanners=scanners, verbose=verbose)
        report = analyzer.run(on_progress=None)
        report.command = command
        return report

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
        report.command = command

    return report


def _output(report: DiagnosisReport, as_json: bool, verbose: bool = False) -> None:
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

        threshold = report.ctx.config.get("min_health_score", 0) if report.ctx else 0
        if threshold > 0:
            metrics = calculate_health(report)
            if metrics.score < threshold:
                return 1
    except Exception:
        pass
    return 0


@app.command(rich_help_panel="CORE COMMANDS")
def diagnose(
    path: Annotated[str, _PATH_ARG] = ".",
    json: Annotated[bool, _JSON_ARG] = False,
    verbose: Annotated[bool, _VERBOSE_ARG] = False,
    no_cache: Annotated[bool, _NO_CACHE_ARG] = False,
) -> None:  # noqa: C901
    """🩺  Run a **full** diagnosis of your Python project."""
    if not json:
        ctx = ProjectContext.from_path(path)
        if not ctx.in_virtualenv:
            console.print("[warning]⚠ No virtual environment detected in this project.[/]")
            if not Confirm.ask("Do you want to proceed using global system packages?"):
                console.print(
                    "\n[info]ℹ Cancelled. Please activate a virtual environment and try again.[/]"
                )
                raise typer.Exit()

    report = _run_scan(
        path=path, verbose=verbose, no_cache=no_cache, as_json=json, command="diagnose"
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


@app.command(rich_help_panel="CORE COMMANDS")
def check(
    path: Annotated[str, _PATH_ARG] = ".",
    ci: bool = typer.Option(False, "--ci", help="Run in CI/CD guard mode."),
    json: Annotated[bool, _JSON_ARG] = False,
    verbose: Annotated[bool, _VERBOSE_ARG] = False,
) -> None:
    """🛡️  Perform security and health checks. Use --ci for pipeline shielding."""
    report = _run_scan(path=path, ci_mode=ci, verbose=verbose, as_json=json, command="check")
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


@app.command(rich_help_panel="SECURITY & CI/CD")
def docker(
    image: Annotated[str | None, typer.Argument(help="Docker image to scan (optional).")] = None,
    path: Annotated[str, _PATH_ARG] = ".",
) -> None:
    """🐳  Diagnose Python issues inside **Docker** containers."""
    console.print(Panel("[section]🐳 Docker Environment Doctor[/]", border_style="rule"))
    console.print("[kernel]Scanning for Dockerfile and container runtime...[/]")
    dockerfile = Path(path) / "Dockerfile"
    if not dockerfile.exists():
        console.print("[error]✖ No Dockerfile found in current directory.[/]")
    else:
        console.print(f"[ok]✔[/] [pkg]Dockerfile[/] detected at {dockerfile}")
        content = dockerfile.read_text()
        if "python" not in content.lower():
            console.print(
                "[warning]⚠ Warning: Dockerfile might not be using a Python base image.[/]"
            )
        else:
            console.print("[ok]✔[/] Python base image identified.")
    console.print("\n[info]ℹ This feature is in beta. Full container introspection coming soon.[/]")


@app.command(rich_help_panel="SECURITY & CI/CD")
def github(
    repo: Annotated[str | None, typer.Argument(help="GitHub repository URL (optional).")] = None,
    path: Annotated[str, _PATH_ARG] = ".",
    json: Annotated[bool, _JSON_ARG] = False,
    verbose: Annotated[bool, _VERBOSE_ARG] = False,
) -> None:
    """🐙  Integrate with **GitHub** for repository-wide health scans."""
    if not json:
        console.print(Panel("[section]🐙 GitHub Repository Doctor[/]", border_style="rule"))
        if not repo:
            res = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=path,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                console.print("[warning]✖ Not an active git repository.[/]")
            else:
                console.print("[ok]✔[/] Local git repository detected.")
        console.print("\n[info]ℹ Running pydoctor on the current branch...[/]")

    report = _run_scan(path=path, ci_mode=True, verbose=verbose, as_json=json, command="github")
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


# --- Individual Targeted Scans ---


@app.command(name="scan-security", rich_help_panel="SECURITY & CI/CD")
def scan_security(
    path: Annotated[str, _PATH_ARG] = ".",
    json: Annotated[bool, _JSON_ARG] = False,
    verbose: Annotated[bool, _VERBOSE_ARG] = False,
) -> None:
    """🔒 Scan installed packages for known vulnerabilities (OSV)."""
    report = _run_scan(
        scanners=["security"], path=path, verbose=verbose, as_json=json, command="scan-security"
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


# ──────────────────────────────────────────────────────────────
# scan-unused
# ──────────────────────────────────────────────────────────────


@app.command(name="scan-unused", rich_help_panel="RESOURCE HYGIENE")
def scan_unused(
    path: Annotated[str, _PATH_ARG] = ".",
    json: Annotated[bool, _JSON_ARG] = False,
    verbose: Annotated[bool, _VERBOSE_ARG] = False,
) -> None:
    """🧹 Detect unused packages via AST analysis."""
    report = _run_scan(
        scanners=["unused"], path=path, verbose=verbose, as_json=json, command="scan-unused"
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


@app.command(name="scan-deps", rich_help_panel="RESOURCE HYGIENE")
def scan_deps(
    path: Annotated[str, _PATH_ARG] = ".",
    json: Annotated[bool, _JSON_ARG] = False,
    verbose: Annotated[bool, _VERBOSE_ARG] = False,
) -> None:
    """📦 Scan for dependency version conflicts."""
    report = _run_scan(
        scanners=["dependencies"], path=path, verbose=verbose, as_json=json, command="scan-deps"
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


@app.command(name="check-env", rich_help_panel="RESOURCE HYGIENE")
def check_env(
    path: Annotated[str, _PATH_ARG] = ".",
    json: Annotated[bool, _JSON_ARG] = False,
    verbose: Annotated[bool, _VERBOSE_ARG] = False,
) -> None:
    """🌍 Verify Python and virtual environment health."""
    report = _run_scan(
        scanners=["environment"], path=path, verbose=verbose, as_json=json, command="check-env"
    )
    _output(report, as_json=json, verbose=verbose)
    raise typer.Exit(code=_exit_code(report, path))


# --- Re-adding fix and other commands ---


@app.command(rich_help_panel="CORE COMMANDS")
def fix(
    packages: Annotated[
        list[str] | None, typer.Argument(help="Specific packages to fix (optional).")
    ] = None,
    path: Annotated[str, _PATH_ARG] = ".",
    safe: bool = typer.Option(True, "--safe/--no-safe", help="Confirm each action."),
    upgrade: bool = typer.Option(True, "--upgrade/--no-upgrade", help="Upgrade outdated."),
    remove: bool = typer.Option(False, "--remove/--no-remove", help="Remove unused."),
) -> None:
    """🔧  Apply **automated fixes** to common issues."""
    console.print(
        Panel(
            "[section]🔧 PyDoctor Auto-Fix[/]\n\nScanning for fixable issues …", border_style="rule"
        )
    )
    report_data = _run_scan(path=path)
    ctx = ProjectContext.from_path(path)
    if packages:
        _filter_issues_by_targets(report_data, packages)
    actions = 0
    actions += _fix_vulnerabilities(report_data, ctx, safe)
    if upgrade:
        actions += _fix_outdated(report_data, ctx, safe)
    actions += _fix_dependencies(report_data, ctx, safe)
    if remove or packages:
        actions += _fix_unused(report_data, ctx, safe)
    actions += _fix_venv(report_data, path, safe)
    _render_fix_summary(actions)


def _filter_issues_by_targets(report_data, packages):
    targets = {p.lower() for p in packages}
    report_data.issues = [
        i for i in report_data.issues if i.package and i.package.lower() in targets
    ]
    if not report_data.issues:
        console.print(f"\n[warning]No fixable issues found for: {', '.join(packages)}[/]")
        raise typer.Exit()


def _run_package_manager_command(ctx, pkg, action, upgrade=False):
    path = str(ctx.root)
    if ctx.is_poetry:
        cmd = ["poetry", "add", pkg] if action == "add" else ["poetry", "remove", pkg]
        if action == "update":
            cmd = ["poetry", "update", pkg]
        console.print(f"  [dim_text]Running: {' '.join(cmd)}[/]")
        return subprocess.run(cmd, cwd=path)
    if ctx.is_uv:
        cmd = ["uv", "add", pkg] if action == "add" else ["uv", "remove", pkg]
        if upgrade:
            cmd = ["uv", "add", "--upgrade", pkg]
        console.print(f"  [dim_text]Running: {' '.join(cmd)}[/]")
        return subprocess.run(cmd, cwd=path)
    if ctx.is_pdm:
        cmd = ["pdm", "add", pkg] if action == "add" else ["pdm", "remove", pkg]
        if action == "update":
            cmd = ["pdm", "update", pkg]
        console.print(f"  [dim_text]Running: {' '.join(cmd)}[/]")
        return subprocess.run(cmd, cwd=path)
    if action == "remove":
        return run_pip_command(["uninstall", "-y", pkg], python_executable=ctx.project_python)
    else:
        args = ["install"]
        if upgrade:
            args.append("--upgrade")
        args.append(pkg)
        return run_pip_command(args, python_executable=ctx.project_python)


def _update_pip_requirements(ctx, pkg, safe, action, version_spec=""):
    if ctx.is_poetry or ctx.is_uv or ctx.is_pdm:
        return
    req_file = ctx.root / "requirements.txt"
    if not req_file.is_file():
        return
    if action == "remove":
        if not safe or Confirm.ask(" Remove from requirements.txt?"):
            remove_from_requirements_file(req_file, pkg)
    elif action == "update":
        if not safe or Confirm.ask(" Update requirements.txt?"):
            update_requirements_file(req_file, pkg, version_spec)


def _fix_vulnerabilities(report, ctx, safe):
    vulnerable = [i for i in report.issues if i.code == "SEC_VULNERABILITY"]
    if not vulnerable:
        return 0
    actions = 0
    for i in vulnerable:
        if i.package and (not safe or Confirm.ask(f" Fix {i.package}?")):
            if _run_package_manager_command(ctx, i.package, "add", True).returncode == 0:
                console.print(f" [ok]✔ {i.package} fixed.[/]")
                actions += 1
    return actions


def _fix_outdated(report, ctx, safe):
    outdated = [i for i in report.issues if i.code == "PKG_OUTDATED"]
    actions = 0
    for i in outdated:
        pkg = i.package
        if pkg and (not safe or Confirm.ask(f" Upgrade {pkg}?")):
            if _run_package_manager_command(ctx, pkg, "update", True).returncode == 0:
                console.print(f" [ok]✔ {pkg} upgraded.[/]")
                actions += 1
    return actions


def _fix_dependencies(report, ctx, safe):
    conflicts = [
        i
        for i in report.issues
        if i.category == "dependencies" and i.code in ("DEP_MISSING", "DEP_VERSION_CONFLICT")
    ]
    actions = 0
    for i in conflicts:
        target = i.extra.get("missing_package") or i.extra.get("required_spec")
        if target and (not safe or Confirm.ask(f" Resolve {target}?")):
            if _run_package_manager_command(ctx, target, "add").returncode == 0:
                console.print(f" [ok]✔ {target} resolved.[/]")
                actions += 1
    return actions


def _fix_unused(report, ctx, safe):
    unused = [i for i in report.issues if i.code == "UNUSED_PACKAGE"]
    actions = 0
    for i in unused:
        if i.package and (not safe or Confirm.ask(f" Remove {i.package}?")):
            if _run_package_manager_command(ctx, i.package, "remove").returncode == 0:
                console.print(f" [ok]✔ {i.package} removed.[/]")
                actions += 1
    return actions


def _fix_venv(report, path, safe):
    if not any(i.code == "ENV_NO_VENV" for i in report.issues):
        return 0
    venv_path = Path(path) / ".venv"
    if venv_path.exists():
        return 0
    if not safe or Confirm.ask(f" Create venv at {venv_path}?"):
        if subprocess.run([sys.executable, "-m", "venv", str(venv_path)]).returncode == 0:
            console.print(" [ok]✔ venv created.[/]")
            return 1
    return 0


def _render_fix_summary(actions):
    if actions:
        console.print(Panel(f"[ok]✔ {actions} fixes applied.[/]", border_style="ok"))
    else:
        console.print(Panel("[dim_text]No fixes applied.[/]", border_style="rule"))


cache_app = typer.Typer(help="Manage the PyDoctor local cache.")
app.add_typer(cache_app, name="cache")


@cache_app.command("clear")
def cache_clear():
    CacheManager().clear()
    console.print("[ok]✔ Cache cleared.[/]")


@cache_app.command("purge")
def cache_purge():
    removed = CacheManager().purge_expired()
    console.print(f"[ok]✔ Purged {removed} entries.[/]")


@app.command()
def version():
    console.print(f"🩺 [b]PyDoctor[/] version [cyan]{__version__}[/]")


def main():
    app()


if __name__ == "__main__":
    main()
