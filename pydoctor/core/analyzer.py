"""
pydoctor/core/analyzer.py
──────────────────────────
Master orchestrator — runs all scanners and collects their results.

The ``Analyzer`` class is the single entry point for a full diagnosis.
It wires together:
  - ProjectContext (the project snapshot)
  - All individual scanners (env, deps, outdated, vulns, unused)
  - The parallel executor (scanners that are independent run concurrently)
  - The final DiagnosisReport assembly

Callers (CLI commands) interact only with this class, never directly with
individual scanners — enforcing clean dependency flow.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from pydoctor.config.settings import MAX_WORKERS, Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.scanners import (
    ci_scanner,
    dependency_scanner,
    env_scanner,
    outdated_package_scanner,
    unused_package_scanner,
    vulnerability_scanner,
)

# ──────────────────────────────────────────────────────────────
# Scanner registry
# ──────────────────────────────────────────────────────────────

# Maps a descriptive key → scanner module's scan() function.
# The key is used for meta-timing and selective-scan CLI flags.
SCANNER_REGISTRY: dict[str, Callable[[ProjectContext], list[Issue]]] = {
    "environment": env_scanner.scan,
    "dependencies": dependency_scanner.scan,
    "outdated": outdated_package_scanner.scan,
    "security": vulnerability_scanner.scan,
    "unused": unused_package_scanner.scan,
    "ci": ci_scanner.scan,
}


# Scanners that read the installed environment (everything except "ci").
_ENV_SCANNERS = {"environment", "dependencies", "outdated", "security", "unused"}


def context_issues(ctx: ProjectContext, scanner_keys: list[str]) -> list[Issue]:
    """
    Problems with the scan itself, reported once regardless of which scanners run.

    These exist so that a scan which couldn't see the project's packages fails
    loudly instead of returning a clean bill of health.
    """
    if not _ENV_SCANNERS.intersection(scanner_keys):
        return []
    if ctx.env_error:
        return [
            Issue(
                category="environment",
                code="ENV_PACKAGES_UNAVAILABLE",
                severity=Severity.ERROR,
                title="Couldn't read the project's installed packages",
                description=(
                    f"PyDoctor tried {ctx.project_python} ({ctx.python_source}) and got: "
                    f"{ctx.env_error}. Security, dependency, outdated and unused checks "
                    "were not run."
                ),
                recommendation=(
                    "Activate the project's virtualenv, or point PyDoctor at its interpreter "
                    "with --python path/to/python (or PYDOCTOR_PYTHON)."
                ),
                extra={"python": ctx.project_python, "source": ctx.python_source},
            )
        ]
    if ctx.declared_deps:
        from pydoctor.utils.env_probe import normalise_name

        missing = [d for d in ctx.declared_deps if normalise_name(d) not in ctx.installed_packages]
        if len(missing) == len(ctx.declared_deps):
            return [
                Issue(
                    category="environment",
                    code="ENV_DEPS_NOT_INSTALLED",
                    severity=Severity.WARNING,
                    title="None of the project's dependencies are installed in the scanned Python",
                    description=(
                        f"Scanned {ctx.python_executable} ({ctx.python_source}), which has none "
                        f"of the {len(ctx.declared_deps)} declared dependencies installed. "
                        "Results describe that interpreter, not your project."
                    ),
                    recommendation=(
                        "Install the dependencies, activate the project's virtualenv, or use "
                        "--python path/to/python."
                    ),
                    extra={"python": ctx.project_python, "missing": sorted(missing)},
                )
            ]
    return []


# ──────────────────────────────────────────────────────────────
# Analyzer
# ──────────────────────────────────────────────────────────────


class Analyzer:
    """
    Orchestrates the full PyDoctor diagnostic scan.

    Parameters
    ----------
    project_path: Directory to analyse (defaults to current working directory).
    scanners:     Optional subset of scanner keys to run.
                  Defaults to all registered scanners.
    verbose:      If True, scanner-level timing metadata is attached to the report.
    """

    def __init__(
        self,
        project_path: str = ".",
        scanners: list[str] | None = None,
        verbose: bool = False,
        python: str | None = None,
        ctx: ProjectContext | None = None,
        no_cache: bool = False,
    ) -> None:
        self._project_path = project_path
        self._scanner_keys = scanners or list(SCANNER_REGISTRY.keys())
        self._verbose = verbose
        self._python = python
        self._ctx = ctx
        self._no_cache = no_cache

    # ── Public API ─────────────────────────────────────────────

    def run(self, on_progress: Callable[[str], None] | None = None) -> DiagnosisReport:
        """
        Execute the full diagnostic scan and return a ``DiagnosisReport``.

        Scanners that are I/O-independent (env, outdated) run in parallel
        with the network-bound scanners (security) under a shared thread pool.

        Returns
        -------
        DiagnosisReport
            Aggregated result from all requested scanners.
        """
        wall_start = time.perf_counter()

        # Build project context once — shared across all scanners
        ctx = self._ctx or ProjectContext.from_path(self._project_path, python=self._python)
        ctx.no_cache = self._no_cache
        report = DiagnosisReport(scan_path=str(ctx.root), ctx=ctx)
        report.scanners = [k for k in self._scanner_keys if k in SCANNER_REGISTRY]
        scanner_timings: dict[str, float] = {}
        report.extend(context_issues(ctx, self._scanner_keys))

        # Parallel execution for independence (each scanner gets its own thread)
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(self._scanner_keys))) as pool:
            future_map = {}
            for key in self._scanner_keys:
                fn = SCANNER_REGISTRY.get(key)
                if fn is None:
                    continue
                future = pool.submit(self._timed_scan, key, fn, ctx)
                future_map[future] = key

            for future in as_completed(future_map):
                key = future_map[future]
                try:
                    if on_progress:
                        on_progress(key)
                    issues, elapsed_ms = future.result()
                    report.extend(issues)
                    scanner_timings[key] = round(elapsed_ms, 2)
                except Exception as exc:
                    # One scanner crashing must not kill the entire report
                    report.add(
                        Issue(
                            category=key,
                            code="SCANNER_ERROR",
                            severity=Severity.ERROR,
                            title=f"Scanner '{key}' encountered an error",
                            description=str(exc),
                            recommendation="Check that all required tools are installed.",
                        )
                    )

        wall_elapsed_ms = (time.perf_counter() - wall_start) * 1000
        report.scan_duration_ms = round(wall_elapsed_ms, 2)

        if self._verbose:
            report.scanner_meta["timings_ms"] = scanner_timings

        return report

    # ── Private helpers ────────────────────────────────────────

    @staticmethod
    def _timed_scan(
        key: str,
        fn: Callable[[ProjectContext], list[Issue]],
        ctx: ProjectContext,
    ) -> tuple[list[Issue], float]:
        """
        Invoke a scanner and return (issues, elapsed_ms).

        Isolated in a static method so it can be trivially called from a
        thread without capturing ``self``.
        """
        t0 = time.perf_counter()
        issues = fn(ctx)
        ms = (time.perf_counter() - t0) * 1000
        return issues, ms
