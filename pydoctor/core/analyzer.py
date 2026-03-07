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
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from pydoctor.config.settings import MAX_WORKERS, Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.scanners import (
    env_scanner,
    dependency_scanner,
    outdated_package_scanner,
    vulnerability_scanner,
    unused_package_scanner,
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
}


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
    ) -> None:
        self._project_path = project_path
        self._scanner_keys = scanners or list(SCANNER_REGISTRY.keys())
        self._verbose = verbose

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
        ctx = ProjectContext.from_path(self._project_path)
        report = DiagnosisReport(scan_path=str(ctx.root))
        scanner_timings: dict[str, float] = {}

        # Parallel execution for independence (each scanner gets its own thread)
        with ThreadPoolExecutor(
            max_workers=min(MAX_WORKERS, len(self._scanner_keys))
        ) as pool:
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
