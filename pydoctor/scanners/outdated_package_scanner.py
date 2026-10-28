"""
pydoctor/scanners/outdated_package_scanner.py
───────────────────────────────────────────────
Outdated package scanner.

Uses ``pip list --outdated --format=json`` to identify packages that have
newer versions available on PyPI.

Each outdated package becomes a WARNING-severity issue with a clear
recommendation to upgrade.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import Issue
from pydoctor.utils.pip_utils import get_outdated_packages, get_outdated_packages_uv

CATEGORY = "outdated"


def _unavailable(reason: str) -> Issue:
    return Issue(
        category=CATEGORY,
        code="PKG_OUTDATED_UNAVAILABLE",
        severity=Severity.INFO,
        title="Outdated-package check skipped",
        description=f"PyDoctor couldn't list outdated packages: {reason}",
        recommendation=(
            "Install pip in the project environment, or install uv, then run the scan again."
        ),
    )


def scan(ctx: ProjectContext) -> list[Issue]:
    """
    Detect outdated packages in the project environment.

    Uses ``pip list --outdated`` when pip is installed in the project, and
    ``uv pip list --outdated`` otherwise. If neither can run, the check is
    reported as skipped, never as "all up to date".
    """
    import shutil
    import subprocess

    issues: list[Issue] = []
    if ctx.env_error:
        return issues

    uv = shutil.which("uv")
    try:
        # ctx.distributions is empty only for contexts built without a probe
        # (for example in tests); keep pip as the default there.
        if ctx.pip_version or not ctx.distributions:
            outdated = get_outdated_packages(python_executable=ctx.project_python)
        elif uv:
            outdated = get_outdated_packages_uv(uv, ctx.project_python)
        else:
            return [
                _unavailable(
                    "pip isn't installed in the project environment, and uv isn't on PATH."
                )
            ]
    except subprocess.TimeoutExpired:
        issues.append(
            Issue(
                category=CATEGORY,
                code="PKG_OUTDATED_TIMEOUT",
                severity=Severity.INFO,
                title="Network Timeout: Outdated Check Skipped",
                description="Checking for outdated packages over the network took too long. This is usually due to a slow internet connection or index server.",
                recommendation="Try running the check again later or verify your network connection.",
            )
        )
        return issues
    except Exception as exc:
        return [_unavailable(str(exc) or exc.__class__.__name__)]

    if outdated is None:
        return [_unavailable("the package index couldn't be queried.")]

    if not outdated:
        issues.append(
            Issue(
                category=CATEGORY,
                code="PKG_ALL_UP_TO_DATE",
                severity=Severity.OK,
                title="All packages are up to date",
                description="No outdated packages were detected in the environment.",
                recommendation="",
            )
        )
        return issues

    for pkg in outdated:
        name = pkg.get("name", "unknown")
        current = pkg.get("version", "?")
        latest = pkg.get("latest_version", "?")
        filetype = pkg.get("latest_filetype", "")

        # Determine if this is a major-version upgrade (potentially breaking)
        severity = _assess_severity(current, latest)

        issues.append(
            Issue(
                category=CATEGORY,
                code="PKG_OUTDATED",
                severity=severity,
                title=f"{name} {current} → {latest}",
                description=(
                    f"{name} is at version {current}. The latest available version "
                    f"is {latest} ({filetype})."
                ),
                recommendation=f"pip install --upgrade {name}",
                package=name.lower(),
                extra={
                    "current_version": current,
                    "latest_version": latest,
                    "filetype": filetype,
                },
            )
        )

    return issues


def _assess_severity(current: str, latest: str) -> str:
    """
    Decide whether an outdated package warrants a WARNING or just INFO.

    Rules:
    - Major version bump (1.x → 2.x) → WARNING (potentially breaking)
    - Minor / patch bump              → INFO
    - Unparseable versions            → WARNING (play it safe)
    """
    try:
        cur = Version(current)
        lat = Version(latest)
        if lat.major > cur.major:
            return Severity.WARNING
        return Severity.INFO
    except (InvalidVersion, TypeError):
        return Severity.WARNING
