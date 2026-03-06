"""
pydoctor/scanners/dependency_scanner.py
──────────────────────────────────────────
Dependency conflict scanner.

Detects:
  • Packages whose installed version violates the specifier declared by
    another installed package (conflicts).
  • Missing packages that are declared as required but not installed.

Algorithm
─────────
1. Run ``pip check`` which reports broken requirements natively.
2. Parse the output and produce structured Issue objects.

``pip check`` is the authoritative source here — it uses pip's own
resolver to identify conflicts, which is more reliable than us
re-implementing constraint satisfaction.
"""

from __future__ import annotations

import re
from typing import List

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import Issue
from pydoctor.utils.subprocess_utils import run_pip_command


CATEGORY = "dependencies"

# Pattern: "packageA 1.2 requires something>=2.0, but 1.5 is installed"
_REQUIRES_PAT = re.compile(
    r"(?P<pkg>[^\s]+)\s+(?P<ver>[^\s]+)\s+requires\s+(?P<req>[^,]+),\s+"
    r"(?:but\s+)?(?P<installed>.+?)\s+is installed",
    re.IGNORECASE,
)

# Pattern: "packageA 1.2 has requirement X, but you have X 2.0"
_HAS_REQ_PAT = re.compile(
    r"(?P<pkg>[^\s]+)\s+(?P<ver>[^\s]+)\s+has requirement\s+(?P<req>[^,]+),\s+"
    r"but you have\s+(?P<installed>.+)",
    re.IGNORECASE,
)

# Pattern: "missing required <package>"
_MISSING_PAT = re.compile(
    r"(?P<pkg>[^\s]+)\s+(?:[^\s]+\s+)?requires\s+(?P<req>[^\s,]+)(?:,\s*which is not installed)?",
    re.IGNORECASE,
)


def scan(ctx: ProjectContext) -> List[Issue]:
    """
    Run dependency conflict detection and return issues.

    Parameters
    ----------
    ctx: Project context (used for installed packages).

    Returns
    -------
    list[Issue]
    """
    issues: List[Issue] = []

    pip_check_issues = _run_pip_check()
    issues.extend(pip_check_issues)

    # If pip check found nothing, emit an OK
    if not pip_check_issues:
        issues.append(
            Issue(
                category=CATEGORY,
                code="DEP_NO_CONFLICTS",
                severity=Severity.OK,
                title="No dependency conflicts detected",
                description="All installed packages satisfy each other's requirements.",
                recommendation="",
            )
        )

    return issues


# ──────────────────────────────────────────────────────────────
# pip check
# ──────────────────────────────────────────────────────────────


def _run_pip_check() -> List[Issue]:
    """
    Invoke ``pip check`` and parse its output into Issue objects.

    ``pip check`` exits with code 0 when everything is consistent and
    non-zero when conflicts exist.  We capture its stdout regardless of
    exit code and parse line-by-line.
    """
    issues: List[Issue] = []
    result = run_pip_command(["check"])

    output = (result.stdout or "").strip()
    if not output or "No broken requirements" in output:
        return []  # Nothing to report

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try each pattern
        if m := _REQUIRES_PAT.search(line):
            issues.append(
                _make_conflict_issue(
                    pkg=m.group("pkg"),
                    ver=m.group("ver"),
                    req=m.group("req"),
                    installed=m.group("installed"),
                )
            )
        elif m := _HAS_REQ_PAT.search(line):
            issues.append(
                _make_conflict_issue(
                    pkg=m.group("pkg"),
                    ver=m.group("ver"),
                    req=m.group("req"),
                    installed=m.group("installed"),
                )
            )
        elif m := _MISSING_PAT.search(line):
            issues.append(
                _make_missing_issue(
                    pkg=m.group("pkg"),
                    req=m.group("req"),
                )
            )
        else:
            # Unrecognised line — still report it generically
            issues.append(
                Issue(
                    category=CATEGORY,
                    code="DEP_CONFLICT",
                    severity=Severity.ERROR,
                    title="Dependency conflict detected",
                    description=line,
                    recommendation=(
                        "Run `pip install --upgrade <package>` or resolve "
                        "version requirements in your requirements.txt."
                    ),
                )
            )

    return issues


def _make_conflict_issue(pkg: str, ver: str, req: str, installed: str) -> Issue:
    """Build an Issue for a version conflict."""
    return Issue(
        category=CATEGORY,
        code="DEP_VERSION_CONFLICT",
        severity=Severity.ERROR,
        title=f"Version conflict: {pkg} {ver}",
        description=(
            f"{pkg} {ver} requires {req}, but {installed} is currently installed, "
            f"which is incompatible."
        ),
        recommendation=(
            f"Resolve the conflict by upgrading or pinning packages: "
            f'`pip install "{req}"`'
        ),
        package=pkg.lower(),
        extra={
            "installed_package": pkg,
            "installed_version": ver,
            "required_spec": req,
            "conflicting_ver": installed,
        },
    )


def _make_missing_issue(pkg: str, req: str) -> Issue:
    """Build an Issue for a missing dependency."""
    return Issue(
        category=CATEGORY,
        code="DEP_MISSING",
        severity=Severity.ERROR,
        title=f"Missing dependency: {req} (required by {pkg})",
        description=(f"{pkg} requires {req}, which is not installed."),
        recommendation=f"Install the missing package: pip install {req}",
        package=pkg.lower(),
        extra={
            "requiring_package": pkg,
            "missing_package": req,
        },
    )
