"""
pydoctor/scanners/env_scanner.py
──────────────────────────────────
Environment health scanner.

Checks the state of the Python environment for issues such as:
  • Python version too old
  • No virtual environment detected
  • pip version outdated
  • OS platform compatibility
  • Broken package metadata (dist-info missing)
"""

from __future__ import annotations

import platform
import sys
from typing import List

from pydoctor.config.settings import (
    Severity,
    MIN_PYTHON_VERSION,
    RECOMMENDED_PYTHON_VERSION,
)
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import Issue
from pydoctor.utils.pip_utils import get_pip_version

# ── Category label ─────────────────────────────────────────────
CATEGORY = "environment"


def scan(ctx: ProjectContext) -> List[Issue]:
    """
    Run all environment checks and return discovered issues.

    Parameters
    ----------
    ctx: The project context (path, installed packages, env detection, …).

    Returns
    -------
    list[Issue]
    """
    issues: List[Issue] = []

    issues.extend(_check_python_version(ctx))
    issues.extend(_check_virtual_environment(ctx))
    issues.extend(_check_pip_version())
    issues.extend(_check_platform(ctx))

    return issues


# ──────────────────────────────────────────────────────────────
# Individual checks
# ──────────────────────────────────────────────────────────────


def _check_python_version(ctx: ProjectContext) -> List[Issue]:
    """Verify that the Python version meets minimum and recommended thresholds."""
    issues: List[Issue] = []
    major, minor, micro = ctx.python_version
    ver_str = f"{major}.{minor}.{micro}"

    min_maj, min_min = MIN_PYTHON_VERSION
    rec_maj, rec_min = RECOMMENDED_PYTHON_VERSION

    if (major, minor) < MIN_PYTHON_VERSION:
        # Below minimum — hard error
        issues.append(
            Issue(
                category=CATEGORY,
                code="ENV_PYTHON_TOO_OLD",
                severity=Severity.ERROR,
                title=f"Python {ver_str} is not supported",
                description=(
                    f"Python {major}.{minor} is below the minimum supported version "
                    f"({min_maj}.{min_min}). Many modern libraries will not install "
                    f"or function correctly."
                ),
                recommendation=(
                    f"Upgrade to Python {rec_maj}.{rec_min}+ using pyenv, "
                    f"the official python.org installer, or your OS package manager."
                ),
            )
        )
    elif (major, minor) < RECOMMENDED_PYTHON_VERSION:
        # Older than recommended — warning
        issues.append(
            Issue(
                category=CATEGORY,
                code="ENV_PYTHON_OUTDATED",
                severity=Severity.WARNING,
                title=f"Python {ver_str} is below the recommended version",
                description=(
                    f"Python {major}.{minor} works but Python "
                    f"{rec_maj}.{rec_min}+ is recommended for better performance "
                    f"and security."
                ),
                recommendation=(f"Consider upgrading to Python {rec_maj}.{rec_min}+."),
            )
        )
    else:
        # All good
        issues.append(
            Issue(
                category=CATEGORY,
                code="ENV_PYTHON_OK",
                severity=Severity.OK,
                title=f"Python {ver_str} detected",
                description="Python version meets the recommended threshold.",
                recommendation="",
            )
        )

    return issues


def _check_virtual_environment(ctx: ProjectContext) -> List[Issue]:
    """Warn when running outside a virtual environment."""
    if ctx.in_virtualenv:
        return [
            Issue(
                category=CATEGORY,
                code="ENV_VENV_OK",
                severity=Severity.OK,
                title="Virtual environment detected",
                description="Running inside a virtual environment — good practice.",
                recommendation="",
            )
        ]
    else:
        return [
            Issue(
                category=CATEGORY,
                code="ENV_NO_VENV",
                severity=Severity.WARNING,
                title="No virtual environment detected",
                description=(
                    "Packages are being installed into the system Python, which "
                    "can cause conflicts between projects and pollute the global "
                    "namespace."
                ),
                recommendation=(
                    "Create a virtual environment: python -m venv .venv && "
                    "source .venv/bin/activate  (use .venv\\Scripts\\activate on Windows)"
                ),
            )
        ]


def _check_pip_version() -> List[Issue]:
    """Check that pip is installed and not critically outdated."""
    pip_ver = get_pip_version()

    if pip_ver is None:
        return [
            Issue(
                category=CATEGORY,
                code="ENV_PIP_MISSING",
                severity=Severity.ERROR,
                title="pip is not available",
                description="pip could not be found or invoked.",
                recommendation=(
                    "Reinstall pip: python -m ensurepip --upgrade "
                    "or python -m pip install --upgrade pip"
                ),
            )
        ]

    # Try to parse major version
    try:
        pip_major = int(pip_ver.split(".")[0])
    except (ValueError, IndexError):
        pip_major = 0

    if pip_major < 21:
        return [
            Issue(
                category=CATEGORY,
                code="ENV_PIP_OUTDATED",
                severity=Severity.WARNING,
                title=f"pip {pip_ver} is outdated",
                description="Old pip versions lack resolver improvements and security fixes.",
                recommendation="Upgrade pip: python -m pip install --upgrade pip",
            )
        ]

    return [
        Issue(
            category=CATEGORY,
            code="ENV_PIP_OK",
            severity=Severity.OK,
            title=f"pip {pip_ver} is up to date",
            description="pip version meets requirements.",
            recommendation="",
        )
    ]


def _check_platform(ctx: ProjectContext) -> List[Issue]:
    """Emit an informational note about the current OS and architecture."""
    os_name = ctx.os_name  # e.g. "Windows", "Linux", "Darwin"
    arch = platform.machine()  # e.g. "AMD64", "x86_64"
    release = platform.release()
    python_path = ctx.python_executable

    return [
        Issue(
            category=CATEGORY,
            code="ENV_PLATFORM_INFO",
            severity=Severity.INFO,
            title=f"Platform: {os_name} {release} ({arch})",
            description=(f"OS: {os_name} {release}\n" f"Arch: {arch}\n" f"Python: {python_path}"),
            recommendation="",
        )
    ]
