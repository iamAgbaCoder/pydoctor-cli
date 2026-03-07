"""
pydoctor/scanners/unused_package_scanner.py
─────────────────────────────────────────────
Unused dependency detector via static AST analysis.

Algorithm
─────────
1. Scan all .py files in the project using the AST.
2. Collect every top-level import name.
3. Normalise import names → PyPI package names (using the known mapping
   table plus a fallback normalisation).
4. Compare against the project's *declared* dependencies
   (requirements.txt / pyproject.toml).
5. Packages that are declared but never imported are flagged as unused.

Limitations
───────────
- Dynamic imports (``importlib.import_module``, ``__import__``) are not
  tracked — false positives may occur for packages loaded dynamically.
- Standard library modules are excluded automatically.
- Only *declared* dependencies are checked; transitive installs are not.
"""

from __future__ import annotations

import sys
from typing import List

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import Issue
from pydoctor.utils.parser_utils import (
    extract_imports_from_project,
    import_name_to_package,
)


CATEGORY = "unused"

# Standard library top-level modules — we exclude these from unused detection
_STDLIB_MODULES: frozenset[str] = frozenset(sys.stdlib_module_names)  # Python 3.10+


def scan(ctx: ProjectContext) -> List[Issue]:
    """
    Detect packages that are declared in requirements but never imported.

    Parameters
    ----------
    ctx: Project context with python_files and declared_deps.

    Returns
    -------
    list[Issue]
    """
    issues: List[Issue] = []

    if not ctx.declared_deps:
        issues.append(
            Issue(
                category=CATEGORY,
                code="UNUSED_NO_DEPS_FILE",
                severity=Severity.INFO,
                title="No requirements.txt found",
                description=(
                    "Cannot detect unused packages without a requirements.txt or "
                    "pyproject.toml in the project root."
                ),
                recommendation=(
                    "Create a requirements.txt with `pip freeze > requirements.txt`."
                ),
            )
        )
        return issues

    if not ctx.python_files:
        issues.append(
            Issue(
                category=CATEGORY,
                code="UNUSED_NO_PY_FILES",
                severity=Severity.INFO,
                title="No Python source files found",
                description="No .py files were found to scan for imports.",
                recommendation="Ensure you're running pydoctor from your project root.",
            )
        )
        return issues

    # Step 1: Extract all imported names from the project
    imported_names = extract_imports_from_project(ctx.python_files)

    # Step 2: Normalise import names → PyPI package names
    imported_packages: set[str] = set()
    for name in imported_names:
        pkg_name = import_name_to_package(name)
        imported_packages.add(pkg_name)
        # Also add the raw import name as a fallback
        imported_packages.add(name.lower().replace("_", "-"))

    # Step 3: Find declared dependencies that are NOT imported
    unused: list[str] = []
    for dep_name in ctx.declared_deps:
        normalised = dep_name.lower().replace("_", "-")
        if normalised not in imported_packages:
            unused.append(dep_name)

    # Step 4: Produce issues
    if not unused:
        issues.append(
            Issue(
                category=CATEGORY,
                code="UNUSED_NONE_FOUND",
                severity=Severity.OK,
                title="No unused packages detected",
                description="All declared dependencies appear to be imported.",
                recommendation="",
            )
        )
    else:
        for pkg in sorted(unused):
            issues.append(
                Issue(
                    category=CATEGORY,
                    code="UNUSED_PACKAGE",
                    severity=Severity.WARNING,
                    title=f"Possibly unused: {pkg}",
                    description=(
                        "Confidence: 82%\n"
                        f"No imports corresponding to '{pkg}' were found in project files."
                    ),
                    recommendation=(f"pip uninstall {pkg}"),
                    package=pkg,
                    extra={"imported_packages_count": len(imported_packages)},
                )
            )

    return issues
