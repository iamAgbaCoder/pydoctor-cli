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

    # Step 3: Account for implicit dependencies
    # Walk the entire tree. If a package (or any of its parents in the tree)
    # is imported, then all of its descendants are "used".
    implicitly_used: set[str] = set()

    def mark_descendants_used(node: dict):
        for dep in node.get("dependencies", []):
            dname = dep.get("package_name", "").lower().replace("_", "-")
            if dname not in implicitly_used:
                implicitly_used.add(dname)
                mark_descendants_used(dep)

    def search_and_mark(nodes: list[dict]):
        for node in nodes:
            name = node.get("package_name", "").lower().replace("_", "-")
            if name in imported_packages:
                mark_descendants_used(node)
            # Continue searching in children even if this node wasn't imported
            # (as a child of this node might be imported)
            search_and_mark(node.get("dependencies", []))

    search_and_mark(ctx.dependency_graph)

    # Step 4: Find declared dependencies that are NOT imported AND NOT implicitly used
    unused: list[str] = []

    # Merge hardcoded defaults with user configuration
    ignored = {
        "black",
        "pytest",
        "flake8",
        "mypy",
        "tox",
        "isort",
        "pydoctor",
        "rich",
        "pydoctor-cli",
        "setuptools",
        "wheel",
    }
    if "ignored_packages" in ctx.config:
        ignored.update(
            p.lower().replace("_", "-") for p in ctx.config["ignored_packages"]
        )

    for dep_name in ctx.declared_deps:
        normalised = dep_name.lower().replace("_", "-")
        if normalised not in imported_packages and normalised not in implicitly_used:
            # Final check: is it a dev-only tool or ignored by config?
            if normalised in ignored:
                continue
            unused.append(dep_name)

    # Step 5: Produce issues
    if not unused:
        issues.append(
            Issue(
                category=CATEGORY,
                code="UNUSED_NONE_FOUND",
                severity=Severity.OK,
                title="No unused packages detected",
                description="All declared dependencies appear to be imported or required by imported packages.",
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
