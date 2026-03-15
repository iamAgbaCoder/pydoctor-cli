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


def scan(ctx: ProjectContext) -> list[Issue]:
    """
    Detect packages that are declared in requirements but never imported.
    """
    precondition_issues = _check_preconditions(ctx)
    if precondition_issues:
        return precondition_issues

    imported_packages = _get_imported_packages(ctx)
    implicitly_used = _get_implicitly_used_packages(ctx, imported_packages)

    unused, transitive = _identify_unused(ctx, imported_packages, implicitly_used)

    issues: list[Issue] = []

    if not unused and not transitive:
        return [
            Issue(
                category=CATEGORY,
                code="UNUSED_NONE_FOUND",
                severity=Severity.OK,
                title="No unused packages detected",
                description="All declared dependencies appear to be properly utilized.",
                recommendation="",
            )
        ]

    for pkg in sorted(unused):
        issues.append(
            Issue(
                category=CATEGORY,
                code="UNUSED_PACKAGE",
                severity=Severity.WARNING,
                title=f"Unused dependency: {pkg}",
                description=f"No imports corresponding to '{pkg}' were found, and it is not required by any used packages.",
                recommendation=f"pip uninstall {pkg}",
                package=pkg,
            )
        )

    for pkg, parents in sorted(transitive, key=lambda x: x[0]):
        parent_str = ", ".join(parents[:3])
        if len(parents) > 3:
            parent_str += " and others"

        issues.append(
            Issue(
                category=CATEGORY,
                code="UNUSED_TRANSITIVE",
                severity=Severity.INFO,
                title=f"Transitive dependency: {pkg} [dim](required by {parent_str})[/]",
                description=f"'{pkg}' is declared explicitly but only used indirectly via {parent_str}.",
                recommendation="Consider removing from requirements to keep dependencies lean.",
                package=pkg,
            )
        )

    return issues


def _check_preconditions(ctx: ProjectContext) -> list[Issue]:
    if not ctx.declared_deps:
        return [
            Issue(
                category=CATEGORY,
                code="UNUSED_NO_DEPS_FILE",
                severity=Severity.INFO,
                title="No dependencies file found",
                description="Cannot detect unused packages without a requirements file.",
                recommendation="Create a requirements.txt file.",
            )
        ]
    if not ctx.python_files:
        return [
            Issue(
                category=CATEGORY,
                code="UNUSED_NO_PY_FILES",
                severity=Severity.INFO,
                title="No Python source files found",
                description="No .py files were found to scan.",
                recommendation="Check the directory path.",
            )
        ]
    return []


def _get_imported_packages(ctx: ProjectContext) -> set[str]:
    names = extract_imports_from_project(ctx.python_files)
    pkgs = set()
    for n in names:
        pkgs.add(import_name_to_package(n))
        pkgs.add(n.lower().replace("_", "-"))
    return pkgs


def _get_implicitly_used_packages(ctx: ProjectContext, imported: set[str]) -> dict[str, list[str]]:
    used: dict[str, list[str]] = {}

    # We also consider dependencies of "ignored" packages as used
    # (e.g., if black is ignored, its dependencies like pathspec are also "used")
    ignored_base = {
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
        "pipdeptree",
        "ruff",
        "build",
    }
    if "ignored_packages" in ctx.config:
        ignored_base.update(p.lower().replace("_", "-") for p in ctx.config["ignored_packages"])

    search_roots = imported | ignored_base

    def mark(node: dict, parent: str):
        for dep in node.get("dependencies", []):
            dname = dep.get("package_name", "").lower().replace("_", "-")
            if parent not in used.setdefault(dname, []):
                used[dname].append(parent)
                mark(dep, parent)

    def search(nodes: list[dict]):
        for node in nodes:
            name = node.get("package_name", "").lower().replace("_", "-")
            if name in search_roots:
                mark(node, name)
            search(node.get("dependencies", []))

    search(ctx.dependency_graph)
    return used


def _identify_unused(
    ctx: ProjectContext, imported: set[str], implicit: dict[str, list[str]]
) -> tuple[list[str], list[tuple[str, list[str]]]]:
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
        "ruff",
        "build",
    }
    if "ignored_packages" in ctx.config:
        ignored.update(p.lower().replace("_", "-") for p in ctx.config["ignored_packages"])

    unused = []
    transitive = []

    for dep in ctx.declared_deps:
        norm = dep.lower().replace("_", "-")
        if norm in imported or norm in ignored:
            continue

        if norm in implicit:
            transitive.append((dep, implicit[norm]))
        else:
            unused.append(dep)

    return unused, transitive
