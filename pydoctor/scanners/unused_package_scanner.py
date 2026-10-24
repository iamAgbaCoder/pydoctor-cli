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

Import names are mapped to distributions with the project's own
``importlib.metadata.packages_distributions()``, so packages whose import
name differs from their PyPI name (``decouple`` → ``python-decouple``,
``jwt`` → ``pyjwt``) are matched correctly.

A dependency also counts as used when:
- a string constant in the code names one of its modules
  (Django ``INSTALLED_APPS``, ``MIDDLEWARE``, ``CACHES`` backends, …), or
- it is named in a deploy or run file (Procfile, Dockerfile, compose files,
  Makefile, shell scripts, CI workflows), e.g. ``gunicorn`` or ``uvicorn``.

Limitations
───────────
- Dynamic imports built at runtime (``importlib.import_module(f"...")``)
  are not tracked, so findings are reported as *possibly* unused.
- Standard library modules are excluded automatically.
- Only *declared* dependencies are checked; transitive installs are not.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import Issue
from pydoctor.utils.parser_utils import (
    extract_imports_from_project,
    extract_string_module_refs,
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
                title=f"Possibly unused dependency: {pkg}",
                description=(
                    f"No import, module-path string, or run command referencing '{pkg}' "
                    "was found, and no used package depends on it. Packages loaded "
                    "dynamically or by plugins can still be missed."
                ),
                recommendation=(
                    f"Confirm '{pkg}' is unused, then remove it with your package manager "
                    "(or `pydoctor fix --remove`). If it is used, add it to "
                    "ignored_packages in [tool.pydoctor]."
                ),
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
                title=f"Transitive dependency: {pkg} (required by {parent_str})",
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


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _get_imported_packages(ctx: ProjectContext) -> set[str]:
    names = extract_imports_from_project(ctx.python_files)
    dist_map = _distribution_map(ctx)
    pkgs: set[str] = set()
    for n in names:
        pkgs.add(import_name_to_package(n))
        pkgs.add(n.lower().replace("_", "-"))
        pkgs.update(_norm(d) for d in dist_map.get(n, []))
    # Module paths held in strings only count when they match an installed
    # distribution, so arbitrary strings can't mark random packages as used.
    for n in extract_string_module_refs(ctx.python_files):
        pkgs.update(_norm(d) for d in dist_map.get(n, []))
    pkgs.update(_packages_named_in_run_files(ctx))
    return pkgs


_DIST_MAP_SNIPPET = (
    "import json, importlib.metadata as m; print(json.dumps(m.packages_distributions()))"
)


def _distribution_map(ctx: ProjectContext) -> dict[str, list[str]]:
    """
    Map top-level import names to distribution names in the *project's* environment.

    Runs in the project interpreter, not pydoctor's own, so it is correct even
    when pydoctor is installed with pipx. Returns {} if that fails.
    """
    python = getattr(ctx, "project_python", None) or sys.executable
    try:
        result = subprocess.run(
            [python, "-c", _DIST_MAP_SNIPPET],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                return {k: list(v) for k, v in data.items()}
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return {}


_RUN_FILE_GLOBS = (
    "Procfile",
    "Dockerfile*",
    "*.dockerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
    "Makefile",
    "*.sh",
    "fly.toml",
    "render.yaml",
    "app.yaml",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
)


def _packages_named_in_run_files(ctx: ProjectContext) -> set[str]:
    """Declared dependencies named in deploy/run files (e.g. `gunicorn app.wsgi`)."""
    text_parts: list[str] = []
    for pattern in _RUN_FILE_GLOBS:
        for fpath in ctx.root.glob(pattern):
            if fpath.is_file():
                try:
                    text_parts.append(fpath.read_text(encoding="utf-8", errors="ignore"))
                except OSError:
                    continue
    if not text_parts:
        return set()
    text = "\n".join(text_parts).lower()
    found: set[str] = set()
    for dep in ctx.declared_deps:
        norm = _norm(dep)
        variants = {norm, norm.replace("-", "_")}
        if any(re.search(rf"(?<![\w-]){re.escape(v)}(?![\w-])", text) for v in variants):
            found.add(norm)
    return found


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
        norm = _norm(dep)
        if norm in imported or norm in ignored:
            continue

        if norm in implicit:
            transitive.append((dep, implicit[norm]))
        else:
            unused.append(dep)

    return unused, transitive
