"""
pydoctor/utils/parser_utils.py
──────────────────────────────
AST-based import extraction utilities.

Used by the unused-package scanner to determine which packages are
actually imported somewhere in the project source.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from pydoctor.utils.file_utils import read_file_safe

# ──────────────────────────────────────────────────────────────
# Top-level import extractor
# ──────────────────────────────────────────────────────────────


def extract_imports_from_file(path: Path) -> set[str]:
    """
    Parse a single Python source file and return the set of top-level module
    names that it imports.

    Handles:
    - ``import foo``              → "foo"
    - ``import foo.bar``          → "foo"
    - ``from foo import bar``     → "foo"
    - ``from foo.bar import baz`` → "foo"

    Parameters
    ----------
    path: Path to a .py file.

    Returns
    -------
    set[str]
        Top-level module names referenced by import statements.
        Returns an empty set if the file cannot be read or parsed.
    """
    source = read_file_safe(path)
    if source is None:
        return set()

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        # Broken file — skip silently
        return set()

    return _walk_imports(tree)


def extract_imports_from_project(python_files: list[Path]) -> set[str]:
    """
    Aggregate imported module names from all Python files in a project.

    Parameters
    ----------
    python_files: List of .py file paths.

    Returns
    -------
    set[str]
        Union of all top-level module names referenced across files.
    """
    all_imports: set[str] = set()
    for fpath in python_files:
        all_imports.update(extract_imports_from_file(fpath))
    return all_imports


_MODULE_STRING = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


def extract_string_constants(python_files: list[Path], max_len: int = 200) -> set[str]:
    """All short string constants in the project's Python files (stripped)."""
    values: set[str] = set()
    for fpath in python_files:
        source = read_file_safe(fpath)
        if source is None:
            continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.strip()
                if 0 < len(value) <= max_len:
                    values.add(value)
    return values


def module_refs_from_strings(strings: set[str]) -> set[str]:
    """
    Top-level names from strings that look like module paths.

    Frameworks load many dependencies by name rather than by ``import``:
    Django's ``INSTALLED_APPS = ["corsheaders"]``, ``MIDDLEWARE = ["whitenoise.middleware..."]``
    and ``"BACKEND": "django_redis.cache.RedisCache"`` are all plain strings.
    Callers should only treat a returned name as a dependency reference when it
    matches the import name of an installed distribution.
    """
    return {v.split(".", 1)[0] for v in strings if _MODULE_STRING.match(v)}


def extract_string_module_refs(python_files: list[Path]) -> set[str]:
    """Backwards-compatible wrapper: module refs found in ``python_files``."""
    return module_refs_from_strings(extract_string_constants(python_files))


# ──────────────────────────────────────────────────────────────
# AST walking
# ──────────────────────────────────────────────────────────────


def _walk_imports(tree: ast.AST) -> set[str]:
    """
    Walk an AST tree and extract all top-level imported module names.

    Parameters
    ----------
    tree: Parsed AST module node.

    Returns
    -------
    set[str]
    """
    names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # ``import foo, foo.bar`` → {"foo"}
            for alias in node.names:
                top = alias.name.split(".")[0]
                names.add(top)

        elif isinstance(node, ast.ImportFrom):
            # ``from foo.bar import baz`` → {"foo"}
            # Relative imports (level > 0) have no module or a relative one
            if node.module:
                top = node.module.split(".")[0]
                names.add(top)

    return names


# ──────────────────────────────────────────────────────────────
# Package name normalisation helpers
# ──────────────────────────────────────────────────────────────

# Mapping from common import name → PyPI distribution name.
# E.g. ``import cv2`` → package "opencv-python".
IMPORT_TO_PACKAGE: dict[str, str] = {
    "cv2": "opencv-python",
    "PIL": "pillow",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "yaml": "pyyaml",
    "dotenv": "python-dotenv",
    "dateutil": "python-dateutil",
    "usaddress": "usaddress",
    "magic": "python-magic",
    "jwt": "pyjwt",
    "Crypto": "pycryptodome",
    "git": "gitpython",
    "attr": "attrs",
    "wx": "wxpython",
    "gi": "pygobject",
    "serial": "pyserial",
    "pkg_resources": "setuptools",
}


def import_name_to_package(import_name: str) -> str:
    """
    Convert a Python import name to its likely PyPI package name.

    Uses the known mapping table first, then falls back to normalising
    the import name (lowercase, replace underscores with dashes).

    Parameters
    ----------
    import_name: str
        The name used in an import statement (e.g. ``"PIL"``).

    Returns
    -------
    str
        The probable PyPI distribution name (e.g. ``"pillow"``).
    """
    if import_name in IMPORT_TO_PACKAGE:
        return IMPORT_TO_PACKAGE[import_name]
    return import_name.lower().replace("_", "-")
