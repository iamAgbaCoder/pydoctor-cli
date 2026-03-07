"""
pydoctor/utils/file_utils.py
──────────────────────────────
File-system helpers for project tree traversal.

Responsible for:
  • Discovering .py files beneath a project root
  • Skipping ignored directories (virtual environments, __pycache__, etc.)
  • Computing relative paths for display
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from pydoctor.config.settings import IGNORED_DIRS, PYTHON_EXTENSION


def collect_python_files(root: Path) -> list[Path]:
    """
    Recursively collect all Python source files under ``root``.

    Directories listed in ``IGNORED_DIRS`` are pruned entirely so we
    never descend into virtualenvs or build artefacts.

    Parameters
    ----------
    root: Path
        Directory to scan.

    Returns
    -------
    list[Path]
        Absolute paths to every ``.py`` file found.
    """
    return list(_iter_python_files(root))


def _iter_python_files(root: Path) -> Generator[Path, None, None]:
    """
    Yield .py files under ``root`` while skipping ignored directories.

    This uses ``os.scandir`` via ``Path.iterdir()`` for efficiency and
    avoids building a complete tree in memory before pruning.
    """
    try:
        entries = list(root.iterdir())
    except PermissionError:
        return

    for entry in entries:
        # Skip ignored directory names
        if entry.is_dir():
            if _should_skip_dir(entry):
                continue
            yield from _iter_python_files(entry)
        elif entry.is_file() and entry.suffix == PYTHON_EXTENSION:
            yield entry


def _should_skip_dir(path: Path) -> bool:
    """
    Return True if the directory should be excluded from scanning.

    We check both exact name matches and glob-style patterns (e.g. ``*.egg-info``).
    """
    name = path.name

    for pattern in IGNORED_DIRS:
        if "*" in pattern:
            # Treat as suffix/prefix glob
            if path.match(pattern):
                return True
        else:
            if name == pattern:
                return True
    return False


def read_file_safe(path: Path, encoding: str = "utf-8") -> str | None:
    """
    Read a file and return its contents, or ``None`` if it cannot be read.

    Never raises; errors (permission denied, encoding errors) are swallowed
    so that a single unreadable file doesn't abort the entire scan.

    Parameters
    ----------
    path:     File to read.
    encoding: Text encoding (default UTF-8 with error replacement).

    Returns
    -------
    str | None
    """
    try:
        return path.read_text(encoding=encoding, errors="replace")
    except (OSError, PermissionError):
        return None
