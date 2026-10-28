"""
pydoctor/utils/pip_utils.py
────────────────────────────
Utilities for querying the pip / package ecosystem.

All information that originates from pip (installed packages, outdated list)
is centralised here so that scanners never call subprocess directly.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from pydoctor.utils.subprocess_utils import run_pip_command

# ──────────────────────────────────────────────────────────────
# Installed packages
# ──────────────────────────────────────────────────────────────


def get_installed_packages(python_executable: str | None = None) -> dict[str, str]:
    """
    Return a mapping of {package_name: version} for every package currently
    installed in the active or specified Python environment.

    Returns
    -------
    dict[str, str]
        Lower-cased package names mapped to their installed version strings.
    """
    result = run_pip_command(["list", "--format=json"], python_executable=python_executable)
    if result.returncode != 0:
        return {}

    try:
        packages = json.loads(result.stdout)
        # Normalise names to lowercase and replace underscores/dashes uniformly
        return {_normalise_name(pkg["name"]): pkg["version"] for pkg in packages}
    except (json.JSONDecodeError, KeyError):
        return {}


def get_outdated_packages(python_executable: str | None = None) -> list[dict] | None:
    """
    Return outdated packages as reported by ``pip list --outdated``.

    Returns ``None`` (not an empty list) when pip fails, so callers can tell
    "nothing is outdated" apart from "couldn't check". Raises
    ``subprocess.TimeoutExpired`` on timeout.
    """
    result = run_pip_command(
        ["list", "--outdated", "--format=json"], python_executable=python_executable, timeout=30
    )
    return _parse_outdated(result)


def get_outdated_packages_uv(uv: str, python_executable: str) -> list[dict] | None:
    """Same as ``get_outdated_packages`` for environments without pip, using uv."""
    from pydoctor.utils.subprocess_utils import run_command

    result = run_command(
        [uv, "pip", "list", "--outdated", "--format", "json", "--python", python_executable],
        timeout=60,
    )
    return _parse_outdated(result)


def _parse_outdated(result) -> list[dict] | None:
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, list) else None


# ──────────────────────────────────────────────────────────────
# Requirements file parsing
# ──────────────────────────────────────────────────────────────

# Matches a requirements-style line: package[extra]>=version
_REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\[.*?\])?"  # optional extras: [security]
    r"(?P<spec>[^#\n]*)?"  # version specifier
    r"\s*(?:#.*)?$"  # optional inline comment
)


def parse_requirements_file(req_path: Path) -> dict[str, str]:
    """
    Parse a ``requirements.txt`` file and return package → version-spec mapping.

    Lines that start with ``-r``, ``-c``, ``--``, or ``#`` are ignored.
    Package names are normalised to lowercase.

    Parameters
    ----------
    req_path: Path to the requirements file.

    Returns
    -------
    dict[str, str]
        {package_name: version_specifier}  e.g. {"requests": ">=2.28,<3"}
        Version specifier may be empty string if unpinned.
    """
    deps: dict[str, str] = {}

    try:
        lines = req_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return deps

    for line in lines:
        stripped = line.strip()
        # Skip blank lines, comments, and pip options
        if not stripped or stripped.startswith(("#", "-r", "-c", "--")):
            continue

        m = _REQ_LINE_RE.match(stripped)
        if m:
            name = _normalise_name(m.group("name"))
            spec = (m.group("spec") or "").strip()
            deps[name] = spec

    return deps


# ──────────────────────────────────────────────────────────────
# pip version
# ──────────────────────────────────────────────────────────────


def get_pip_version() -> str | None:
    """
    Return the version string of the currently active pip installation.

    Returns ``None`` if pip cannot be queried.
    """
    result = run_pip_command(["--version"])
    if result.returncode != 0:
        return None

    # Output: "pip 23.x.y from ... (python 3.x)"
    parts = result.stdout.strip().split()
    if len(parts) >= 2:
        return parts[1]
    return None


def update_requirements_file(req_path: Path, package: str, new_spec: str) -> bool:
    """
    Attempt to update a package version in requirements.txt.
    Returns True if updated, False otherwise.
    """
    if not req_path.is_file():
        return False

    try:
        lines = req_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False

    new_lines = []
    updated = False
    norm_pkg = _normalise_name(package)

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-r", "-c", "--")):
            new_lines.append(line)
            continue

        m = _REQ_LINE_RE.match(stripped)
        if m and _normalise_name(m.group("name")) == norm_pkg:
            # We found the line. Construct new line.
            comment = ""
            if "#" in line:
                comment = "  " + line[line.find("#") :]

            new_lines.append(f"{package}{new_spec}{comment}")
            updated = True
        else:
            new_lines.append(line)

    if updated:
        try:
            req_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        except OSError:
            return False

    return updated


def remove_from_requirements_file(req_path: Path, package: str) -> bool:
    """
    Attempt to remove a package from requirements.txt.
    Returns True if removed, False otherwise.
    """
    if not req_path.is_file():
        return False

    try:
        lines = req_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False

    new_lines = []
    updated = False
    norm_pkg = _normalise_name(package)

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-r", "-c", "--")):
            new_lines.append(line)
            continue

        m = _REQ_LINE_RE.match(stripped)
        if m and _normalise_name(m.group("name")) == norm_pkg:
            updated = True
            # Skip it (removal)
        else:
            new_lines.append(line)

    if updated:
        try:
            req_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        except OSError:
            return False

    return updated


def get_dependency_graph(python_executable: str | None = None) -> list[dict]:
    """
    Return the dependency tree of the given (or current) environment.

    pipdeptree is a PyDoctor dependency, so it is installed next to PyDoctor,
    not necessarily in the project. It is run from PyDoctor's interpreter and
    pointed at the project with ``--python``, which also works for
    environments without pip (uv). Returns [] if it can't run.
    """
    import subprocess

    cmd = [sys.executable, "-m", "pipdeptree", "--json-tree"]
    if python_executable and python_executable != sys.executable:
        cmd[3:3] = ["--python", python_executable]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data if isinstance(data, list) else []
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        pass
    return []


# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────


def _normalise_name(name: str) -> str:
    """Normalise a package name to lowercase with underscores→dashes removed."""
    return name.lower().replace("_", "-").replace(".", "-")
