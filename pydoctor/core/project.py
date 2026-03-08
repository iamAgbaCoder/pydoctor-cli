"""
pydoctor/core/project.py
────────────────────────
Project context model.

When PyDoctor starts scanning it collects basic facts about the project
(location, Python files, declared dependencies) into a ``ProjectContext``
object.  All scanners receive this object so they work against a
consistent snapshot rather than discovering the same information
independently.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydoctor.utils.file_utils import collect_python_files
from pydoctor.utils.pip_utils import get_installed_packages, parse_requirements_file


@dataclass
class ProjectContext:
    """
    Snapshot of the project being diagnosed.

    Attributes
    ----------
    root:               Absolute path to the project root.
    python_files:       All .py files found under ``root`` (excluding ignored dirs).
    installed_packages: Mapping of package_name → installed_version.
    declared_deps:      Packages listed in requirements.txt / pyproject.toml.
    python_executable:  Path to the Python interpreter being used.
    python_version:     (major, minor, micro) tuple of that interpreter.
    in_virtualenv:      Whether we're running inside a virtual environment.
    """

    root: Path
    python_files: list[Path] = field(default_factory=list)
    installed_packages: dict[str, str] = field(default_factory=dict)  # name → version
    declared_deps: dict[str, str] = field(default_factory=dict)  # name → version_spec
    python_executable: str = sys.executable
    python_version: tuple[int, int, int] = field(
        default_factory=lambda: (
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        )
    )
    in_virtualenv: bool = False
    dependency_graph: list[dict] = field(default_factory=list)
    platform_info: str = ""
    os_name: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    is_poetry: bool = False
    is_uv: bool = False
    is_pdm: bool = False
    project_python: str = sys.executable

    # ── Factory method ─────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str | Path) -> ProjectContext:
        """Build a ProjectContext by scanning ``path``."""
        root = Path(path).resolve()
        python_files = collect_python_files(root)

        declared = cls._parse_dependencies(root)
        meta = cls._extract_pyproject_metadata(root)

        # Detect virtual environment and project python
        import os
        import platform

        project_py = cls._find_project_python(root, meta)
        from pydoctor.utils.pip_utils import get_dependency_graph, get_installed_packages

        installed = get_installed_packages(python_executable=project_py)
        in_venv = (project_py != sys.base_prefix) or bool(os.environ.get("VIRTUAL_ENV"))
        graph = get_dependency_graph(python_executable=project_py)

        return cls(
            root=root,
            python_files=python_files,
            installed_packages=installed,
            declared_deps=declared,
            in_virtualenv=in_venv,
            dependency_graph=graph,
            platform_info=platform.platform(),
            os_name=platform.system(),
            config=meta.get("config", {}),
            is_poetry=meta.get("is_poetry", False),
            is_uv=meta.get("is_uv", False),
            is_pdm=meta.get("is_pdm", False),
            project_python=project_py,
        )

    @classmethod
    def _find_project_python(cls, root: Path, meta: dict) -> str:
        """Find the Python interpreter for the project."""
        import subprocess

        # 1. Check for common venv names
        for venv_dir in [".venv", "venv", ".env", "env"]:
            if os.name == "nt":
                py_path = root / venv_dir / "Scripts" / "python.exe"
            else:
                py_path = root / venv_dir / "bin" / "python"

            if py_path.exists():
                return str(py_path)

        # 2. Check package managers
        try:
            if meta.get("is_poetry"):
                result = subprocess.run(
                    ["poetry", "env", "info", "-p"],
                    capture_output=True,
                    text=True,
                    cwd=root,
                    check=False,
                )
                if result.returncode == 0:
                    base = Path(result.stdout.strip())
                    py = (
                        base / "bin" / "python"
                        if os.name != "nt"
                        else base / "Scripts" / "python.exe"
                    )
                    if py.exists():
                        return str(py)

            if meta.get("is_uv"):
                # uv typically uses .venv, already checked, but fallback
                pass

            if meta.get("is_pdm"):
                result = subprocess.run(
                    ["pdm", "info", "--where"],
                    capture_output=True,
                    text=True,
                    cwd=root,
                    check=False,
                )
                if result.returncode == 0:
                    # Actually pdm info has a python path
                    result_py = subprocess.run(
                        ["pdm", "info", "--python"],
                        capture_output=True,
                        text=True,
                        cwd=root,
                        check=False,
                    )
                    if result_py.returncode == 0:
                        return result_py.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # 3. Fallback to current interpreter
        return sys.executable

    @staticmethod
    def _parse_dependencies(root: Path) -> dict[str, str]:
        """Parse declared dependencies from various sources."""
        declared: dict[str, str] = {}

        # 1. Try requirements.txt
        req_file = root / "requirements.txt"
        if req_file.is_file():
            declared.update(parse_requirements_file(req_file))

        # 2. Try pyproject.toml
        pyproject = root / "pyproject.toml"
        if not pyproject.is_file():
            return declared

        try:
            with pyproject.open("rb") as f:
                if sys.version_info >= (3, 11):
                    import tomllib

                    data = tomllib.load(f)
                else:
                    import tomli

                    data = tomli.load(f)

            project_info = data.get("project", {})
            for d in project_info.get("dependencies", []):
                name_match = re.match(r"^([A-Za-z0-9_.\-]+)", d)
                if name_match:
                    declared[name_match.group(1).lower().replace("_", "-")] = d

            for group in project_info.get("optional-dependencies", {}).values():
                for d in group:
                    name_match = re.match(r"^([A-Za-z0-9_.\-]+)", d)
                    if name_match:
                        declared[name_match.group(1).lower().replace("_", "-")] = d
        except Exception:
            pass
        return declared

    @staticmethod
    def _extract_pyproject_metadata(root: Path) -> dict:
        """Extract config and tool detection info from pyproject.toml."""
        ret = {"config": {}, "is_poetry": False, "is_pdm": False, "is_uv": False}
        pyproject = root / "pyproject.toml"
        if not pyproject.is_file():
            return ret

        try:
            with pyproject.open("rb") as f:
                if sys.version_info >= (3, 11):
                    import tomllib

                    data = tomllib.load(f)
                else:
                    import tomli

                    data = tomli.load(f)
            ret["config"] = data.get("tool", {}).get("pydoctor", {})
            ret["is_poetry"] = "poetry" in data.get("tool", {})
            ret["is_pdm"] = "pdm" in data.get("tool", {})
            ret["is_uv"] = "uv" in data.get("tool", {}) or (root / "uv.lock").exists()
        except Exception:
            pass
        return ret
