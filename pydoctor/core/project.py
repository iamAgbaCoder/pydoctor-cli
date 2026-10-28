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
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydoctor.utils.file_utils import collect_python_files
from pydoctor.utils.pip_utils import parse_requirements_file


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
    python_executable:  Path to the project's Python interpreter (the one scanned).
    python_version:     (major, minor, micro) tuple of that interpreter.
    in_virtualenv:      Whether that interpreter belongs to a virtual environment.
    python_source:      How the interpreter was chosen (shown to the user).
    pip_version:        pip version inside the project environment, or None.
    env_error:          Why the environment could not be read, or None.
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
    venv_name: str | None = None
    venv_path: str | None = None
    git_repo: str | None = None
    git_branch: str | None = None
    git_origin: str | None = None
    python_source: str = ""
    pip_version: str | None = None
    env_error: str | None = None
    distributions: dict[str, dict] = field(default_factory=dict)
    marker_env: dict[str, str] = field(default_factory=dict)

    # ── Factory method ─────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str | Path, python: str | None = None) -> ProjectContext:
        """
        Build a ProjectContext by scanning ``path``.

        ``python`` (or the ``PYDOCTOR_PYTHON`` environment variable) forces the
        interpreter to scan. Otherwise it is discovered; see
        ``_find_project_python``. Every fact about the environment comes from
        that interpreter, never from the one PyDoctor itself is running on.
        """
        import platform

        from pydoctor.utils.env_probe import probe_environment
        from pydoctor.utils.pip_utils import get_dependency_graph

        root = Path(path).resolve()
        python_files = collect_python_files(root)

        declared = cls._parse_dependencies(root)
        meta = cls._extract_pyproject_metadata(root)

        project_py, source = cls._find_project_python(
            root, meta, python or os.environ.get("PYDOCTOR_PYTHON")
        )
        probe, env_error = probe_environment(project_py)

        venv_path = None
        venv_name = None
        if probe and probe.in_virtualenv:
            venv_path = probe.prefix
            venv_name = Path(probe.prefix).name

        git_info = cls._get_git_info(root)

        return cls(
            root=root,
            python_files=python_files,
            installed_packages=probe.packages if probe else {},
            declared_deps=declared,
            python_executable=probe.executable if probe else project_py,
            python_version=probe.version if probe else (0, 0, 0),
            in_virtualenv=probe.in_virtualenv if probe else False,
            dependency_graph=get_dependency_graph(python_executable=project_py) if probe else [],
            platform_info=platform.platform(),
            os_name=platform.system(),
            config=meta.get("config", {}),
            is_poetry=meta.get("is_poetry", False),
            is_uv=meta.get("is_uv", False),
            is_pdm=meta.get("is_pdm", False),
            project_python=project_py,
            venv_name=venv_name,
            venv_path=venv_path,
            git_repo=git_info.get("repo"),
            git_branch=git_info.get("branch"),
            git_origin=git_info.get("origin"),
            python_source=source,
            pip_version=probe.pip_version if probe else None,
            env_error=env_error,
            distributions=probe.distributions if probe else {},
            marker_env=probe.markers if probe else {},
        )

    @classmethod
    def _find_project_python(
        cls, root: Path, meta: dict, explicit: str | None = None
    ) -> tuple[str, str]:
        """
        Choose the interpreter to scan and say why.

        Order: explicit ``--python`` / ``PYDOCTOR_PYTHON``, the active
        virtualenv, a virtualenv in the project (or its parent), Poetry/PDM,
        then ``python3`` on PATH. PyDoctor's own interpreter is the last
        resort, because under pipx or ``uv tool`` it only contains PyDoctor's
        dependencies.
        """
        if explicit:
            resolved = shutil.which(explicit) or explicit
            return resolved, "--python option"

        venv = cls._find_venv_python(root)
        if venv:
            return venv

        mgr_py = cls._find_manager_python(root, meta)
        if mgr_py:
            return mgr_py, "Poetry environment" if meta.get("is_poetry") else "PDM environment"

        for name in ("python3", "python"):
            found = shutil.which(name)
            if found:
                return found, f"`{name}` on PATH (no project virtualenv found)"

        return sys.executable, "PyDoctor's own interpreter (no other Python found)"

    @staticmethod
    def _venv_python(base: Path) -> Path:
        return base / "Scripts" / "python.exe" if os.name == "nt" else base / "bin" / "python"

    @classmethod
    def _find_venv_python(cls, root: Path) -> tuple[str, str] | None:
        """Find a virtualenv for the project and describe where it came from."""
        active_venv = os.environ.get("VIRTUAL_ENV")
        if active_venv:
            py = cls._venv_python(Path(active_venv))
            if py.exists():
                return str(py), f"active virtualenv ({active_venv})"

        venv_names = [".venv", "venv", "env", ".env"]
        for venv_dir in venv_names:
            py = cls._venv_python(root / venv_dir)
            if py.exists():
                return str(py), f"{venv_dir}/ in the project"

        found = cls._find_pyvenv_cfg_dir(root)
        if found:
            return found

        # Monorepos often keep one .venv at the repository root. Only the
        # conventional names are considered, and the source says so.
        for venv_dir in (".venv", "venv"):
            py = cls._venv_python(root.parent / venv_dir)
            if py.exists():
                return str(py), f"{venv_dir}/ in the parent directory ({root.parent})"

        return None

    @classmethod
    def _find_pyvenv_cfg_dir(cls, root: Path) -> tuple[str, str] | None:
        """Any directory in the project root that contains pyvenv.cfg."""
        try:
            for entry in sorted(root.iterdir()):
                if entry.is_dir() and (entry / "pyvenv.cfg").exists():
                    py = cls._venv_python(entry)
                    if py.exists():
                        return str(py), f"{entry.name}/ in the project"
        except OSError:
            pass
        return None

    @staticmethod
    def _get_git_info(root: Path) -> dict[str, str | None]:
        """Collect git repository information."""
        import subprocess

        info: dict[str, str | None] = {"repo": None, "branch": None, "origin": None}
        try:
            # Check if it's a git repo
            res = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                return info

            # Get real repo root name
            res = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                repo_root = Path(res.stdout.strip())
                info["repo"] = repo_root.name
            else:
                info["repo"] = root.name

            # Get branch
            res = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                info["branch"] = res.stdout.strip()

            # Get origin URL
            res = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                info["origin"] = res.stdout.strip()

        except Exception:
            pass
        return info

    @staticmethod
    def _find_manager_python(root: Path, meta: dict) -> str | None:
        """Search for interpreters managed by Poetry, PDM, etc."""
        import subprocess

        try:
            if meta.get("is_poetry"):
                res = subprocess.run(
                    ["poetry", "env", "info", "-p"],
                    capture_output=True,
                    text=True,
                    cwd=root,
                    check=False,
                )
                if res.returncode == 0:
                    base = Path(res.stdout.strip())
                    py = (
                        base / "bin" / "python"
                        if os.name != "nt"
                        else base / "Scripts" / "python.exe"
                    )
                    if py.exists():
                        return str(py)

            if meta.get("is_pdm"):
                res = subprocess.run(
                    ["pdm", "info", "--python"],
                    capture_output=True,
                    text=True,
                    cwd=root,
                    check=False,
                )
                if res.returncode == 0:
                    return res.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return None

    @staticmethod
    def _parse_dependencies(root: Path) -> dict[str, str]:  # noqa: C901
        """Parse declared dependencies from various sources, searching beyond just the root."""
        declared: dict[str, str] = {}

        # 1. Gather all potential requirements files
        # We check root first, then common subdirs, then a shallow recursive search
        potential_reqs = [root / "requirements.txt"]

        # Common patterns
        for subdir in ["requirements", "reqs", "config", "deploy", "docker", "app"]:
            potential_reqs.append(root / subdir / "requirements.txt")
            potential_reqs.append(root / subdir / "base.txt")
            potential_reqs.append(root / subdir / "prod.txt")

        # Use a set to avoid duplicates and check existence
        seen_files = set()
        for req_file in potential_reqs:
            if req_file.is_file() and req_file not in seen_files:
                declared.update(parse_requirements_file(req_file))
                seen_files.add(req_file)

        # 2. Try pyproject.toml (usually root, but check config/ too)
        pyprojects = [root / "pyproject.toml", root / "config" / "pyproject.toml"]
        for pyproject in pyprojects:
            if not pyproject.is_file():
                continue

            try:
                with pyproject.open("rb") as f:
                    if sys.version_info >= (3, 11):
                        import tomllib

                        data = tomllib.load(f)
                    else:
                        import tomli

                        data = tomli.load(f)

                project_info = data.get("project", {})
                # Core dependencies
                for d in project_info.get("dependencies", []):
                    name_match = re.match(r"^([A-Za-z0-9_.\-]+)", d)
                    if name_match:
                        declared[name_match.group(1).lower().replace("_", "-")] = d

                # Optional/Extra dependencies
                for group in project_info.get("optional-dependencies", {}).values():
                    for d in group:
                        name_match = re.match(r"^([A-Za-z0-9_.\-]+)", d)
                        if name_match:
                            declared[name_match.group(1).lower().replace("_", "-")] = d

                # Poetry specific
                poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                for name, spec in poetry_deps.items():
                    if name.lower() != "python":
                        declared[name.lower().replace("_", "-")] = f"{name} {spec}"
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
