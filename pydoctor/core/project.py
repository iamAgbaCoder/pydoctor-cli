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

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pydoctor.config.settings import PYTHON_EXTENSION, IGNORED_DIRS
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

    # ── Factory method ─────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str | Path) -> "ProjectContext":
        """
        Build a ProjectContext by scanning ``path``.

        This performs:
        1. Python file discovery (respects IGNORED_DIRS)
        2. Installed-packages enumeration via pip internals
        3. requirements.txt / pyproject.toml parsing
        4. Virtual-environment detection
        5. Dependency tree collection
        6. System platform discovery

        Parameters
        ----------
        path: str | Path
            The project directory to scan.

        Returns
        -------
        ProjectContext
        """
        root = Path(path).resolve()

        # Discover all .py files under the project (skipping venv, dist, etc.)
        python_files = collect_python_files(root)

        # Enumerate packages currently installed in the active Python env
        installed = get_installed_packages()

        # Parse requirements.txt if it exists
        declared: dict[str, str] = {}
        req_file = root / "requirements.txt"
        if req_file.is_file():
            declared = parse_requirements_file(req_file)

        # Detect virtual environment:
        # sys.prefix != sys.base_prefix  →  in a venv
        # Also check for VIRTUAL_ENV env var as a fallback
        import os
        import platform
        from pydoctor.utils.pip_utils import get_dependency_graph

        in_venv = (sys.prefix != sys.base_prefix) or bool(os.environ.get("VIRTUAL_ENV"))
        graph = get_dependency_graph()

        # Load configuration from pyproject.toml
        config = {}
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            try:
                if sys.version_info >= (3, 11):
                    import tomllib

                    with pyproject.open("rb") as f:
                        data = tomllib.load(f)
                else:
                    import tomli

                    with pyproject.open("rb") as f:
                        data = tomli.load(f)
                config = data.get("tool", {}).get("pydoctor", {})
            except Exception:
                pass  # Fallback to empty config if parsing fails

        return cls(
            root=root,
            python_files=python_files,
            installed_packages=installed,
            declared_deps=declared,
            in_virtualenv=in_venv,
            dependency_graph=graph,
            platform_info=platform.platform(),
            os_name=platform.system(),
            config=config,
        )
