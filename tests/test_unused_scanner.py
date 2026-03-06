"""
tests/test_unused_scanner.py
──────────────────────────────
Unit tests for the unused package scanner (AST-based).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.scanners import unused_package_scanner


def _make_ctx(
    tmp_path: Path,
    py_files: list[tuple[str, str]] | None = None,
    declared: dict[str, str] | None = None,
) -> ProjectContext:
    """
    Build a ProjectContext with specific py files and declared deps.

    py_files: list of (filename, content) tuples to write to tmp_path.
    declared: dict of declared package names.
    """
    python_files: list[Path] = []

    if py_files:
        for name, content in py_files:
            fpath = tmp_path / name
            fpath.write_text(content, encoding="utf-8")
            python_files.append(fpath)

    return ProjectContext(
        root=tmp_path,
        python_files=python_files,
        installed_packages={},
        declared_deps=declared or {},
    )


class TestUnusedPackageScanner:
    def test_detects_unused_package(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import flask\nimport requests\n")],
            declared={"flask": "", "requests": "", "pandas": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        unused = [i for i in issues if i.code == "UNUSED_PACKAGE"]
        pkg_names = [i.package for i in unused]
        assert "pandas" in pkg_names

    def test_no_unused_when_all_imported(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import flask\nimport requests\n")],
            declared={"flask": "", "requests": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        assert any(i.code == "UNUSED_NONE_FOUND" for i in issues)

    def test_no_requirements_raises_info(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import flask\n")],
            declared={},  # empty → no requirements.txt
        )
        issues = unused_package_scanner.scan(ctx)
        assert any(i.code == "UNUSED_NO_DEPS_FILE" for i in issues)

    def test_no_python_files_info(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[],  # no files
            declared={"flask": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        assert any(i.code == "UNUSED_NO_PY_FILES" for i in issues)

    def test_stdlib_not_flagged_as_unused(self, tmp_path):
        """os, sys should never appear as unused packages."""
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import os\nimport sys\n")],
            declared={"os": "", "sys": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        unused = [i for i in issues if i.code == "UNUSED_PACKAGE"]
        pkg_names = [i.package for i in unused]
        # stdlib modules should be excluded
        assert "os" not in pkg_names
        assert "sys" not in pkg_names

    def test_from_import_detected(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "from flask import Flask\n")],
            declared={"flask": "", "requests": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        unused = [i for i in issues if i.code == "UNUSED_PACKAGE"]
        pkg_names = [i.package for i in unused]
        # flask is imported via from-import, requests is not
        assert "requests" in pkg_names
        assert "flask" not in pkg_names
