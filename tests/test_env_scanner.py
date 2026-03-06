"""
tests/test_env_scanner.py
──────────────────────────
Unit tests for the environment scanner.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.scanners import env_scanner


# ── Helpers ────────────────────────────────────────────────────


def _make_ctx(tmp_path: Path, in_venv: bool = True) -> ProjectContext:
    ctx = ProjectContext(
        root=tmp_path,
        python_version=(
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        ),
        in_virtualenv=in_venv,
        installed_packages={},
        declared_deps={},
    )
    return ctx


# ── Tests ──────────────────────────────────────────────────────


class TestPythonVersionCheck:
    def test_current_version_passes(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        issues = env_scanner.scan(ctx)
        py_issues = [i for i in issues if "python" in i.code.lower()]
        # Should be OK or WARNING, never ERROR for the running interpreter
        assert any(
            i.severity in (Severity.OK, Severity.WARNING, Severity.INFO)
            for i in py_issues
        )

    def test_old_python_gives_error(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.python_version = (2, 7, 18)

        issues = env_scanner._check_python_version(ctx)
        assert any(i.code == "ENV_PYTHON_TOO_OLD" for i in issues)
        assert any(i.severity == Severity.ERROR for i in issues)

    def test_python_38_gives_warning(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.python_version = (3, 8, 0)

        issues = env_scanner._check_python_version(ctx)
        outdated = [i for i in issues if i.code == "ENV_PYTHON_OUTDATED"]
        assert outdated, "Expected a warning for Python 3.8"
        assert outdated[0].severity == Severity.WARNING

    def test_python_311_ok(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.python_version = (3, 11, 0)

        issues = env_scanner._check_python_version(ctx)
        assert any(i.code == "ENV_PYTHON_OK" for i in issues)


class TestVirtualEnvCheck:
    def test_in_venv_ok(self, tmp_path):
        ctx = _make_ctx(tmp_path, in_venv=True)
        issues = env_scanner._check_virtual_environment(ctx)
        assert issues[0].code == "ENV_VENV_OK"
        assert issues[0].severity == Severity.OK

    def test_no_venv_warning(self, tmp_path):
        ctx = _make_ctx(tmp_path, in_venv=False)
        issues = env_scanner._check_virtual_environment(ctx)
        assert issues[0].code == "ENV_NO_VENV"
        assert issues[0].severity == Severity.WARNING


class TestPipVersionCheck:
    def test_pip_missing(self):
        with patch("pydoctor.scanners.env_scanner.get_pip_version", return_value=None):
            issues = env_scanner._check_pip_version()
        assert any(i.code == "ENV_PIP_MISSING" for i in issues)

    def test_pip_outdated(self):
        with patch(
            "pydoctor.scanners.env_scanner.get_pip_version", return_value="20.0.0"
        ):
            issues = env_scanner._check_pip_version()
        assert any(i.code == "ENV_PIP_OUTDATED" for i in issues)

    def test_pip_ok(self):
        with patch(
            "pydoctor.scanners.env_scanner.get_pip_version", return_value="23.1.0"
        ):
            issues = env_scanner._check_pip_version()
        assert any(i.code == "ENV_PIP_OK" for i in issues)
