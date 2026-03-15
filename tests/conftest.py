"""
tests/conftest.py
──────────────────
Shared pytest fixtures and helpers.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make sure the project root is on sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pydoctor.config.settings import Severity  # noqa: E402
from pydoctor.core.project import ProjectContext  # noqa: E402
from pydoctor.core.report import DiagnosisReport, Issue  # noqa: E402

# ── Fixtures ───────────────────────────────────────────────────


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """
    Create a minimal temporary Python project directory.

    Structure:
        tmp_project/
            main.py          (imports flask, requests)
            requirements.txt (flask, requests, pandas)
    """
    main_py = tmp_path / "main.py"
    main_py.write_text(
        "import flask\nimport requests\nfrom os import path\n",
        encoding="utf-8",
    )
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("flask\nrequests\npandas\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def empty_project(tmp_path: Path) -> Path:
    """A project directory with no Python files and no requirements."""
    return tmp_path


@pytest.fixture
def mock_installed_packages() -> dict[str, str]:
    """A small realistic installed-packages dict for testing."""
    return {
        "flask": "2.3.0",
        "requests": "2.28.0",
        "pandas": "1.5.0",
        "pip": "23.0.0",
    }


@pytest.fixture
def basic_ctx(tmp_project: Path, mock_installed_packages: dict) -> ProjectContext:
    """
    A ProjectContext built around the tmp_project fixture with
    mock installed packages (avoids real pip calls in unit tests).
    """
    ctx = ProjectContext.from_path(tmp_project)
    ctx.installed_packages = mock_installed_packages
    return ctx


@pytest.fixture
def empty_report() -> DiagnosisReport:
    """An empty DiagnosisReport."""
    return DiagnosisReport()


@pytest.fixture
def sample_issue() -> Issue:
    """A sample WARNING issue for use in display tests."""
    return Issue(
        category="test",
        code="TEST_ISSUE",
        severity=Severity.WARNING,
        title="Test warning",
        description="This is a test warning issue.",
        recommendation="Fix it by doing X.",
        package="test-pkg",
    )
