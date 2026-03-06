"""
tests/test_dependency_scanner.py
───────────────────────────────────
Unit tests for the dependency conflict scanner.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from pydoctor.config.settings import Severity
from pydoctor.scanners import dependency_scanner


class TestDependencyScanner:
    def test_no_conflicts(self, basic_ctx):
        with patch("pydoctor.scanners.dependency_scanner.run_pip_command") as m_run:
            m_run.return_value = subprocess.CompletedProcess(
                args=["pip", "check"],
                returncode=0,
                stdout="No broken requirements found.",
                stderr="",
            )

            issues = dependency_scanner.scan(basic_ctx)
            assert len(issues) == 1
            assert issues[0].code == "DEP_NO_CONFLICTS"
            assert issues[0].severity == Severity.OK

    def test_version_conflict(self, basic_ctx):
        with patch("pydoctor.scanners.dependency_scanner.run_pip_command") as m_run:
            m_run.return_value = subprocess.CompletedProcess(
                args=["pip", "check"],
                returncode=1,
                stdout="pydantic 1.10.8 requires typing-extensions>=4.2.0, but 3.10.0 is installed.",
                stderr="",
            )

            issues = dependency_scanner.scan(basic_ctx)
            assert len(issues) == 1
            issue = issues[0]
            assert issue.code == "DEP_VERSION_CONFLICT"
            assert issue.severity == Severity.ERROR
            assert issue.package == "pydantic"
            assert "typing-extensions>=4.2.0" in issue.extra["required_spec"]
            assert "3.10.0" in issue.extra["conflicting_ver"]

    def test_missing_dependency(self, basic_ctx):
        with patch("pydoctor.scanners.dependency_scanner.run_pip_command") as m_run:
            m_run.return_value = subprocess.CompletedProcess(
                args=["pip", "check"],
                returncode=1,
                stdout="flask 2.3.0 requires werkzeug which is not installed.",
                stderr="",
            )

            issues = dependency_scanner.scan(basic_ctx)
            assert len(issues) == 1
            issue = issues[0]
            assert issue.code == "DEP_MISSING"
            assert issue.severity == Severity.ERROR
            assert issue.package == "flask"
            assert issue.extra["missing_package"] == "werkzeug"

    def test_unrecognized_output_generic_conflict(self, basic_ctx):
        with patch("pydoctor.scanners.dependency_scanner.run_pip_command") as m_run:
            m_run.return_value = subprocess.CompletedProcess(
                args=["pip", "check"],
                returncode=1,
                stdout="Some bizarre pip check failure message here.",
                stderr="",
            )

            issues = dependency_scanner.scan(basic_ctx)
            assert len(issues) == 1
            issue = issues[0]
            assert issue.code == "DEP_CONFLICT"
            assert issue.severity == Severity.ERROR
            assert issue.description == "Some bizarre pip check failure message here."
