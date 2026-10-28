"""
tests/test_environment.py
─────────────────────────
The scanned environment must be the project's, and a scan that can't read
it must say so instead of reporting a clean result.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from pydoctor.config.settings import Severity
from pydoctor.core.analyzer import Analyzer, context_issues
from pydoctor.core.project import ProjectContext
from pydoctor.scanners import dependency_scanner, outdated_package_scanner
from pydoctor.utils.env_probe import probe_environment

# ── Probe ──────────────────────────────────────────────────────


def test_probe_reads_the_target_interpreter():
    probe, error = probe_environment(sys.executable)
    assert error is None and probe is not None
    assert probe.version == tuple(sys.version_info[:3])
    assert "pytest" in probe.packages
    assert probe.markers["python_version"] == f"{sys.version_info[0]}.{sys.version_info[1]}"


def test_probe_reports_virtualenv_from_the_target_not_from_pydoctor():
    # The test suite runs inside a virtualenv; its base interpreter is not one.
    base = getattr(sys, "_base_executable", None)
    if sys.prefix == sys.base_prefix or not base or not Path(base).exists():
        pytest.skip("needs to run inside a virtualenv")
    venv_probe, _ = probe_environment(sys.executable)
    base_probe, _ = probe_environment(base)
    assert venv_probe is not None and venv_probe.in_virtualenv is True
    assert base_probe is not None and base_probe.in_virtualenv is False


def test_probe_failure_is_reported_not_swallowed():
    probe, error = probe_environment("/definitely/not/python")
    assert probe is None
    assert "not found" in error


def test_probe_ignores_project_files_that_shadow_the_stdlib(tmp_path, monkeypatch):
    (tmp_path / "json.py").write_text("raise SystemExit('shadowed')\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    probe, error = probe_environment(sys.executable)
    assert error is None and probe is not None


# ── Interpreter discovery ──────────────────────────────────────


def _fake_venv(base: Path) -> Path:
    py = base / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    py.parent.mkdir(parents=True)
    py.write_text("", encoding="utf-8")
    return py


def test_explicit_python_wins(tmp_path):
    _fake_venv(tmp_path / ".venv")
    py, source = ProjectContext._find_project_python(tmp_path, {}, explicit=sys.executable)
    assert py == sys.executable and source == "--python option"


def test_project_venv_is_found_and_labelled(tmp_path, monkeypatch):
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    expected = _fake_venv(tmp_path / ".venv")
    py, source = ProjectContext._find_project_python(tmp_path, {})
    assert py == str(expected)
    assert source == ".venv/ in the project"


def test_parent_venv_is_labelled_as_parent(tmp_path, monkeypatch):
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    _fake_venv(tmp_path / ".venv")
    (tmp_path / "backend").mkdir()
    _, source = ProjectContext._find_project_python(tmp_path / "backend", {})
    assert "parent directory" in source


def test_sibling_folders_named_like_venvs_are_not_used(tmp_path, monkeypatch):
    """2.1.0 accepted ../test, ../dev, ../prod etc. from the parent directory."""
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    _fake_venv(tmp_path / "test")
    (tmp_path / "web").mkdir()
    with patch("shutil.which", return_value="/usr/bin/python3"):
        py, source = ProjectContext._find_project_python(tmp_path / "web", {})
    assert py == "/usr/bin/python3"
    assert "PATH" in source


# ── Failing loudly ─────────────────────────────────────────────


def test_unreadable_environment_fails_the_scan(tmp_project):
    report = Analyzer(project_path=str(tmp_project), python="/definitely/not/python").run()
    codes = [i.code for i in report.issues]
    assert "ENV_PACKAGES_UNAVAILABLE" in codes
    assert report.has_errors
    # No scanner may claim a clean result for an environment it never saw.
    for clean in ("SEC_NO_VULNS", "DEP_NO_CONFLICTS", "PKG_ALL_UP_TO_DATE", "UNUSED_NONE_FOUND"):
        assert clean not in codes


def test_ci_only_scan_does_not_need_the_environment(tmp_project):
    report = Analyzer(
        project_path=str(tmp_project), scanners=["ci"], python="/definitely/not/python"
    ).run()
    assert "ENV_PACKAGES_UNAVAILABLE" not in [i.code for i in report.issues]


def test_wrong_interpreter_is_flagged(tmp_path):
    ctx = ProjectContext(
        root=tmp_path,
        declared_deps={"django": "", "requests": ""},
        installed_packages={"pip": "24.0"},
        python_source="`python3` on PATH (no project virtualenv found)",
    )
    issues = context_issues(ctx, ["security"])
    assert [i.code for i in issues] == ["ENV_DEPS_NOT_INSTALLED"]
    assert issues[0].severity == Severity.WARNING


# ── Checks that work without pip ───────────────────────────────


def _ctx_with_dists(tmp_path, dists):
    return ProjectContext(
        root=tmp_path,
        distributions=dists,
        installed_packages={k.lower(): v["version"] for k, v in dists.items()},
        marker_env={"python_version": "3.11", "sys_platform": "linux", "os_name": "posix"},
        pip_version=None,
    )


def test_metadata_check_finds_conflicts_and_missing_packages(tmp_path):
    ctx = _ctx_with_dists(
        tmp_path,
        {
            "requests": {
                "version": "2.31.0",
                "requires": [
                    "urllib3<3,>=1.21.1",
                    "idna<4,>=2.5",
                    "PySocks!=1.5.7; extra == 'socks'",
                ],
            },
            "urllib3": {"version": "3.0.0", "requires": []},
            "legacy": {"version": "1.0", "requires": ["tomli; python_version < '3.11'"]},
        },
    )
    issues = dependency_scanner.scan(ctx)
    codes = sorted(i.code for i in issues)
    assert codes == ["DEP_MISSING", "DEP_VERSION_CONFLICT"]
    missing = next(i for i in issues if i.code == "DEP_MISSING")
    assert missing.extra["missing_package"] == "idna"  # extras and false markers are skipped


def test_outdated_check_failure_is_not_reported_as_up_to_date(tmp_path):
    ctx = ProjectContext(root=tmp_path, pip_version="24.0")
    with patch.object(outdated_package_scanner, "get_outdated_packages", return_value=None):
        issues = outdated_package_scanner.scan(ctx)
    assert [i.code for i in issues] == ["PKG_OUTDATED_UNAVAILABLE"]


def test_outdated_check_without_pip_or_uv_is_skipped(tmp_path):
    ctx = _ctx_with_dists(tmp_path, {"six": {"version": "1.16.0", "requires": []}})
    with patch("shutil.which", return_value=None):
        issues = outdated_package_scanner.scan(ctx)
    assert [i.code for i in issues] == ["PKG_OUTDATED_UNAVAILABLE"]


def test_outdated_check_uses_uv_when_pip_is_absent(tmp_path):
    ctx = _ctx_with_dists(tmp_path, {"six": {"version": "1.16.0", "requires": []}})
    rows = [{"name": "six", "version": "1.16.0", "latest_version": "1.17.0"}]
    with (
        patch("shutil.which", return_value="/usr/bin/uv"),
        patch.object(outdated_package_scanner, "get_outdated_packages_uv", return_value=rows) as uv,
    ):
        issues = outdated_package_scanner.scan(ctx)
    uv.assert_called_once()
    assert [i.code for i in issues] == ["PKG_OUTDATED"]
