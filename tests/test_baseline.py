"""
tests/test_baseline.py
──────────────────────
Baselines hide known issues, survive unrelated edits, and never hide a
broken scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pydoctor.cli import main
from pydoctor.core.baseline import BaselineError, apply_baseline, write_baseline
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.reports.fingerprint import fingerprint


def _vuln(pkg="pillow", vid="GHSA-aaaa", version="12.2.0"):
    return Issue(
        "security",
        "SEC_VULNERABILITY",
        "critical",
        f"{pkg} {version} — {vid}",
        "d",
        "r",
        package=pkg,
        extra={"vuln_id": vid, "version": version},
    )


def _secret(line=1):
    return Issue(
        "ci",
        "SECRET_EXPOSED_STRIPE_KEY",
        "critical",
        f"Exposed secret (app.py:{line})",
        "d",
        "r",
        extra={"file": "app.py", "line": line},
    )


def _report(root: Path, *issues: Issue, scanners=("security", "ci")) -> DiagnosisReport:
    report = DiagnosisReport(scan_path=str(root))
    report.extend(list(issues))
    report.scanners = list(scanners)
    return report


# ── Fingerprints ───────────────────────────────────────────────


def test_vulnerability_fingerprint_ignores_installed_version(tmp_path):
    assert fingerprint(_vuln(version="12.2.0"), tmp_path) == fingerprint(
        _vuln(version="12.3.0"), tmp_path
    )
    assert fingerprint(_vuln(vid="GHSA-aaaa"), tmp_path) != fingerprint(
        _vuln(vid="GHSA-bbbb"), tmp_path
    )


def test_file_finding_fingerprint_survives_line_shifts(tmp_path):
    (tmp_path / "app.py").write_text("KEY = 'x'\n", encoding="utf-8")
    before = fingerprint(_secret(line=1), tmp_path)
    (tmp_path / "app.py").write_text("# header\n# more\nKEY = 'x'\n", encoding="utf-8")
    assert fingerprint(_secret(line=3), tmp_path) == before
    (tmp_path / "app.py").write_text("# header\n# more\nKEY = 'y'\n", encoding="utf-8")
    assert fingerprint(_secret(line=3), tmp_path) != before


# ── Apply ──────────────────────────────────────────────────────


def test_known_issues_are_hidden_and_new_ones_kept(tmp_path):
    path = tmp_path / ".pydoctor-baseline.json"
    write_baseline(_report(tmp_path, _vuln()), path, "test")
    report = _report(tmp_path, _vuln(), _vuln(vid="GHSA-new"))
    result = apply_baseline(report, path, {"security"})
    assert [i.extra["vuln_id"] for i in report.issues] == ["GHSA-new"]
    assert result.suppressed == 1 and result.stale == 0
    assert report.scanner_meta["baseline"]["suppressed"] == 1


def test_fixed_issues_are_counted_as_stale_only_for_scanned_categories(tmp_path):
    (tmp_path / "app.py").write_text("KEY = 'x'\n", encoding="utf-8")
    path = tmp_path / ".pydoctor-baseline.json"
    write_baseline(_report(tmp_path, _vuln(), _secret()), path, "test")
    # A security-only scan finds no vulnerabilities: the vuln is fixed, the
    # secret wasn't checked and must not be called fixed.
    result = apply_baseline(_report(tmp_path, scanners=["security"]), path, {"security"})
    assert result.stale == 1


@pytest.mark.parametrize(
    "code", ["SEC_SCAN_INCOMPLETE", "ENV_PACKAGES_UNAVAILABLE", "SCANNER_ERROR"]
)
def test_broken_scans_are_never_baselined(tmp_path, code):
    broken = Issue("security", code, "error", "t", "d", "r")
    path = tmp_path / "b.json"
    assert write_baseline(_report(tmp_path, broken), path, "test") == 0
    report = _report(tmp_path, broken)
    apply_baseline(report, path, {"security"})
    assert report.has_errors


def test_info_and_ok_are_not_recorded(tmp_path):
    info = Issue("outdated", "PKG_OUTDATED", "info", "t", "d", "r", package="six")
    assert write_baseline(_report(tmp_path, info), tmp_path / "b.json", "test") == 0


def test_partial_baseline_keeps_other_categories(tmp_path):
    (tmp_path / "app.py").write_text("KEY = 'x'\n", encoding="utf-8")
    path = tmp_path / "b.json"
    write_baseline(_report(tmp_path, _vuln(), _secret()), path, "test")
    count = write_baseline(_report(tmp_path, scanners=["ci"]), path, "test", {"ci"})
    entries = json.loads(path.read_text())["issues"]
    assert count == 1 and [e["code"] for e in entries] == ["SEC_VULNERABILITY"]


def test_invalid_baseline_file_is_an_error(tmp_path):
    path = tmp_path / "b.json"
    path.write_text('{"something": "else"}', encoding="utf-8")
    with pytest.raises(BaselineError):
        apply_baseline(_report(tmp_path), path, {"ci"})


def test_baseline_file_contains_no_secret_values(tmp_path):
    secret = _secret()
    secret.extra["preview"] = "sk_l…Wx (32 chars)"
    (tmp_path / "app.py").write_text("KEY = 'x'\n", encoding="utf-8")
    path = tmp_path / "b.json"
    write_baseline(_report(tmp_path, secret), path, "test")
    assert "preview" not in path.read_text() and "sk_l" not in path.read_text()


# ── CLI ────────────────────────────────────────────────────────


def test_cli_exit_code_ignores_baselined_issues(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("KEY = 'x'\n", encoding="utf-8")
    write_baseline(_report(tmp_path, _secret()), tmp_path / ".pydoctor-baseline.json", "test")
    monkeypatch.setattr(
        main, "_run_scan", lambda **k: _report(tmp_path, _secret(), scanners=["ci"])
    )
    runner = CliRunner()
    assert (
        runner.invoke(main.app, ["check", "--ci", "--path", str(tmp_path), "--json"]).exit_code == 0
    )
    result = runner.invoke(
        main.app, ["check", "--ci", "--path", str(tmp_path), "--json", "--no-baseline"]
    )
    assert result.exit_code == 1


def test_cli_missing_explicit_baseline_is_a_usage_error(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "_run_scan", lambda **k: _report(tmp_path, scanners=["ci"]))
    result = CliRunner().invoke(
        main.app,
        ["check", "--ci", "--path", str(tmp_path), "--baseline", str(tmp_path / "nope.json")],
    )
    assert result.exit_code == 2
