"""
tests/test_fix_command.py
─────────────────────────
Unit tests for `pydoctor fix`: per-package prompts, verified upgrades,
and no implicit removals.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from typer.testing import CliRunner

from pydoctor.cli import main
from pydoctor.core.report import DiagnosisReport, Issue


def _vuln(pkg, fixed_in, severity="critical"):
    return Issue(
        category="security",
        code="SEC_VULNERABILITY",
        severity=severity,
        title=f"{pkg} advisory",
        description="",
        recommendation="",
        package=pkg,
        extra={"fixed_in": fixed_in},
    )


def test_one_prompt_per_vulnerable_package(monkeypatch):
    report = DiagnosisReport(
        issues=[
            _vuln("pillow", "12.3.0"),
            _vuln("pillow", "13.0.0"),
            _vuln("pillow", "12.2.1", severity="warning"),
            _vuln("cryptography", "46.0.5"),
        ]
    )
    prompts, applied = [], []
    monkeypatch.setattr(main.Confirm, "ask", lambda msg, *a, **k: prompts.append(msg) or True)
    monkeypatch.setattr(
        main,
        "_apply_and_verify",
        lambda ctx, pkg, action, target, verb: applied.append((pkg, target)) or True,
    )

    handled: set[str] = set()
    actions = main._fix_vulnerabilities(report, SimpleNamespace(), True, handled)

    assert len(prompts) == 2
    assert "3 advisories, 2 critical" in prompts[0]
    assert applied == [("pillow", "13.0.0"), ("cryptography", "46.0.5")]
    assert actions == 2
    assert handled == {"pillow", "cryptography"}


def test_outdated_skips_packages_already_handled(monkeypatch):
    report = DiagnosisReport(
        issues=[
            Issue(
                category="outdated",
                code="PKG_OUTDATED",
                severity="warning",
                title="",
                description="",
                recommendation="",
                package="pillow",
                extra={"latest_version": "13.0.0"},
            )
        ]
    )
    monkeypatch.setattr(main.Confirm, "ask", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert main._fix_outdated(report, SimpleNamespace(), True, {"pillow"}) == 0


def test_unchanged_version_is_not_reported_as_fixed(monkeypatch, tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = [\n    "pillow==12.2.0",\n]\n', encoding="utf-8"
    )
    ctx = SimpleNamespace(root=tmp_path)
    monkeypatch.setattr(main, "_installed_version", lambda ctx, pkg: "12.2.0")
    monkeypatch.setattr(
        main,
        "_run_package_manager_command",
        lambda *a, **k: subprocess.CompletedProcess(args=[], returncode=0),
    )

    assert main._apply_and_verify(ctx, "pillow", "add", None, "upgraded") is False
    out = capsys.readouterr().out
    assert "still 12.2.0" in out
    assert "pillow==12.2.0" in out
    assert "✔" not in out


def test_changed_version_is_reported(monkeypatch, capsys):
    versions = iter(["12.2.0", "13.0.0"])
    monkeypatch.setattr(main, "_installed_version", lambda ctx, pkg: next(versions))
    monkeypatch.setattr(
        main,
        "_run_package_manager_command",
        lambda *a, **k: subprocess.CompletedProcess(args=[], returncode=0),
    )
    assert main._apply_and_verify(SimpleNamespace(), "pillow", "add", "13.0.0", "upgraded")
    assert "12.2.0 → 13.0.0" in capsys.readouterr().out


def test_uv_uses_minimum_version_requirement(monkeypatch):
    calls = []
    monkeypatch.setattr(
        main.subprocess,
        "run",
        lambda cmd, cwd=None: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0),
    )
    ctx = SimpleNamespace(root=".", is_poetry=False, is_uv=True, is_pdm=False)
    main._run_package_manager_command(ctx, "pillow", "add", True, "13.0.0")
    assert calls == [["uv", "add", "pillow>=13.0.0"]]


def test_naming_a_package_does_not_remove_it(monkeypatch, tmp_path):
    report = DiagnosisReport(
        issues=[
            Issue(
                category="unused",
                code="UNUSED_PACKAGE",
                severity="warning",
                title="",
                description="",
                recommendation="",
                package="redis",
            )
        ]
    )
    monkeypatch.setattr(main, "_run_scan", lambda **k: report)
    monkeypatch.setattr(main, "_fix_unused", lambda *a: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(main, "_fix_venv", lambda *a: 0)

    result = CliRunner().invoke(main.app, ["fix", "redis", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.stdout
    assert "pydoctor fix --remove" in result.stdout
