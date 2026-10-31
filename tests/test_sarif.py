"""
tests/test_sarif.py
───────────────────
SARIF output shape, locations and rules.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.reports.docs_links import _BY_CATEGORY, _BY_CODE, docs_url
from pydoctor.reports.sarif_formatter import build_sarif


def _report(root: Path, *issues: Issue) -> DiagnosisReport:
    report = DiagnosisReport(scan_path=str(root))
    report.extend(list(issues))
    return report


def _run(root, *issues):
    return build_sarif(_report(root, *issues))["runs"][0]


def _vuln(score=7.5):
    return Issue(
        "security",
        "SEC_VULNERABILITY",
        "critical",
        "requests 2.31.0 — GHSA-x",
        "summary",
        'pip install "requests>=2.32.0"',
        package="requests",
        extra={"vuln_id": "GHSA-x", "cvss_score": score},
    )


def test_vulnerability_points_at_its_declaration(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\nRequests==2.31.0\n", encoding="utf-8")
    run = _run(tmp_path, _vuln())
    result = run["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert result["ruleId"] == "GHSA-x" and result["level"] == "error"
    assert loc["artifactLocation"]["uri"] == "requirements.txt"
    assert loc["region"]["startLine"] == 2
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "7.5"
    assert rule["helpUri"] == "https://osv.dev/vulnerability/GHSA-x"


def test_paths_are_relative_to_the_repository_root(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    project = tmp_path / "backend"
    project.mkdir()
    issue = Issue(
        "ci",
        "SECRET_EXPOSED_STRIPE_KEY",
        "critical",
        "t",
        "d",
        "r",
        extra={"file": "app.py", "line": 4},
    )
    result = _run(project, issue)["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "backend/app.py"
    assert loc["region"]["startLine"] == 4
    assert result["partialFingerprints"]["pydoctorFingerprint/v1"]


def test_environment_info_and_broken_scan_issues_are_left_out(tmp_path):
    run = _run(
        tmp_path,
        Issue("environment", "ENV_NO_VENV", "warning", "t", "d", "r"),
        Issue("security", "SEC_SCAN_INCOMPLETE", "error", "t", "d", "r"),
        Issue("outdated", "PKG_OUTDATED", "info", "t", "d", "r", package="six"),
        Issue("outdated", "PKG_OUTDATED", "warning", "t", "d", "r", package="django"),
    )
    assert [r["ruleId"] for r in run["results"]] == ["PKG_OUTDATED"]


def test_one_rule_per_code_or_advisory(tmp_path):
    run = _run(
        tmp_path, _vuln(), _vuln(), Issue("unused", "UNUSED_PACKAGE", "warning", "t", "d", "r")
    )
    assert sorted(r["id"] for r in run["tool"]["driver"]["rules"]) == ["GHSA-x", "UNUSED_PACKAGE"]
    assert len(run["results"]) == 3


# Anchors that exist on https://pydoctor-docs.thally.app (checked when this test was written).
LIVE_ANCHORS = {
    "/scanners": {
        "scanned-environment", "environment", "dependencies", "outdated-packages", "security",
        "severity", "unused-packages", "ci-cd", "secret-rules", "workflow-checks",
    },
    "/guides/troubleshooting": {
        "packages-unavailable", "wrong-python", "scan-incomplete", "env-file-committed",
    },
}  # fmt: skip


def test_docs_links_only_use_known_anchors():
    for path in list(_BY_CODE.values()) + list(_BY_CATEGORY.values()) + ["/scanners#secret-rules"]:
        page, anchor = path.split("#")
        assert anchor in LIVE_ANCHORS[page], path


def test_every_issue_gets_a_docs_link():
    assert (
        docs_url(Issue("x", "UNKNOWN", "warning", "t", "d", "r"))
        == "https://pydoctor-docs.thally.app"
    )
    secret = Issue("ci", "SECRET_EXPOSED_AWS_KEY", "critical", "t", "d", "r")
    assert docs_url(secret).endswith("/scanners#secret-rules")
    assert secret.to_dict()["docs_url"] == docs_url(secret)
