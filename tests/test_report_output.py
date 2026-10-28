"""
tests/test_report_output.py
───────────────────────────
Health score behaviour and JSON output shape.
"""

from __future__ import annotations

import io
import json

from pydoctor.analysis.health_score import calculate_health
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.reports.json_formatter import render_json


def _vuln(pkg: str, severity: str = "critical", vuln_id: str = "GHSA-x") -> Issue:
    return Issue(
        "security",
        "SEC_VULNERABILITY",
        severity,
        f"{pkg} advisory",
        "summary",
        "upgrade",
        package=pkg,
        extra={"vuln_id": vuln_id, "version": "1.0", "aliases": ["CVE-1"], "fixed_in": "1.1"},
    )


def _report(*issues: Issue) -> DiagnosisReport:
    report = DiagnosisReport()
    report.extend(list(issues))
    return report


def test_many_advisories_for_one_package_cost_one_penalty():
    one = calculate_health(_report(_vuln("pillow")))
    many = calculate_health(_report(*[_vuln("pillow") for _ in range(54)]))
    assert one.score == many.score


def test_fixing_packages_moves_the_score_in_a_badly_affected_project():
    pkgs = ["pillow", "cryptography", "pyjwt", "urllib3", "sqlparse", "djangorestframework"]
    before = calculate_health(_report(*[_vuln(p) for p in pkgs])).score
    after = calculate_health(_report(*[_vuln(p) for p in pkgs[3:]])).score
    assert after > before


def test_any_critical_issue_rules_out_good():
    health = calculate_health(_report(_vuln("pillow")))
    assert health.score <= 69 and health.verdict in ("Needs Attention", "Critical")


def test_incomplete_scan_is_labelled_incomplete():
    issue = Issue("security", "SEC_SCAN_INCOMPLETE", "error", "t", "d", "r")
    assert calculate_health(_report(issue)).verdict == "Incomplete"


def test_json_includes_health():
    out = io.StringIO()
    render_json(_report(Issue("outdated", "PKG_OUTDATED", "warning", "t", "d", "r")), stream=out)
    data = json.loads(out.getvalue())
    assert set(data["health"]) == {"score", "verdict"}


def test_security_json_keeps_advisory_ids():
    out = io.StringIO()
    render_json(_report(_vuln("requests", "error", "GHSA-9wx4-h78v-vm56")), stream=out)
    entry = json.loads(out.getvalue())["vulnerabilities"][0]
    assert entry["advisory"] == "GHSA-9wx4-h78v-vm56"
    assert entry["code"] == "SEC_VULNERABILITY"
    assert entry["fixed_in"] == "1.1" and entry["aliases"] == ["CVE-1"]
