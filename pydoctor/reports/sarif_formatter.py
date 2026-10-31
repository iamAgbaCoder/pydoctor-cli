"""
pydoctor/reports/sarif_formatter.py
────────────────────────────────────
SARIF 2.1.0 output, for GitHub code scanning and other SARIF viewers.

Design choices:

- Each vulnerability advisory is its own rule (ruleId = GHSA/PYSEC/CVE id),
  because code scanning reads ``security-severity`` from the rule, and
  advisories under one rule would all share a severity.
- Package findings point at the line that declares the package
  (pyproject.toml or requirements*.txt) so they appear on a file; file
  findings (secrets, workflows) point at their own file and line.
- Environment findings and problems with the scan itself are left out: they
  describe the machine, not the code, and they already fail the run.
- Paths are relative to the git repository root, which is what code scanning
  expects even when the scanned project is a subdirectory.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from pydoctor import __version__
from pydoctor.core.baseline import NEVER_BASELINE
from pydoctor.core.report import DiagnosisReport, Issue
from pydoctor.reports.docs_links import DOCS_URL, docs_url
from pydoctor.reports.fingerprint import fingerprint

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_EXCLUDED_CATEGORIES = {"environment"}
_EXCLUDED_CODES = NEVER_BASELINE | {"SECRET_FINDINGS_TRUNCATED"}
_LEVEL = {"critical": "error", "error": "error", "warning": "warning"}
_SECURITY_SEVERITY = {"critical": "9.0", "error": "6.5", "warning": "3.5"}
_MANIFESTS = ("pyproject.toml", "requirements.txt")


def _repo_root(project_root: Path) -> Path:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip()).resolve()
    except (OSError, subprocess.SubprocessError):
        pass
    return project_root


def _declaration(project_root: Path, package: str) -> tuple[str, int] | None:
    """File (relative to the project) and line that declare ``package``."""
    name = re.escape(package).replace(r"\-", "[-_.]").replace(r"\_", "[-_.]")
    pattern = re.compile(rf"""^\s*["']?{name}\s*(?:\[[^\]]*\])?\s*([<>=!~^;,"'\s]|$)""", re.I)
    candidates = [project_root / m for m in _MANIFESTS] + sorted(
        project_root.glob("requirements*.txt")
    )
    for path in dict.fromkeys(candidates):
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for no, line in enumerate(lines, start=1):
            if pattern.match(line):
                return str(path.relative_to(project_root)), no
    return None


def _first_manifest(project_root: Path) -> str | None:
    return next((m for m in _MANIFESTS if (project_root / m).is_file()), None)


def _location(issue: Issue, project_root: Path, repo_root: Path) -> dict | None:
    extra = issue.extra or {}
    if "file" in extra:
        rel, line = extra["file"], extra.get("line") or 1
    elif issue.package and (decl := _declaration(project_root, issue.package)):
        rel, line = decl
    elif manifest := _first_manifest(project_root):
        rel, line = manifest, 1
    else:
        return None
    try:
        uri = (project_root / rel).resolve().relative_to(repo_root).as_posix()
    except ValueError:
        uri = Path(rel).as_posix()
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": int(line)},
        }
    }


def _rule_id(issue: Issue) -> str:
    if issue.code == "SEC_VULNERABILITY":
        return str((issue.extra or {}).get("vuln_id") or issue.code)
    return issue.code


def _rule(issue: Issue, rule_id: str) -> dict:
    extra = issue.extra or {}
    rule: dict = {"id": rule_id, "properties": {"tags": [issue.category]}}
    if issue.code == "SEC_VULNERABILITY":
        rule["name"] = "Vulnerability"
        rule["shortDescription"] = {"text": f"{rule_id} in {issue.package}"}
        rule["fullDescription"] = {"text": issue.description or rule_id}
        rule["helpUri"] = f"https://osv.dev/vulnerability/{rule_id}"
        rule["help"] = {"text": f"{issue.recommendation}\n\nAdvisory: {rule['helpUri']}"}
        score = extra.get("cvss_score")
        rule["properties"]["security-severity"] = (
            f"{float(score):.1f}" if score else _SECURITY_SEVERITY.get(issue.severity, "5.0")
        )
        rule["properties"]["tags"] += ["security", "vulnerability", "dependency"]
    else:
        rule["name"] = "".join(p.capitalize() for p in issue.code.lower().split("_"))
        rule["shortDescription"] = {"text": issue.code.replace("_", " ").capitalize()}
        rule["helpUri"] = docs_url(issue)
        rule["help"] = {"text": f"{issue.recommendation}\n\nDocs: {rule['helpUri']}"}
        if issue.category in ("ci", "security"):
            rule["properties"]["security-severity"] = _SECURITY_SEVERITY.get(issue.severity, "5.0")
            rule["properties"]["tags"].append("security")
    return rule


def build_sarif(report: DiagnosisReport) -> dict:
    project_root = (
        Path(report.ctx.root) if report.ctx is not None else Path(report.scan_path)
    ).resolve()
    repo_root = _repo_root(project_root)
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for issue in report.issues:
        if (
            issue.severity not in _LEVEL
            or issue.category in _EXCLUDED_CATEGORIES
            or issue.code in _EXCLUDED_CODES
        ):
            continue
        rule_id = _rule_id(issue)
        rules.setdefault(rule_id, _rule(issue, rule_id))
        result: dict = {
            "ruleId": rule_id,
            "level": _LEVEL[issue.severity],
            "message": {"text": f"{issue.title}. {issue.description}".strip()},
            "partialFingerprints": {"pydoctorFingerprint/v1": fingerprint(issue, project_root)},
            "properties": {"pydoctorCode": issue.code, "pydoctorSeverity": issue.severity},
        }
        if location := _location(issue, project_root, repo_root):
            result["locations"] = [location]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pydoctor",
                        "version": __version__,
                        "informationUri": DOCS_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(report: DiagnosisReport, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_sarif(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
