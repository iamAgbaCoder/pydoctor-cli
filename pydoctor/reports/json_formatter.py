"""
pydoctor/reports/json_formatter.py
────────────────────────────────────
JSON report serialiser for CI/CD integration.

Converts a ``DiagnosisReport`` into a deterministic, human-readable
JSON structure that can be piped into jq, saved to a file, or parsed
by other tools.

Example output shape:
    {
        "scan_path": "/home/user/myproject",
        "scanned_at": "2024-01-15T10:30:00Z",
        "scan_duration_ms": 1234.56,
        "summary": {"ok": 3, "warning": 2, "error": 1, ...},
        "issues": [...],
        "meta": {...}
    }
"""

from __future__ import annotations

import json
import sys
from typing import IO

from pydoctor.core.report import DiagnosisReport


def render_json(
    report: DiagnosisReport,
    *,
    indent: int = 2,
    stream: IO = sys.stdout,
    pretty: bool = True,
) -> str:
    """
    Serialise a ``DiagnosisReport`` to a JSON string and optionally print it.

    Parameters
    ----------
    report:  The report to serialise.
    indent:  JSON indentation level (default 2 for human readability).
    stream:  Output stream.  Defaults to stdout.
             Pass ``None`` to suppress printing and just return the string.
    pretty:  Whether to sort keys for deterministic output.

    Returns
    -------
    str
        The serialised JSON string.
    """
    from pydoctor.analysis.health_score import calculate_health

    health = calculate_health(report)
    data = report.to_dict()
    data["health"] = {"score": health.score, "verdict": health.verdict}

    # Security-only scans keep their compact shape, now with advisory IDs.
    categories = {i.category for i in report.issues if i.code not in _CONTEXT_CODES}
    if categories == {"security"}:
        data = {
            "scan_type": "security",
            "health": data["health"],
            "vulnerabilities": [
                _vuln_entry(i) for i in report.issues if i.severity not in ("ok", "info")
            ],
        }

    json_str = json.dumps(
        data,
        indent=indent if pretty else None,
        sort_keys=pretty,
        ensure_ascii=False,
    )

    if stream is not None:
        stream.write(json_str)
        stream.write("\n")

    return json_str


_CONTEXT_CODES = {"ENV_PACKAGES_UNAVAILABLE", "ENV_DEPS_NOT_INSTALLED"}


def _vuln_entry(issue) -> dict:
    """
    One entry of the security-only JSON.

    `advisory` used to hold the issue code ("SEC_VULNERABILITY") for every
    finding, so the GHSA/CVE id was lost. It is now the advisory id; `code`
    carries the issue code.
    """
    extra = issue.extra or {}
    return {
        "package": issue.package,
        "version": extra.get("version", "unknown"),
        "advisory": extra.get("vuln_id", issue.code),
        "aliases": extra.get("aliases", []),
        "fixed_in": extra.get("fixed_in") or None,
        "cvss_score": extra.get("cvss_score"),
        "severity": issue.severity,
        "summary": issue.description,
        "code": issue.code,
        "docs_url": issue.docs_url,
        **(
            {"unchecked_packages": extra["unchecked_packages"]}
            if "unchecked_packages" in extra
            else {}
        ),
        **({"python": extra["python"]} if "python" in extra else {}),
    }


def report_to_dict(report: DiagnosisReport) -> dict:
    """
    Return the report as a plain Python dictionary.

    Useful when embedding the report data in a larger JSON structure
    or when a caller pre-processes it before serialisation.

    Parameters
    ----------
    report: DiagnosisReport to convert.

    Returns
    -------
    dict
    """
    return report.to_dict()
