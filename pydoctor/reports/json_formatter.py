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
from typing import IO, Optional

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
    data = report.to_dict()

    # Special case: map purely security outputs to simple output
    categories = {i.category for i in report.issues}
    if categories == {"security"}:
        vulns = []
        for issue in report.issues:
            if issue.severity in ("ok", "info"):
                continue
            vulns.append(
                {
                    "package": issue.package,
                    "version": issue.extra.get("version", "unknown"),
                    "advisory": issue.code,
                    "severity": issue.severity,
                }
            )
        data = {"scan_type": "security", "vulnerabilities": vulns}

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
