"""
pydoctor/reports/fingerprint.py
────────────────────────────────
Stable identities for issues, shared by baselines and SARIF output.

A fingerprint must stay the same across scans while the problem is the same,
and change when it's a different problem:

- A vulnerability is identified by package and advisory, not by the
  installed version, so it stays "known" until the advisory no longer
  applies.
- An outdated package is identified by name only; the latest version changes
  all the time.
- File findings (secrets, workflow checks) use the file and a hash of the
  line's content, not the line number, so adding lines above them doesn't
  turn them into new findings.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from pydoctor.core.report import Issue

FINGERPRINT_VERSION = "v1"


def _line_hash(root: Path | None, rel: str, line: int | None) -> str:
    if root is None or not line:
        return ""
    try:
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    except OSError:
        text = ""
    return hashlib.sha256(text.encode()).hexdigest()[:16] if text else f"L{line}"


def _key(issue: Issue, root: Path | None) -> str:
    extra = issue.extra or {}
    if issue.code == "SEC_VULNERABILITY":
        return f"{issue.package}|{extra.get('vuln_id', issue.title)}"
    if "file" in extra:
        return f"{extra['file']}|{_line_hash(root, extra['file'], extra.get('line'))}"
    if issue.code.startswith("DEP_"):
        target = extra.get("missing_package") or extra.get("required_spec") or ""
        return f"{issue.package}|{target}"
    if issue.package:
        return str(issue.package)
    return issue.title


def fingerprint(issue: Issue, root: Path | None = None) -> str:
    """Return a short, stable identifier for ``issue``."""
    raw = f"{FINGERPRINT_VERSION}|{issue.code}|{_key(issue, root)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]
