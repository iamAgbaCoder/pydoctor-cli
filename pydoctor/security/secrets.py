"""
pydoctor/security/secrets.py
─────────────────────────────
Secret detection for the CI/CD guard.

Earlier versions only looked at ``.py`` files with four patterns, so a
hardcoded Django ``SECRET_KEY``, a Stripe live key or a committed ``.env``
file were all reported as "secure". This module:

- scans the files that are (or are about to be) in version control, of any
  text type, not just Python;
- uses provider-specific patterns (high confidence) plus a generic
  "secret-looking name assigned a high-entropy literal" rule;
- returns the file, line and a redacted preview for every finding;
- honours ``# pydoctor: ignore`` on the same line.
"""

from __future__ import annotations

import math
import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pydoctor.utils.file_utils import _should_skip_dir

MAX_FILE_BYTES = 1_000_000
IGNORE_MARKER = re.compile(r"pydoctor:\s*ignore", re.I)

# Files that are never worth scanning for secrets.
_SKIP_SUFFIXES = {
    ".lock", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf",
    ".zip", ".gz", ".tar", ".whl", ".so", ".dll", ".dylib", ".pyc", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".min.js", ".map",
}  # fmt: skip
_SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock"}

# Environment files that hold real values. Templates are fine to commit.
_ENV_FILE = re.compile(r"^\.env(\..+)?$")
_ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)


@dataclass(frozen=True)
class Rule:
    code: str
    label: str
    pattern: re.Pattern[str]
    group: int = 0  # group holding the secret value
    high_confidence: bool = True


# Provider formats: specific enough that a match is almost always a real key.
PROVIDER_RULES = [
    Rule("AWS_KEY", "AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("GH_TOKEN", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    Rule("GH_TOKEN", "GitHub token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    Rule("PYPI_TOKEN", "PyPI API token", re.compile(r"\bpypi-[A-Za-z0-9_\-]{50,}")),
    Rule("STRIPE_KEY", "Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    Rule("ANTHROPIC_KEY", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    Rule(
        "OPENAI_KEY",
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|\bsk-[A-Za-z0-9]{48}\b"),
    ),
    Rule("SLACK_TOKEN", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    Rule("GOOGLE_API_KEY", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule(
        "PRIVATE_KEY",
        "Private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    Rule(
        "DATABASE_URL",
        "Database URL with a password",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp)"
            r"://[^:\s/@'\"]+:([^@\s'\"]+)@([^:/\s'\"]+)"
        ),
        group=1,
    ),
    Rule(
        "APP_SECRET_KEY",
        "SECRET_KEY setting (Django/Flask)",
        re.compile(r"^\s*SECRET_KEY\s*=\s*[rbuRBU]?['\"]([^'\"]{20,})['\"]", re.M),
        group=1,
    ),
]

# A secret-looking name assigned a literal value. Lower confidence, so the
# name must END with a secret word (MAX_SECRET_FINDINGS doesn't count), the
# value must be a literal that looks random, and documentation is skipped.
_SECRET_NAME = r"[A-Za-z0-9_.\-]*?(?:secret|passw(?:or)?d|pwd|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key)"
_CODE_ASSIGN = re.compile(
    rf"""(?i)\b({_SECRET_NAME})["']?\s*(?::=|=>|:|=)\s*[rbuf]?["']([^"'\s]{{8,}})["']"""
)
_CONFIG_ASSIGN = re.compile(
    rf"""(?i)^\s*(?:export\s+)?({_SECRET_NAME})\s*[=:]\s*["']?([^"'\s#]{{8,}})"""
)
GENERIC_RULE = Rule("GENERIC_SECRET", "Hardcoded credential", _CODE_ASSIGN, 2, False)

_DOC_SUFFIXES = {".md", ".rst", ".txt", ".adoc", ".ipynb"}
# Example and documentation code is full of illustrative credentials.
_DOC_DIRS = {"docs", "doc", "docs_src", "examples", "example", "samples", "tutorial", "tutorials"}
_CONFIG_SUFFIXES = {".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml"}
_CONTEXT_RULES = {"APP_SECRET_KEY", "DATABASE_URL"}  # too often illustrative in docs

_PLACEHOLDER = re.compile(
    r"(change.?me|example|your[_\-]|xxx|placeholder|dummy|sample|redacted|todo|\.\.\.|…|"
    r"<.*>|\$\{|\{\{|%\(|os\.environ|getenv|env\(|config\(|\*\*\*\*|^none$|^null$|"
    r"^true$|^false$|^password$|^secret$|not.?set|replace)",
    re.I,
)


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "db", "database", "postgres", "mysql", "redis"}


@dataclass(frozen=True)
class Finding:
    code: str
    label: str
    path: Path
    line: int
    preview: str
    high_confidence: bool


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def redact(value: str) -> str:
    """Show enough to locate the value without printing the secret."""
    value = value.strip()
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def _looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.search(value)) or len(set(value)) <= 3


def _looks_random(value: str) -> bool:
    """Heuristic for generic matches: mixed letters and digits, not an identifier."""
    if re.fullmatch(r"[A-Z0-9_]+|[a-z_.\-]+|[\w.\-]+\.(?:py|js|ts|json|txt)", value):
        return False  # NAME_OF_ENV_VAR, plain words, file names
    if value.startswith(("/", "./", "http://", "https://")):
        return False
    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_letter and has_digit and shannon_entropy(value) >= 3.0


# ── File selection ─────────────────────────────────────────────


def _git(root: Path, *args: str) -> list[str] | None:
    try:
        res = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return [p for p in res.stdout.split("\0") if p]


def candidate_files(root: Path, fallback: list[Path]) -> tuple[list[Path], set[Path], bool]:
    """
    Files to scan, the subset already committed, and whether git was used.

    In a git repository this is every tracked file plus untracked files that
    aren't ignored (they're one ``git add`` away from being committed).
    Outside git, ``fallback`` (the project's Python files) plus config-like
    files found while walking the tree, excluding ``.env`` files, since a
    local ``.env`` outside version control is normal.
    """
    tracked = _git(root, "ls-files", "-z")
    if tracked is not None:
        untracked = _git(root, "ls-files", "-z", "--others", "--exclude-standard") or []
        tracked_paths = {root / p for p in tracked}
        files = sorted(tracked_paths | {root / p for p in untracked})
        return [f for f in files if f.is_file()], tracked_paths, True

    found: set[Path] = set(fallback)
    for path in _walk(root):
        if path.suffix in {".py", ".cfg", ".ini", ".toml", ".yml", ".yaml", ".json", ".sh"}:
            found.add(path)
    return sorted(found), set(), False


def _walk(root: Path) -> Iterator[Path]:
    try:
        entries = list(root.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry.is_dir():
            if not _should_skip_dir(entry) and entry.name != ".git":
                yield from _walk(entry)
        elif entry.is_file():
            yield entry


def is_env_file(path: Path) -> bool:
    return bool(_ENV_FILE.match(path.name)) and not _ENV_TEMPLATE.search(path.name)


def _readable_text(path: Path) -> str | None:
    name = path.name.lower()
    if name in _SKIP_NAMES or any(name.endswith(s) for s in _SKIP_SUFFIXES):
        return None
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


# ── Scanning ───────────────────────────────────────────────────


class _Collector:
    """Collects findings for one file: one per line, honouring ignore markers."""

    def __init__(self, path: Path, lines: list[str]) -> None:
        self.path, self.lines = path, lines
        self.findings: list[Finding] = []
        self.flagged: set[int] = set()

    def add(self, rule: Rule, line_no: int, value: str) -> None:
        line = self.lines[line_no - 1] if 0 < line_no <= len(self.lines) else ""
        if line_no in self.flagged or IGNORE_MARKER.search(line) or _looks_like_placeholder(value):
            return
        self.flagged.add(line_no)
        self.findings.append(
            Finding(rule.code, rule.label, self.path, line_no, redact(value), rule.high_confidence)
        )


def _provider_pass(out: _Collector, text: str, is_doc: bool) -> None:
    for rule in PROVIDER_RULES:
        if is_doc and rule.code in _CONTEXT_RULES:
            continue
        for m in rule.pattern.finditer(text):
            if rule.code == "DATABASE_URL" and m.group(2).lower() in _LOCAL_HOSTS:
                continue  # local/dev database (docker-compose style); not a leak
            out.add(rule, text.count("\n", 0, m.start()) + 1, m.group(rule.group))


def _generic_pass(out: _Collector, is_config: bool) -> None:
    for line_no, line in enumerate(out.lines, start=1):
        if line_no in out.flagged or line.lstrip().startswith(("#", "//")):
            continue
        m = _CONFIG_ASSIGN.match(line) if is_config else None
        m = m or _CODE_ASSIGN.search(line)
        if m and "hash" not in m.group(1).lower() and _looks_random(m.group(2)):
            out.add(GENERIC_RULE, line_no, m.group(2))


def scan_text(path: Path, text: str) -> list[Finding]:
    """Find secrets in one file's text."""
    suffix = path.suffix.lower()
    is_doc = suffix in _DOC_SUFFIXES or bool(_DOC_DIRS.intersection(p.lower() for p in path.parts))
    is_config = path.name.startswith(".env") or suffix in _CONFIG_SUFFIXES
    is_workflow = ".github/workflows/" in path.as_posix() or path.name == ".gitlab-ci.yml"
    out = _Collector(path, text.splitlines())
    _provider_pass(out, text, is_doc)
    # Docs are full of examples; workflows get their own CI_CLEARTEXT_ENV check.
    if not (is_doc or is_workflow):
        _generic_pass(out, is_config)
    return out.findings


def scan_files(files: list[Path], skip_content) -> list[Finding]:
    """Scan ``files``; ``skip_content(path)`` excludes e.g. test fixtures."""
    findings: list[Finding] = []
    for path in files:
        if skip_content(path):
            continue
        text = _readable_text(path)
        if text is None:
            continue
        findings.extend(scan_text(path, text))
    return findings
