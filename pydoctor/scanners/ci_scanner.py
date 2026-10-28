"""
pydoctor/scanners/ci_scanner.py
─────────────────────────────
CI/CD Guard Mode scanner.

Checks for exposed secrets in the files you commit, and for risky patterns in
GitHub Actions / GitLab CI workflows.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import Issue
from pydoctor.security.secrets import (
    _looks_like_placeholder,
    _looks_random,
    candidate_files,
    is_env_file,
    scan_files,
)
from pydoctor.utils.file_utils import is_test_file

CATEGORY = "ci"
MAX_SECRET_FINDINGS = 50

_SECRET_RECOMMENDATION = (
    "Revoke or rotate this credential now (it may already be in git history), then "
    "load it from an environment variable or a secret manager. If this is a false "
    "positive, add `# pydoctor: ignore` to the line."
)


def scan(ctx: ProjectContext) -> list[Issue]:
    """Perform CI/CD and Secret scanning."""
    issues: list[Issue] = []

    # 1. Secret Scanning
    issues.extend(_scan_for_secrets(ctx))

    # 2. Workflow Scanning
    issues.extend(_scan_workflows(ctx))

    if not issues:
        issues.append(
            Issue(
                category=CATEGORY,
                code="CI_HEALTHY",
                severity=Severity.OK,
                title="CI/CD and Secrets secure",
                description="No exposed secrets or high-risk workflow patterns detected.",
                recommendation="",
            )
        )

    return issues


# ──────────────────────────────────────────────────────────────
# Secrets
# ──────────────────────────────────────────────────────────────


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _scan_for_secrets(ctx: ProjectContext) -> list[Issue]:
    """Scan committed (or about-to-be-committed) files for hardcoded secrets."""
    files, tracked, using_git = candidate_files(ctx.root, ctx.python_files)
    issues: list[Issue] = []

    if using_git:
        env_files = [f for f in files if is_env_file(f) and not is_test_file(f, ctx.root)]
        for env_file in env_files:
            committed = env_file in tracked
            rel = _rel(env_file, ctx.root)
            issues.append(
                Issue(
                    category=CATEGORY,
                    code="CI_ENV_FILE_COMMITTED" if committed else "CI_ENV_FILE_NOT_IGNORED",
                    severity=Severity.ERROR if committed else Severity.WARNING,
                    title=(
                        f"Environment file committed to git: {rel}"
                        if committed
                        else f"Environment file not ignored by git: {rel}"
                    ),
                    description=(
                        f"{rel} usually holds real credentials. "
                        + (
                            "It is tracked by git, so everyone with access to the repository "
                            "(and its history) can read it."
                            if committed
                            else "It isn't in .gitignore, so the next `git add .` commits it."
                        )
                    ),
                    recommendation=(
                        f"git rm --cached {rel}, add it to .gitignore, rotate the values it "
                        "contained, and commit a .env.example with placeholders instead."
                        if committed
                        else f"Add {rel} to .gitignore. Commit a .env.example with placeholders."
                    ),
                    extra={"file": rel},
                )
            )

    findings = scan_files(files, lambda p: is_test_file(p, ctx.root))
    for f in findings[:MAX_SECRET_FINDINGS]:
        rel = _rel(f.path, ctx.root)
        issues.append(
            Issue(
                category=CATEGORY,
                code=f"SECRET_EXPOSED_{f.code}",
                severity=Severity.CRITICAL if f.high_confidence else Severity.ERROR,
                title=f"Exposed secret: {f.label} ({rel}:{f.line})",
                description=(
                    f"{'Found' if f.high_confidence else 'Possible'} {f.label.lower()} "
                    f"in {rel} on line {f.line}: {f.preview}"
                ),
                recommendation=_SECRET_RECOMMENDATION,
                extra={"file": rel, "line": f.line, "preview": f.preview},
            )
        )
    if len(findings) > MAX_SECRET_FINDINGS:
        issues.append(
            Issue(
                category=CATEGORY,
                code="SECRET_FINDINGS_TRUNCATED",
                severity=Severity.ERROR,
                title=f"{len(findings) - MAX_SECRET_FINDINGS} more possible secrets not shown",
                description=f"{len(findings)} findings in total; the first {MAX_SECRET_FINDINGS} are listed.",
                recommendation="Fix the listed findings and scan again.",
            )
        )
    return issues


# ──────────────────────────────────────────────────────────────
# Workflows
# ──────────────────────────────────────────────────────────────

_BRANCH_REFS = {"main", "master", "head", "dev", "develop", "trunk"}
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^@\s'\"#]+)@([^\s'\"#]+)")
_RUN = re.compile(r"^(\s*)(?:-\s*)?run:\s*(.*)$")
_UNTRUSTED = re.compile(
    r"\$\{\{\s*(github\.head_ref|github\.event\.(?:issue|pull_request|comment|review|"
    r"review_comment|discussion|discussion_comment|pages|commits|head_commit|workflow_run)"
    r"[\w.\[\]*'\"-]*(?:title|body|message|name|email|label|ref|head_branch|default_branch|"
    r"page_name)[\w.]*)\s*\}\}"
)
_SECRET_ENV = re.compile(
    r"^\s*([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)[A-Z0-9_]*)"
    r"\s*:\s*['\"]?([^'\"\s#]+)"
)


def _scan_workflows(ctx: ProjectContext) -> list[Issue]:
    """Scan CI workflow files for insecure patterns."""
    issues: list[Issue] = []
    wf_dir = ctx.root / ".github" / "workflows"
    files = (
        sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))) if wf_dir.is_dir() else []
    )
    gitlab = ctx.root / ".gitlab-ci.yml"
    if gitlab.is_file():
        files.append(gitlab)
    for f in files:
        _check_workflow_file(f, issues, ctx)
    return issues


def _issue(code, severity, title, description, recommendation, rel, line) -> Issue:
    return Issue(
        category=CATEGORY,
        code=code,
        severity=severity,
        title=f"{title} ({rel}:{line})",
        description=description,
        recommendation=recommendation,
        extra={"file": rel, "line": line},
    )


def _check_uses(line: str, rel: str, no: int) -> Issue | None:
    m = _USES.match(line)
    if not m:
        return None
    action, ref = m.group(1), m.group(2)
    if action.startswith(("./", "docker://")) or ref.lower() not in _BRANCH_REFS:
        return None
    return _issue(
        "CI_UNPINNED_ACTION",
        Severity.WARNING,
        f"Unpinned GitHub Action {action}@{ref}",
        f"{rel} runs {action} from the {ref} branch, which can change at any time.",
        "Pin to a release tag, or better, a full commit SHA.",
        rel,
        no,
    )


def _check_injection(line: str, rel: str, no: int) -> Issue | None:
    m = _UNTRUSTED.search(line)
    if not m:
        return None
    return _issue(
        "CI_SCRIPT_INJECTION",
        Severity.ERROR,
        "Untrusted input interpolated into a shell script",
        f"`{m.group(0)}` is controlled by whoever opens the issue or pull request. "
        "Inside `run:` it is pasted into the script, so crafted text can run "
        "commands in your workflow.",
        f"Pass it through an environment variable instead: `env: VALUE: {m.group(0)}` "
        'and use "$VALUE" in the script.',
        rel,
        no,
    )


def _check_permissions(line: str, rel: str, no: int) -> Issue | None:
    if not re.match(r"^\s*permissions:\s*write-all\s*$", line):
        return None
    return _issue(
        "CI_BROAD_PERMISSIONS",
        Severity.WARNING,
        "Workflow token has write access to everything",
        "`permissions: write-all` lets any step, including third-party actions, "
        "push code, publish releases and change settings.",
        "Grant only what the job needs, e.g. `permissions: { contents: read }`.",
        rel,
        no,
    )


def _check_pr_target_checkout(line: str, rel: str, no: int) -> Issue | None:
    if not re.search(r"ref:\s*.*(github\.event\.pull_request\.head|github\.head_ref)", line):
        return None
    return _issue(
        "CI_PULL_REQUEST_TARGET_CHECKOUT",
        Severity.CRITICAL,
        "pull_request_target workflow checks out pull request code",
        "pull_request_target runs with your repository's secrets and a write token. "
        "Checking out the PR's code there lets anyone who opens a PR run code with "
        'those privileges (a "pwn request").',
        "Use the `pull_request` trigger for building or testing PR code, or don't "
        "check out the PR head in this workflow.",
        rel,
        no,
    )


def _check_cleartext(line: str, rel: str, no: int) -> Issue | None:
    m = _SECRET_ENV.match(line)
    if not m or "$" in line:
        return None
    value = m.group(2)
    # CI service containers commonly use throwaway values like
    # POSTGRES_PASSWORD: postgres; only flag values that look real.
    if len(value) < 8 or not _looks_random(value) or _looks_like_placeholder(value):
        return None
    return _issue(
        "CI_CLEARTEXT_ENV",
        Severity.ERROR,
        f"Secret value written in the workflow: {m.group(1)}",
        f"{m.group(1)} is set to a literal value in {rel}, visible to anyone "
        "who can read the repository.",
        "Store it as a repository secret and use ${{ secrets.NAME }}.",
        rel,
        no,
    )


def _run_block_lines(lines: list[str]) -> set[int]:
    """Line numbers that belong to a `run:` script (inline or block)."""
    inside: set[int] = set()
    run_indent: int | None = None
    for no, line in enumerate(lines, start=1):
        indent = len(line) - len(line.lstrip())
        if run_indent is not None and line.strip() and indent <= run_indent:
            run_indent = None
        if run_indent is not None:
            inside.add(no)
        run = _RUN.match(line)
        if run:
            inside.add(no)
            if run.group(2).strip() in ("|", ">", "|-", ">-", "|+", ">+", ""):
                run_indent = len(run.group(1))
    return inside


def _check_workflow_file(file_path: Path, issues: list[Issue], ctx: ProjectContext) -> None:
    """Check a single workflow file for risky patterns, with line numbers."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    rel = _rel(file_path, ctx.root)
    lines = content.splitlines()
    is_prt = bool(re.search(r"\bpull_request_target\b", content))
    run_lines = _run_block_lines(lines)

    for no, line in enumerate(lines, start=1):
        if "pydoctor: ignore" in line.lower():
            continue
        checks = [_check_uses, _check_permissions, _check_cleartext]
        if no in run_lines:
            checks.append(_check_injection)
        if is_prt:
            checks.append(_check_pr_target_checkout)
        for check in checks:
            found = check(line, rel, no)
            if found:
                issues.append(found)
