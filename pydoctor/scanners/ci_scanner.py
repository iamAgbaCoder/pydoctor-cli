"""
pydoctor/scanners/ci_scanner.py
─────────────────────────────
CI/CD Guard Mode scanner.

Checks for exposed secrets in the codebase and verifies that GitHub Actions/GitLab CI
workflows follow best security practices (e.g. pinned versions, no cleartext secrets).
"""

from __future__ import annotations

import re
from pathlib import Path

from pydoctor.config.settings import Severity
from pydoctor.core.project import ProjectContext
from pydoctor.core.report import Issue
from pydoctor.utils.file_utils import is_test_file

CATEGORY = "ci"

# Simple regex patterns for common secrets (can be expanded)
SECRET_PATTERNS = {
    "AWS_KEY": re.compile(r"(?:AWS|AKIA)[A-Z0-9]{16}"),
    "GH_TOKEN": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "PYPI_TOKEN": re.compile(r"pypi-[a-zA-Z0-9\-_]{50,}"),
    "GENERIC_SECRET": re.compile(
        r"(?:secret|password|passwd|api_key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9\-_{}]{8,}['\"]", re.I
    ),
}


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


def _scan_for_secrets(ctx: ProjectContext) -> list[Issue]:
    """Scan all project files for hardcoded secrets."""
    issues: list[Issue] = []

    # We only scan files collected in the context to avoid node_modules, .git etc.
    for file_path in ctx.python_files:
        if is_test_file(file_path, ctx.root):
            continue

        try:
            content = file_path.read_text(errors="ignore")
            for name, pattern in SECRET_PATTERNS.items():
                if pattern.search(content):
                    issues.append(
                        Issue(
                            category=CATEGORY,
                            code=f"SECRET_EXPOSED_{name}",
                            severity=Severity.CRITICAL,
                            title=f"Potential Secret Exposed: {name}",
                            description=f"Possible sensitive credential found in {file_path.relative_to(ctx.root)}",
                            recommendation="Move secrets to environment variables or a secure secret manager (e.g. GitHub Secrets).",
                        )
                    )
        except Exception:
            continue

    return issues


def _scan_workflows(ctx: ProjectContext) -> list[Issue]:
    """Scan CI workflow files for insecure patterns."""
    issues: list[Issue] = []

    workflow_dirs = [
        ctx.root / ".github" / "workflows",
        ctx.root / ".gitlab-ci.yml",
    ]

    for path in workflow_dirs:
        if path.exists():
            if path.is_file():
                _check_workflow_file(path, issues, ctx)
            else:
                for f in path.glob("*.yml"):
                    _check_workflow_file(f, issues, ctx)
                for f in path.glob("*.yaml"):
                    _check_workflow_file(f, issues, ctx)

    return issues


def _check_workflow_file(file_path: Path, issues: list[Issue], ctx: ProjectContext):
    """Check a single workflow file for best practices."""
    try:
        content = file_path.read_text(errors="ignore")
        rel_path = file_path.relative_to(ctx.root)

        # Check for unpinned actions (using @master or @main instead of hash)
        if "@master" in content or "@main" in content:
            issues.append(
                Issue(
                    category=CATEGORY,
                    code="CI_UNPINNED_ACTION",
                    severity=Severity.WARNING,
                    title="Unpinned GitHub Action",
                    description=f"Workflow {rel_path} uses unpinned (@main/@master) actions.",
                    recommendation="Pin actions to a specific commit hash or version tag for supply-chain security.",
                )
            )

        # Check for cleartext environment variables that look like secrets
        if re.search(r"env:\s*SECRET_", content, re.I):
            issues.append(
                Issue(
                    category=CATEGORY,
                    code="CI_CLEARTEXT_ENV",
                    severity=Severity.WARNING,
                    title="Potential cleartext secret in workflow",
                    description=f"Workflow {rel_path} defines environment variables that might contain secrets.",
                    recommendation="Ensure sensitive values are passed via ${{ secrets.VARIABLE_NAME }}.",
                )
            )
    except Exception:
        pass
