"""
pydoctor/reports/docs_links.py
───────────────────────────────
Link every issue to the page of the documentation that explains it.

Anchors here must exist on https://pydoctor-docs.thally.app. Specific
troubleshooting entries win; otherwise the issue links to the section of
the scanner reference that produced it.
"""

from __future__ import annotations

from pydoctor.core.report import Issue

DOCS_URL = "https://pydoctor-docs.thally.app"

_BY_CODE: dict[str, str] = {
    "ENV_PACKAGES_UNAVAILABLE": "/guides/troubleshooting#packages-unavailable",
    "ENV_DEPS_NOT_INSTALLED": "/guides/troubleshooting#wrong-python",
    "SEC_SCAN_INCOMPLETE": "/guides/troubleshooting#scan-incomplete",
    "CI_ENV_FILE_COMMITTED": "/guides/troubleshooting#env-file-committed",
    "CI_ENV_FILE_NOT_IGNORED": "/guides/troubleshooting#env-file-committed",
    "CI_PULL_REQUEST_TARGET_CHECKOUT": "/scanners#workflow-checks",
    "CI_SCRIPT_INJECTION": "/scanners#workflow-checks",
    "CI_BROAD_PERMISSIONS": "/scanners#workflow-checks",
    "CI_UNPINNED_ACTION": "/scanners#workflow-checks",
    "CI_CLEARTEXT_ENV": "/scanners#workflow-checks",
    "SEC_VULNERABILITY": "/scanners#severity",
}

_BY_PREFIX: dict[str, str] = {
    "SECRET_EXPOSED_": "/scanners#secret-rules",
}

_BY_CATEGORY: dict[str, str] = {
    "environment": "/scanners#environment",
    "dependencies": "/scanners#dependencies",
    "outdated": "/scanners#outdated-packages",
    "security": "/scanners#security",
    "unused": "/scanners#unused-packages",
    "ci": "/scanners#ci-cd",
}


def docs_url(issue: Issue) -> str:
    """The documentation page for ``issue`` (falls back to the docs home)."""
    path = _BY_CODE.get(issue.code)
    if path is None:
        path = next((p for prefix, p in _BY_PREFIX.items() if issue.code.startswith(prefix)), None)
    if path is None:
        path = _BY_CATEGORY.get(issue.category, "")
    return DOCS_URL + path
