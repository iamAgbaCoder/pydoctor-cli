"""
tests/test_ci_scanner.py
────────────────────────
Secret and workflow detection. Each "should not flag" case below is a real
line from a popular open-source project that an earlier draft flagged.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from pydoctor.core.project import ProjectContext
from pydoctor.scanners.ci_scanner import scan
from pydoctor.security.secrets import scan_text


def _codes(issues):
    return sorted(i.code for i in issues if i.severity != "ok")


def _ctx(root: Path, files: list[Path] | None = None) -> ProjectContext:
    return ProjectContext(root=root, python_files=files or [])


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


# Fake credentials are assembled at runtime, so this file never contains a
# string in a real provider's format. Secret scanners (GitHub push
# protection included) rightly reject such strings even in tests.
FAKE_AWS = "AK" + "IA" + "1234567890ABCDEF"
FAKE_STRIPE = "sk_" + "live_" + "51HxYzAbCdEfGhIjKlMnOpQrStUvWx"
FAKE_OPENAI = "sk-" + "proj-" + "AbCdEf1234567890AbCdEf1234567890"
FAKE_ANTHROPIC = "sk-" + "ant-" + "api03-AbCdEf1234567890AbCdEf"
FAKE_GITHUB = "gh" + "p_" + "a1B2c3D4e5" * 4
FAKE_KEY_HEADER = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"


# ── Secrets ────────────────────────────────────────────────────


def test_scan_for_secrets(tmp_path):
    secret_file = tmp_path / "config.py"
    secret_file.write_text(f'AWS_SECRET_KEY = "{FAKE_AWS}"')
    issues = scan(_ctx(tmp_path, [secret_file]))
    finding = next(i for i in issues if i.code == "SECRET_EXPOSED_AWS_KEY")
    assert finding.severity == "critical"
    assert finding.extra["line"] == 1
    assert FAKE_AWS not in finding.description  # redacted


@pytest.mark.parametrize(
    "line,code",
    [
        ("SECRET_KEY = 'django-insecure-9x!q@7k#z$2m^p&w*r(t)y_u+i=o-0v'", "APP_SECRET_KEY"),
        (f'STRIPE = "{FAKE_STRIPE}"', "STRIPE_KEY"),
        (f'KEY = "{FAKE_OPENAI}"', "OPENAI_KEY"),
        (f'KEY = "{FAKE_ANTHROPIC}"', "ANTHROPIC_KEY"),
        (f'T = "{FAKE_GITHUB}"', "GH_TOKEN"),
        ('URL = "postgres://admin:Sup3rS3cret@db.example.com/prod"', "DATABASE_URL"),
        (FAKE_KEY_HEADER, "PRIVATE_KEY"),
        ('db_password = "Xk82mPq0vL3z"', "GENERIC_SECRET"),
    ],
)
def test_detects_common_secrets(tmp_path, line, code):
    assert [f.code for f in scan_text(tmp_path / "settings.py", line)] == [code]


@pytest.mark.parametrize(
    "line",
    [
        "    if len(findings) > MAX_SECRET_FINDINGS:",  # name merely contains SECRET
        "  sessionSecret: 'THALLY_READER_SESSION_SECRET',",  # value is an env var name
        "        username, password = get_auth_from_url(proxy)",
        '__author_email__ = "me@kennethreitz.org"',
        "SECRET_KEY = config('SECRET_KEY')",
        'API_KEY = "your-api-key-here"',
        'KEY = "AKIAIOSFODNN7EXAMPLE"',  # AWS's documented example key
        'URL = "postgres://postgres:postgres@localhost:5432/app"',  # local dev database
        '"hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w"',
        f'token = "{FAKE_STRIPE}"  # pydoctor: ignore',
    ],
)
def test_does_not_flag_lookalikes(tmp_path, line):
    assert scan_text(tmp_path / "app.py", line) == []


def test_documentation_only_reports_provider_keys(tmp_path):
    doc = "Set ``SECRET_KEY = '192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc'``\n"
    doc += 'password = "Xk82mPq0vL3z"\n'
    assert scan_text(tmp_path / "docs" / "config.rst", doc) == []
    real = f'STRIPE = "{FAKE_STRIPE}"'
    assert [f.code for f in scan_text(tmp_path / "README.md", real)] == ["STRIPE_KEY"]


def test_env_style_config_values(tmp_path):
    text = f"DEBUG=1\nOPENAI_API_KEY={FAKE_OPENAI}\nAPP_TOKEN=9f8e7d6c5b4a3f2e\n"
    codes = [f.code for f in scan_text(tmp_path / ".env", text)]
    assert codes == ["OPENAI_KEY", "GENERIC_SECRET"]


# ── .env files under git ───────────────────────────────────────


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    return tmp_path


def test_committed_env_file_is_flagged(repo):
    (repo / ".env").write_text("DEBUG=1\n")
    _git(repo, "add", ".env")
    assert "CI_ENV_FILE_COMMITTED" in _codes(scan(_ctx(repo)))


def test_unignored_env_file_is_a_warning(repo):
    (repo / ".env").write_text("DEBUG=1\n")
    issues = scan(_ctx(repo))
    finding = next(i for i in issues if i.code == "CI_ENV_FILE_NOT_IGNORED")
    assert finding.severity == "warning"


def test_ignored_env_template_and_test_fixture_are_fine(repo):
    (repo / ".gitignore").write_text(".env\n")
    (repo / ".env").write_text(f"STRIPE={FAKE_STRIPE}\n")
    (repo / ".env.example").write_text("STRIPE=" + "sk_" + "live_your_key_here\n")
    (repo / "tests").mkdir()
    (repo / "tests" / ".env").write_text("FOO=bar\n")
    _git(repo, "add", ".gitignore", ".env.example")
    _git(repo, "add", "-f", "tests/.env")  # a committed test fixture
    assert _codes(scan(_ctx(repo))) == []


# ── Workflows ──────────────────────────────────────────────────


def _workflow(root: Path, text: str) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(text)


def test_scan_workflows(tmp_path):
    _workflow(
        tmp_path, "      - uses: actions/checkout@main\n      - uses: actions/setup-python@v5\n"
    )
    issues = [i for i in scan(_ctx(tmp_path)) if i.code == "CI_UNPINNED_ACTION"]
    assert len(issues) == 1 and issues[0].extra["line"] == 1


def test_pwn_request_and_script_injection(tmp_path):
    _workflow(
        tmp_path,
        """on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          echo "Building"
          echo "${{ github.event.pull_request.title }}"
      - name: safe
        env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
""",
    )
    codes = _codes(scan(_ctx(tmp_path)))
    assert codes == [
        "CI_BROAD_PERMISSIONS",
        "CI_PULL_REQUEST_TARGET_CHECKOUT",
        "CI_SCRIPT_INJECTION",
    ]


def test_ci_service_passwords_are_not_flagged(tmp_path):
    _workflow(
        tmp_path,
        "services:\n  postgres:\n    env:\n      POSTGRES_PASSWORD: postgres\n"
        "      API_TOKEN: 7f3k9q2m8x1v5b6n\n",
    )
    assert _codes(scan(_ctx(tmp_path))) == ["CI_CLEARTEXT_ENV"]


def test_scan_clean_project(tmp_path):
    issues = scan(_ctx(tmp_path))
    assert len(issues) == 1
    assert issues[0].code == "CI_HEALTHY"
