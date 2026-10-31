"""
tests/test_github_action.py
───────────────────────────
The composite action's shell scripts: version resolution and exit handling.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# These scripts run under GitHub Actions' own bash (Git Bash on Windows
# runners). On a Windows test runner, `bash` on PATH is often WSL, which can't
# read Windows paths, so the scripts are tested on Linux and macOS only.
pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or sys.platform == "win32",
    reason="needs a POSIX bash (the action itself runs under Git Bash on Windows)",
)


def _install_spec(**env) -> str:
    result = subprocess.run(
        ["bash", str(ROOT / "action" / "install.sh")],
        env={**os.environ, "PYDOCTOR_DRY_RUN": "1", **env},
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.mark.parametrize(
    "env,expected",
    [
        ({"ACTION_REF": "v2"}, "pydoctor-cli>=2,<3"),
        ({"ACTION_REF": "v2.3.0"}, "pydoctor-cli==2.3.0"),
        ({"ACTION_REF": "main"}, "pydoctor-cli"),
        ({"ACTION_REF": "v2", "PYDOCTOR_VERSION": "2.2.0"}, "pydoctor-cli==2.2.0"),
        ({"PYDOCTOR_VERSION": "local", "GITHUB_ACTION_PATH": "/x/action"}, "/x/action"),
    ],
)
def test_version_resolution(env, expected):
    assert _install_spec(**env) == expected


def _scan(tmp_path, exit_code: int, write_sarif: bool):
    fake = tmp_path / "pydoctor"
    sarif = tmp_path / "out.sarif"
    body = f'touch "{sarif}"\n' if write_sarif else ""
    fake.write_text(f'#!/usr/bin/env bash\necho "$@" > "{tmp_path}/args"\n{body}exit {exit_code}\n')
    fake.chmod(0o755)
    out = tmp_path / "github_output"
    result = subprocess.run(
        ["bash", str(ROOT / "action" / "scan.sh")],
        env={
            **os.environ,
            "PYDOCTOR_BIN": str(fake),
            "INPUT_CI_ONLY": "true",
            "INPUT_ARGS": "--no-baseline --verbose",
            "INPUT_SARIF_FILE": str(sarif),
            "GITHUB_OUTPUT": str(out),
        },
        capture_output=True,
        text=True,
    )
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
    return result.returncode, outputs, (tmp_path / "args").read_text().split()


def test_findings_are_recorded_without_failing_the_step(tmp_path):
    code, outputs, args = _scan(tmp_path, exit_code=1, write_sarif=True)
    assert code == 0  # the upload step must still run
    assert outputs["exit-code"] == "1" and outputs["sarif-written"] == "true"
    assert args[:3] == ["check", "--path", "."]
    assert "--ci" in args and args[-2:] == ["--no-baseline", "--verbose"]


def test_missing_sarif_is_reported(tmp_path):
    _, outputs, _ = _scan(tmp_path, exit_code=2, write_sarif=False)
    assert outputs["exit-code"] == "2" and outputs["sarif-written"] == "false"
