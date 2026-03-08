"""
pydoctor/utils/subprocess_utils.py
────────────────────────────────────
Safe subprocess helpers.

All subprocess calls in PyDoctor should go through these helpers rather
than calling ``subprocess`` directly.  This ensures:
  • consistent timeout handling
  • clean error propagation
  • captured stdout / stderr for later inspection
  • cross-platform shell avoidance
"""

from __future__ import annotations

import subprocess
import sys


def run_command(
    args: list[str],
    *,
    timeout: int = 30,
    capture_output: bool = True,
    text: bool = True,
    cwd: str | None = None,
    raise_on_error: bool = False,
) -> subprocess.CompletedProcess:
    """
    Execute an external command safely.

    Parameters
    ----------
    args:           Command and its arguments as a list (no shell=True).
    timeout:        Maximum seconds to wait before raising TimeoutExpired.
    capture_output: Capture stdout and stderr (default True).
    text:           Decode output as text (default True).
    cwd:            Working directory for the subprocess.
    raise_on_error: If True, raises CalledProcessError on non-zero exit.

    Returns
    -------
    subprocess.CompletedProcess
        Contains .stdout, .stderr, and .returncode attributes.

    Raises
    ------
    subprocess.TimeoutExpired  – if the command runs longer than ``timeout``.
    subprocess.CalledProcessError – if ``raise_on_error=True`` and exit != 0.
    """
    try:
        result = subprocess.run(
            args,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            cwd=cwd,
        )
        if raise_on_error:
            result.check_returncode()
        return result
    except FileNotFoundError:
        # The executable doesn't exist; return a synthetic failed result
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr=f"Executable not found: {args[0]}",
        )


def run_pip_command(
    pip_args: list[str],
    *,
    timeout: int = 120,
    python_executable: str | None = None,
) -> subprocess.CompletedProcess:
    """
    Run a ``pip`` sub-command via the specified or current Python interpreter.

    Parameters
    ----------
    pip_args: Arguments to pass to pip (e.g. ["list", "--outdated"]).
    timeout:  Seconds before timing out.
    python_executable: Path to python interpreter to use. Defaults to sys.executable.

    Returns
    -------
    subprocess.CompletedProcess
    """
    py = python_executable or sys.executable
    return run_command(
        [py, "-m", "pip"] + pip_args,
        timeout=timeout,
    )
