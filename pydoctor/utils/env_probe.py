"""
pydoctor/utils/env_probe.py
────────────────────────────
Read facts about the *project's* Python environment.

PyDoctor often runs from a different interpreter than the project it scans
(pipx, ``uv tool``, a global install). Anything that asks PyDoctor's own
``sys`` module, or assumes ``pip`` is installed in the project, then
describes the wrong environment. uv-created environments don't include pip
at all.

This module runs a small, stdlib-only script inside the project's
interpreter and returns what it reports: version, virtualenv status,
installed distributions with their requirements, marker environment, and
pip version (if pip is present).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field

# Runs inside the project's interpreter. Must stay stdlib-only and work on
# every Python version PyDoctor supports scanning.
_PROBE_SCRIPT = r"""
import json, os, platform, sys
import importlib.metadata as md

def _fmt(info):
    v = "%d.%d.%d" % (info.major, info.minor, info.micro)
    if info.releaselevel != "final":
        v += info.releaselevel[0] + str(info.serial)
    return v

out = {
    "executable": sys.executable,
    "version": list(sys.version_info[:3]),
    "prefix": sys.prefix,
    "base_prefix": getattr(sys, "base_prefix", sys.prefix),
    "markers": {
        "implementation_name": sys.implementation.name,
        "implementation_version": _fmt(sys.implementation.version),
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "platform_python_implementation": platform.python_implementation(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
    },
}
dists = {}
for d in md.distributions():
    try:
        name = d.metadata["Name"]
    except Exception:
        name = None
    if not name or name in dists:
        continue
    dists[name] = {"version": d.version, "requires": list(d.requires or [])}
out["distributions"] = dists
try:
    out["pip"] = md.version("pip")
except Exception:
    out["pip"] = None
print(json.dumps(out))
"""


@dataclass
class EnvProbe:
    """Facts reported by the project's own interpreter."""

    executable: str
    version: tuple[int, int, int]
    prefix: str
    base_prefix: str
    markers: dict[str, str] = field(default_factory=dict)
    distributions: dict[str, dict] = field(default_factory=dict)
    pip_version: str | None = None

    @property
    def in_virtualenv(self) -> bool:
        return self.prefix != self.base_prefix

    @property
    def packages(self) -> dict[str, str]:
        """Normalised distribution name → installed version."""
        return {normalise_name(n): d["version"] for n, d in self.distributions.items()}


def normalise_name(name: str) -> str:
    """PEP 503-style normalisation used throughout PyDoctor."""
    return name.lower().replace("_", "-").replace(".", "-")


def probe_environment(python: str, timeout: int = 60) -> tuple[EnvProbe | None, str | None]:
    """
    Run the probe in ``python``.

    Returns ``(probe, None)`` on success or ``(None, reason)`` on failure.
    The probe runs from an empty temporary directory so files in the
    project (for example a local ``json.py``) can't shadow the stdlib.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="pydoctor-probe-") as cwd:
            result = subprocess.run(
                [python, "-c", _PROBE_SCRIPT],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
    except FileNotFoundError:
        return None, f"interpreter not found: {python}"
    except subprocess.TimeoutExpired:
        return None, f"interpreter did not respond within {timeout}s: {python}"
    except OSError as exc:
        return None, f"could not run {python}: {exc}"

    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        return None, f"{python} exited with code {result.returncode}" + (
            f": {detail[-1]}" if detail else ""
        )
    try:
        data = json.loads(result.stdout.strip().splitlines()[-1])
        return (
            EnvProbe(
                executable=data["executable"],
                version=tuple(data["version"]),
                prefix=data["prefix"],
                base_prefix=data["base_prefix"],
                markers=data.get("markers", {}),
                distributions=data.get("distributions", {}),
                pip_version=data.get("pip"),
            ),
            None,
        )
    except (ValueError, KeyError, IndexError) as exc:
        return None, f"unexpected output from {python}: {exc}"
