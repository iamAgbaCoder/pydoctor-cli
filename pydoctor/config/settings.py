"""
pydoctor/config/settings.py
────────────────────────────
Central configuration settings for PyDoctor.

All tunable constants live here so that the rest of the codebase never
hard-codes values.  Import this module as the single source of truth.
"""

from __future__ import annotations

import os
from pathlib import Path

# ──────────────────────────────────────────────────────────────
# Cache paths
# ──────────────────────────────────────────────────────────────

# The directory where PyDoctor stores its runtime cache
PYDOCTOR_HOME: Path = Path.home() / ".pydoctor"

# Main cache file (JSON)
CACHE_FILE: Path = PYDOCTOR_HOME / "cache.json"

# Cache TTL in seconds (default: 1 hour)
CACHE_TTL_SECONDS: int = int(os.getenv("PYDOCTOR_CACHE_TTL", "3600"))

# ──────────────────────────────────────────────────────────────
# API endpoints
# ──────────────────────────────────────────────────────────────

# OSV (Open Source Vulnerabilities) batch query endpoint
OSV_API_URL: str = "https://api.osv.dev/v1/querybatch"

# Single-package OSV query
OSV_SINGLE_URL: str = "https://api.osv.dev/v1/query"

# PyPI JSON API for latest version lookups
PYPI_URL_TEMPLATE: str = "https://pypi.org/pypi/{package}/json"

# ──────────────────────────────────────────────────────────────
# Network
# ──────────────────────────────────────────────────────────────

# HTTP request timeout (seconds)
REQUEST_TIMEOUT: int = int(os.getenv("PYDOCTOR_REQUEST_TIMEOUT", "10"))

# Maximum concurrent workers for parallel tasks
MAX_WORKERS: int = int(os.getenv("PYDOCTOR_MAX_WORKERS", "8"))

# ──────────────────────────────────────────────────────────────
# Scanning limits
# ──────────────────────────────────────────────────────────────

# Maximum number of packages to query against OSV in a single batch
OSV_BATCH_SIZE: int = 100

# Minimum Python version considered "supported" (as a tuple)
MIN_PYTHON_VERSION: tuple[int, int] = (3, 8)

# Recommended Python version
RECOMMENDED_PYTHON_VERSION: tuple[int, int] = (3, 11)

# ──────────────────────────────────────────────────────────────
# Severity levels (used across the whole application)
# ──────────────────────────────────────────────────────────────


class Severity:
    """Canonical severity string constants."""

    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ──────────────────────────────────────────────────────────────
# File scanning
# ──────────────────────────────────────────────────────────────

# Python source file extension we care about
PYTHON_EXTENSION: str = ".py"

# Directories to skip when scanning a project tree
IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".venv",
        "venv",
        ".env",
        "env",
        "__pycache__",
        ".git",
        ".tox",
        "dist",
        "build",
        "*.egg-info",
        ".mypy_cache",
        ".pytest_cache",
        "node_modules",
        "site-packages",
    }
)
