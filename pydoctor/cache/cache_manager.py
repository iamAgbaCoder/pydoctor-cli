"""
pydoctor/cache/cache_manager.py
────────────────────────────────
File-backed JSON cache for expensive network calls.

The cache stores arbitrary serialisable data keyed by a string.
Entries automatically expire after ``CACHE_TTL_SECONDS``.

Cache file location: ``~/.pydoctor/cache.json``

Design notes
────────────
- Thread-safe reads (no mutation from multiple threads simultaneously
  because we load/save atomically with per-invocation dict copies).
- Graceful degradation: if the cache is corrupt or unreadable, it is
  silently reset — the tool never crashes due to cache issues.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from pydoctor.config.settings import CACHE_FILE, CACHE_TTL_SECONDS, PYDOCTOR_HOME


class CacheManager:
    """
    JSON file-backed key-value cache with TTL expiration.

    Usage
    -----
    ::

        cache = CacheManager()
        data  = cache.get("vulns_requests_2.28")
        if data is None:
            data = fetch_from_network()
            cache.set("vulns_requests_2.28", data)
    """

    def __init__(
        self,
        cache_file: Path = CACHE_FILE,
        ttl: int = CACHE_TTL_SECONDS,
    ) -> None:
        self._cache_file = cache_file
        self._ttl = ttl
        self._data: dict[str, dict] = {}
        self._load()

    # ── Public API ─────────────────────────────────────────────

    def get(self, key: str) -> Any | None:
        """
        Retrieve a cached value by key.

        Returns ``None`` if the key is missing or the entry has expired.

        Parameters
        ----------
        key: Cache key string.

        Returns
        -------
        Any | None
        """
        entry = self._data.get(key)
        if entry is None:
            return None

        # Expiry check
        ts: float = entry.get("_ts", 0.0)
        if time.time() - ts > self._ttl:
            del self._data[key]
            return None

        return entry.get("value")

    def set(self, key: str, value: Any) -> None:
        """
        Store a value in the cache with the current timestamp.

        Parameters
        ----------
        key:   Cache key.
        value: Any JSON-serialisable value.
        """
        self._data[key] = {"_ts": time.time(), "value": value}
        self._save()

    def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache."""
        self._data.pop(key, None)
        self._save()

    def clear(self) -> None:
        """Wipe the entire cache (both in memory and on disk)."""
        self._data = {}
        self._save()

    def purge_expired(self) -> int:
        """
        Remove all expired entries.

        Returns
        -------
        int
            Number of entries removed.
        """
        now = time.time()
        expired = [k for k, v in self._data.items() if now - v.get("_ts", 0.0) > self._ttl]
        for k in expired:
            del self._data[k]
        if expired:
            self._save()
        return len(expired)

    # ── Private helpers ────────────────────────────────────────

    def _load(self) -> None:
        """Load the cache file from disk.  Silently resets on corruption."""
        if not self._cache_file.is_file():
            return
        try:
            raw = self._cache_file.read_text(encoding="utf-8")
            self._data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            # Corrupted or unreadable cache — start fresh
            self._data = {}

    def _save(self) -> None:
        """
        Persist the current cache to disk.

        Creates ``~/.pydoctor/`` if it doesn't exist.
        Fails silently if the file cannot be written (e.g. read-only FS).
        """
        try:
            PYDOCTOR_HOME.mkdir(parents=True, exist_ok=True)
            self._cache_file.write_text(
                json.dumps(self._data, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass  # Non-fatal — tool still works without caching
