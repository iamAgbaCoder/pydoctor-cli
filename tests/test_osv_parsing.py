"""
tests/test_osv_parsing.py
─────────────────────────
Severity and fix-version extraction from real-shaped OSV records.
"""

from __future__ import annotations

import pytest

from pydoctor.cache.cache_manager import CacheManager
from pydoctor.config.settings import Severity
from pydoctor.scanners.vulnerability_scanner import _map_severity
from pydoctor.security import osv_client
from pydoctor.security.cvss import base_score, rating
from pydoctor.security.osv_client import (
    OSVClient,
    _extract_fixed_version,
    _extract_severity,
)

# Reference scores from the FIRST CVSS v3.1 calculator.
CVSS_CASES = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1, "LOW"),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
]


@pytest.mark.parametrize("vector,score,label", CVSS_CASES)
def test_cvss_base_score_matches_reference(vector, score, label):
    assert base_score(vector) == score
    assert rating(score) == label


def test_invalid_or_unsupported_vectors_are_not_scored():
    assert base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None  # CVSS v2
    assert base_score("CVSS:3.1/AV:X") is None


def test_low_vulnerability_is_no_longer_reported_as_critical():
    """2.1.0 labelled any network/no-privilege vector HIGH, shown as critical."""
    raw = {"severity": [{"type": "CVSS_V3", "score": CVSS_CASES[5][0]}]}
    label, score = _extract_severity(raw)
    assert (label, score) == ("LOW", 3.1)
    assert _map_severity(label) == Severity.WARNING


def test_github_moderate_maps_to_medium():
    label, _ = _extract_severity({"database_specific": {"severity": "MODERATE"}})
    assert label == "MEDIUM"
    assert _map_severity("MODERATE") == Severity.ERROR


def test_cvss_v4_only_is_unknown_not_guessed():
    raw = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"}]}
    assert _extract_severity(raw) == ("UNKNOWN", None)


DJANGO_ADVISORY = {
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "Django"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "5.1"},
                        {"fixed": "5.1.4"},
                        {"introduced": "0"},
                        {"fixed": "4.2.17"},
                        {"introduced": "5.0"},
                        {"fixed": "5.0.10"},
                    ],
                },
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
            ],
        }
    ]
}


@pytest.mark.parametrize(
    "installed,expected",
    [("5.1.2", "5.1.4"), ("5.0.3", "5.0.10"), ("4.2.1", "4.2.17"), ("4.2.20", "5.0.10")],
)
def test_fixed_version_comes_from_the_installed_release_line(installed, expected):
    assert _extract_fixed_version(DJANGO_ADVISORY, "django", installed) == expected


def test_no_fix_in_installed_line_returns_empty():
    raw = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}]}],
            }
        ]
    }
    assert _extract_fixed_version(raw, "pkg", "2.5") == ""


def test_other_packages_in_the_advisory_are_ignored():
    raw = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "other"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0"}]}
                ],
            },
            DJANGO_ADVISORY["affected"][0],
        ]
    }
    assert _extract_fixed_version(raw, "django", "5.1.2") == "5.1.4"


class _Resp:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def _client(tmp_path, monkeypatch, read_cache=True):
    monkeypatch.setattr(osv_client.time, "sleep", lambda _s: None)
    return OSVClient(cache=CacheManager(cache_file=tmp_path / "c.json"), read_cache=read_cache)


def test_withdrawn_advisories_are_skipped_and_sparse_ones_fetched(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    batch = {"results": [{"vulns": [{"id": "GHSA-live"}, {"id": "GHSA-gone"}]}]}
    full = {
        "GHSA-live": {
            "id": "GHSA-live",
            "summary": "real",
            "database_specific": {"severity": "LOW"},
        },
        "GHSA-gone": {"id": "GHSA-gone", "summary": "x", "withdrawn": "2026-01-01T00:00:00Z"},
    }
    fetched = []
    monkeypatch.setattr(client._session, "post", lambda *a, **k: _Resp(batch))

    def get(url, timeout):
        vid = url.rsplit("/", 1)[-1]
        fetched.append(vid)
        return _Resp(full[vid])

    monkeypatch.setattr(client._session, "get", get)
    records = client.query_packages({"pkg": "1.0"})
    assert [r.vuln_id for r in records] == ["GHSA-live"]
    assert sorted(fetched) == ["GHSA-gone", "GHSA-live"]


def test_no_cache_ignores_cached_results_but_refreshes_them(tmp_path, monkeypatch):
    calls = []
    batch = {"results": [{"vulns": []}]}

    def post(*a, **k):
        calls.append(1)
        return _Resp(batch)

    first = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(first._session, "post", post)
    first.query_packages({"pkg": "1.0"})
    cached = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(cached._session, "post", post)
    cached.query_packages({"pkg": "1.0"})
    bypass = _client(tmp_path, monkeypatch, read_cache=False)
    monkeypatch.setattr(bypass._session, "post", post)
    bypass.query_packages({"pkg": "1.0"})
    assert len(calls) == 2  # first run and the --no-cache run; the middle run hit the cache
