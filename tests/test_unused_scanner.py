"""
tests/test_unused_scanner.py
──────────────────────────────
Unit tests for the unused package scanner (AST-based).
"""

from __future__ import annotations

from pathlib import Path

from pydoctor.core.project import ProjectContext
from pydoctor.scanners import unused_package_scanner


def _make_ctx(
    tmp_path: Path,
    py_files: list[tuple[str, str]] | None = None,
    declared: dict[str, str] | None = None,
) -> ProjectContext:
    """
    Build a ProjectContext with specific py files and declared deps.

    py_files: list of (filename, content) tuples to write to tmp_path.
    declared: dict of declared package names.
    """
    python_files: list[Path] = []

    if py_files:
        for name, content in py_files:
            fpath = tmp_path / name
            fpath.write_text(content, encoding="utf-8")
            python_files.append(fpath)

    return ProjectContext(
        root=tmp_path,
        python_files=python_files,
        installed_packages={},
        declared_deps=declared or {},
    )


class TestUnusedPackageScanner:
    def test_detects_unused_package(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import flask\nimport requests\n")],
            declared={"flask": "", "requests": "", "pandas": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        unused = [i for i in issues if i.code == "UNUSED_PACKAGE"]
        pkg_names = [i.package for i in unused]
        assert "pandas" in pkg_names

    def test_no_unused_when_all_imported(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import flask\nimport requests\n")],
            declared={"flask": "", "requests": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        assert any(i.code == "UNUSED_NONE_FOUND" for i in issues)

    def test_no_requirements_raises_info(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import flask\n")],
            declared={},  # empty → no requirements.txt
        )
        issues = unused_package_scanner.scan(ctx)
        assert any(i.code == "UNUSED_NO_DEPS_FILE" for i in issues)

    def test_no_python_files_info(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[],  # no files
            declared={"flask": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        assert any(i.code == "UNUSED_NO_PY_FILES" for i in issues)

    def test_stdlib_not_flagged_as_unused(self, tmp_path):
        """os, sys should never appear as unused packages."""
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "import os\nimport sys\n")],
            declared={"os": "", "sys": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        unused = [i for i in issues if i.code == "UNUSED_PACKAGE"]
        pkg_names = [i.package for i in unused]
        # stdlib modules should be excluded
        assert "os" not in pkg_names
        assert "sys" not in pkg_names

    def test_from_import_detected(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "from flask import Flask\n")],
            declared={"flask": "", "requests": ""},
        )
        issues = unused_package_scanner.scan(ctx)
        unused = [i for i in issues if i.code == "UNUSED_PACKAGE"]
        pkg_names = [i.package for i in unused]
        # flask is imported via from-import, requests is not
        assert "requests" in pkg_names
        assert "flask" not in pkg_names


class TestFrameworkAwareDetection:
    """Dependencies used without a plain ``import`` must not be flagged."""

    def test_import_name_differs_from_distribution(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            unused_package_scanner,
            "_distribution_map",
            lambda ctx: {"decouple": ["python-decouple"]},
        )
        ctx = _make_ctx(
            tmp_path,
            py_files=[("settings.py", "from decouple import config\n")],
            declared={"python-decouple": ""},
        )
        unused = [i.package for i in unused_package_scanner.scan(ctx) if i.code == "UNUSED_PACKAGE"]
        assert "python-decouple" not in unused

    def test_module_path_strings_count_as_usage(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            unused_package_scanner,
            "_distribution_map",
            lambda ctx: {
                "whitenoise": ["whitenoise"],
                "corsheaders": ["django-cors-headers"],
                "django_redis": ["django-redis"],
            },
        )
        settings = (
            'INSTALLED_APPS = ["corsheaders"]\n'
            'MIDDLEWARE = ["whitenoise.middleware.WhiteNoiseMiddleware"]\n'
            'CACHES = {"default": {"BACKEND": "django_redis.cache.RedisCache"}}\n'
        )
        ctx = _make_ctx(
            tmp_path,
            py_files=[("settings.py", settings)],
            declared={"whitenoise": "", "django-cors-headers": "", "django-redis": "", "six": ""},
        )
        unused = [i.package for i in unused_package_scanner.scan(ctx) if i.code == "UNUSED_PACKAGE"]
        assert unused == ["six"]

    def test_arbitrary_strings_do_not_mark_packages_used(self, tmp_path, monkeypatch):
        monkeypatch.setattr(unused_package_scanner, "_distribution_map", lambda ctx: {})
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", 'GREETING = "six"\n')],
            declared={"six": ""},
        )
        unused = [i.package for i in unused_package_scanner.scan(ctx) if i.code == "UNUSED_PACKAGE"]
        assert unused == ["six"]

    def test_server_named_in_procfile_is_used(self, tmp_path, monkeypatch):
        monkeypatch.setattr(unused_package_scanner, "_distribution_map", lambda ctx: {})
        (tmp_path / "Procfile").write_text("web: gunicorn app.wsgi\n", encoding="utf-8")
        ctx = _make_ctx(
            tmp_path,
            py_files=[("main.py", "x = 1\n")],
            declared={"gunicorn": "", "uvicorn": ""},
        )
        unused = [i.package for i in unused_package_scanner.scan(ctx) if i.code == "UNUSED_PACKAGE"]
        assert unused == ["uvicorn"]

    def test_title_has_no_rich_markup(self, tmp_path):
        ctx = _make_ctx(tmp_path, py_files=[("main.py", "import os\n")], declared={"pandas": ""})
        for issue in unused_package_scanner.scan(ctx):
            assert "[dim]" not in issue.title and "[/]" not in issue.title
