.PHONY: help install dev test lint format check build publish clean

help:
	@echo "PyDoctor Makefile"
	@echo "-----------------"
	@echo "install  - Install pydoctor"
	@echo "dev      - Install for development"
	@echo "test     - Run tests with coverage"
	@echo "lint     - Run ruff linter and mypy"
	@echo "format   - Format code with black"
	@echo "check    - Run all CI checks (lint + test)"
	@echo "build    - Build final wheel/sdist packages"
	@echo "publish  - Upload to PyPI"
	@echo "clean    - Remove build/cache files"

install:
	python -m pip install .

dev:
	python -m pip install -e ".[dev]"

test:
	pytest --cov=pydoctor --cov-report=term-missing

lint:
	ruff check pydoctor tests
	mypy pydoctor

format:
	black pydoctor tests

check: format lint test

build: clean
	python -m build

publish: build
	twine upload dist/*

clean:
	rm -rf dist build *.egg-info .pytest_cache .mypy_cache .ruff_cache coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} +
