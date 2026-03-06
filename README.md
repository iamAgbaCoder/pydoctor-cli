# 🩺 PyDoctor

[![CI](https://github.com/iamAgbaCoder/pydoctor-cli/workflows/CI/badge.svg)](https://github.com/iamAgbaCoder/pydoctor-cli/actions)
[![PyPI version](https://img.shields.io/pypi/v/pydoctor-cli.svg)](https://pypi.org/project/pydoctor-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydoctor-cli.svg)](https://pypi.org/project/pydoctor-cli/)

**PyDoctor** is a premium, developer-friendly diagnostic assistant for Python environments. It acts like a doctor for your code — scanning your project and environment to prescribe fixes for misconfigurations, dependencies, and security vulnerabilities.

---

## 🔥 Features

- **Environment Analysis**: Detects issues like missing virtual environments, outdated pip, or deprecated Python versions.
- **Dependency Conflicts**: Automatically runs resolver checks (via pip check) and flags conflicting requirements or missing packages.
- **Outdated Packages**: Scans your environment and lets you know what could be upgraded.
- **Security & Vulnerabilities**: Integrates with the [OSV.dev API](https://osv.dev/) to check all installed packages against known CVEs and GHSAs. Responses are cached locally for speed.
- **Unused Package Detection**: Parses your codebase's AST to identify packages listed in `requirements.txt` that are never actually imported.
- **Beautiful CLI UI**: Powered by [Rich](https://github.com/Textualize/rich) (Icons, Progress Spinners, Color-coded severities).
- **Speed**: Executes I/O-bound operations across concurrent thread pools.
- **JSON Reporting**: Full structured output support via `--json` for CI/CD pipelines.
- **Automated Remediation**: Run `pydoctor fix` to automatically perform upgrades, remove unused packages, and initialize virtual environments.

---

## 📦 Installation

PyDoctor requires **Python 3.10+**.

```bash
pip install pydoctor-cli
```

_(Or install it via pipx to keep it globally available but isolated):_

```bash
pipx install pydoctor-cli
```

---

## ⚡ Usage

### Full Diagnosis

Run the full suite of checks in your current directory:

```bash
pydoctor diagnose
```

Or specify a path:

```bash
pydoctor diagnose --path /path/to/project
```

### Targeted Scans

```bash
# Check the Python environment (Python version, venv, pip)
pydoctor check-env

# Scan dependency tree constraints
pydoctor scan-deps

# Check for security vulnerabilities via OSV
pydoctor scan-security

# Detect unused packages by parsing your .py imports
pydoctor scan-unused
```

### Automated Fixes

```bash
# Have PyDoctor automatically attempt to resolve issues
pydoctor fix

# Run without prompting for confirmation
pydoctor fix --no-safe
```

### JSON Output (CI/CD)

```bash
pydoctor diagnose --json > report.json
```

---

## 🔬 Architecture

PyDoctor is designed with a **clean, modular architecture** making it easy to mock, test, and extend.

```text
pydoctor/
├── cli/          # Handlers for Typer CLI commands
├── core/         # Core data-models (Issue, Report, ProjectContext) and the orchestrator Analyzer
├── scanners/     # Individual check modules (Env, Deps, Vulns, Outdated, Unused)
├── reports/      # Formatting logic (Terminal Rich tables + JSON exports)
├── cache/        # Local JSON cache management for networks API calls
├── security/     # OSV.dev batch API integration
└── utils/        # Shared system/pip/AST-parsing utils
```

Each scanner takes a snapshot `ProjectContext` and yields standard `Issue` dataclasses which are aggregated by the report engine.

---

## 🛠️ Development Setup

Using `pyproject.toml` definition:

```bash
git clone https://github.com/iamAgbaCoder/pydoctor-cli.git
cd pydoctor-cli

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run type checker and linter
mypy pydoctor
ruff check pydoctor
```

## 📜 License

MIT License.
python -m pip install -e ".[dev]"
