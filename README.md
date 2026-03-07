<div align="center">

# 🩺 PyDoctor

**PyDoctor** is a premium, developer-friendly diagnostic assistant for Python environments. It acts like a personal physician for your code — scanning your project and environment to prescribe fixes for misconfigurations, dependencies, and security vulnerabilities.

[![CI Status](https://github.com/iamAgbaCoder/pydoctor-cli/actions/workflows/publish.yml/badge.svg)](https://github.com/iamAgbaCoder/pydoctor-cli/actions)
[![PyPI version](https://img.shields.io/pypi/v/pydoctor-cli.svg?color=blue&style=flat-square)](https://pypi.org/project/pydoctor-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydoctor-cli.svg?style=flat-square)](https://pypi.org/project/pydoctor-cli/)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange.svg?style=flat-square)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

[Features](#-features) • [Quick Start](#-installation) • [Usage](#-usage) • [Configuration](#-configuration) • [Architecture](#-architecture)

</div>

---

## 📸 How it looks

PyDoctor provides a beautiful, color-coded interface powered by [Rich](https://github.com/Textualize/rich).

```text
🩺 PyDoctor Diagnosis Report

─────────────────────────────────── Results ────────────────────────────────────
  Environment             ⚠ 1 issue detected
  Dependencies            ✔ Healthy
  Outdated Packages       ⚠ 3 detected
  Security                ⚠ 2 vulnerabilities Found
  Unused Packages         ⚠ 5 detected

❤️  Project Health Score
████████████░░░░░░░░ 60%

🩺 Doctor's Verdict
Your project contains severe risks that should be fixed before production.
```

---

## ✨ Features

PyDoctor isn't just a scanner; it's a complete remediation tool.

- **🔍 Env Analysis**: Detects missing virtualenvs, outdated pip, or deprecated Python versions.
- **🏗️ Dependency Fix**: Automatically resolves conflicts and installs missing packages.
- **🛡️ Security**: Integrates with [OSV.dev API](https://osv.dev/) to check against known CVEs/GHSAs.
- **🧹 Unused Detection**: Uses AST analysis to identify declared packages that are never imported.
- **🚀 Multi-Manager**: Intelligent support for **pip**, **Poetry**, **uv**, and **pdm**.
- **🎨 Rich UI**: Beautiful progress spinners, icons, and color-coded severities.
- **🤖 CI/CD Ready**: Structured JSON output and non-zero exit codes for failing health scores.

---

## 📦 Installation

PyDoctor requires **Python 3.10+**. For the best experience, we recommend using `pipx`.

```bash
# Recommended: Install globally in an isolated environment
pipx install pydoctor-cli

# Standard pip installation
pip install pydoctor-cli
```

---

## ⚡ Usage

### Full Diagnosis

Run a comprehensive check-up on your project.

```bash
pydoctor diagnose
```

### Targeted Scans

Need a second opinion on a specific area?

```bash
pydoctor check-env       # Check Python, venv, and pip
pydoctor scan-deps       # Scan dependency constraints
pydoctor scan-security   # Check for security vulnerabilities
pydoctor scan-unused     # Identify imports that aren't used
```

### 🔨 The Surgeon: Automated Fixes

Let PyDoctor perform the heavy lifting. It will offer to install missing packages, upgrade outdated ones, and clean up your environment.

```bash
pydoctor fix
```

---

## ⚙️ Configuration

PyDoctor works out of the box with zero configuration. For advanced control, add a `[tool.pydoctor]` section to your `pyproject.toml`:

```toml
[tool.pydoctor]
# Packages to ignore during unused dependency scanning
ignored_packages = ["ruff", "mypy", "pytest"]

# Minimum health score required for CI to pass (0-100)
min_health_score = 80
```

---

## 🔬 Architecture

PyDoctor is built with a clean, modular engine designed for extensibility. It uses a **Project Context** to share metadata across specialized scanners for environment, dependencies, security, and usage.

### 📂 Project Structure

- `pydoctor/cli/`: Typer command handlers.
- `pydoctor/core/`: The core engine (Analyzer, Context, logic).
- `pydoctor/scanners/`: Individual diagnostic modules.
- `pydoctor/reports/`: Visual and JSON formatting.
- `pydoctor/utils/`: High-performance pip, subprocess, and AST helpers.

---

## 🛠️ Development Setup

We welcome contributions! Setting up the environment is simple:

```bash
git clone https://github.com/iamAgbaCoder/pydoctor-cli.git
cd pydoctor-cli

python -m venv .venv
# Activate venv, then:
pip install -e ".[dev]"

# Verify with tests
pytest
```

---

<div align="center">

Developed with ❤️ by [Favour Bamgboye](https://iamagbacoder.github.io)

[Apache License 2.0](LICENSE)

</div>
