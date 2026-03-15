<div align="center">

# PyDoctor CLI (Command Line Interface)

**PyDoctor** is a standalone, developer-friendly diagnostic assistant for Python environments. It acts like a personal physician for your code — scanning your project and environment to prescribe fixes for misconfigurations, dependencies, and security vulnerabilities.

[![CI Status](https://github.com/iamAgbaCoder/pydoctor-cli/actions/workflows/publish.yml/badge.svg)](https://github.com/iamAgbaCoder/pydoctor-cli/actions)
[![PyPI version](https://img.shields.io/pypi/v/pydoctor-cli.svg?color=blue&style=flat-square)](https://pypi.org/project/pydoctor-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydoctor-cli.svg?style=flat-square)](https://pypi.org/project/pydoctor-cli/)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange.svg?style=flat-square)](LICENSE)

</div>

---

## 🧭 Navigation

- [Project Description](#-project-description)
- [Release History](#-release-history)
- [Quick Start](#-installation)
- [Usage](#-usage)
- [Development](#-development-setup)

---

## Project Description

PyDoctor isn't just a scanner; it's a complete remediation tool that performs static analysis on your project files and cross-references your environment against live security databases.

### Key Features

- **Environment Analysis**: Detects missing virtualenvs, outdated pip, or deprecated Python versions.
- **Dependency Fix**: Automatically resolves conflicts and installs missing packages.
- **Security**: Integrates with [OSV.dev API](https://osv.dev/) to check against known CVEs/GHSAs.
- **Unused Detection**: Identifies declared packages that are never imported.
- **Multi-Manager**: Intelligent support for **pip**, **Poetry**, **uv**, and **pdm**.
- **Rich UI**: Beautiful progress spinners, icons, and color-coded severities.

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

### Automated Fixes

Let PyDoctor perform the heavy lifting. It will offer to install missing packages, upgrade outdated ones, and clean up your environment.

```bash
pydoctor fix
```

---

## Release History

### v2.0.0

- **🚀 Major UI/UX Revamp**: Introduced a premium "kernel/hacker" aesthetic with boxed reports, dynamic progress animations, and improved readability.
- **🛡️ CI/CD Guard Mode**: New `pydoctor check --ci` command to detect exposed secrets (AWS, GitHub, PyPI tokens) and insecure workflow patterns in GitHub Actions/GitLab CI.
- **🐳 Docker Support**: New `pydoctor docker` command to diagnose Python issues inside containers and audit Dockerfiles.
- **🐙 GitHub Integration**: New `pydoctor github` command for repository-wide health scans and local git configuration audits.
- **📈 Advanced Health Scoring**: Refined the 0-100 scoring algorithm with granular penalties for security vulnerabilities and CI/CD risks.
- **⚡ Performance Boost**: Parallel execution engine for scanning large codebases faster.
- **🔍 Smart Environment Detection**: Now automatically prompts users when no venv is found, preventing accidental system-wide changes.
- **🎯 Context-Aware Reporting**: Targeted commands (like `pydoctor scan-unused` or `pydoctor github`) now intelligently suppress unrelated scanner noise.
- **🧠 OSV Deep-Fetching**: Overcame upstream OSV API batch limits by implementing dynamic real-time fetching and caching of full vulnerability advisories natively.
- **🔗 Transitive Dependency Tracking**: PyDoctor now uniquely segregates mathematical/transitive dependencies from pure unused bloat, effectively preventing `pydoctor fix` from uninstalling required sub-packages.
- **🛠️ Refined Git Discovery**: Utilizes native git heuristics (`--is-inside-work-tree` & `--show-toplevel`) to flawlessly map out project roots and repository states, even when scanning from deeply nested sub-directories.
- **🔮 Dynamic Fix Suggestions**: The `🚀 Next Steps` terminal guide now dynamically rules out the currently running command and gracefully self-hides when a project achieves a perfect 100/100 health rating.

### v0.1.3

- **Enhanced Package Detection**: Pydoctor now intelligently detects and uses your project's specific virtual environment (Poetry, UV, PDM, or standard venv) to run all scans and diagnoses.
- **Improved Architecture**: Refactored core modules to reduce complexity and improve maintainability (resolved C901 linting errors).
- **Fix Rendering Errors**: Resolved issues with undefined verbose detail renderers in the CLI.

### v0.1.2

- **Maintenance**: Minor internal fixes and linting improvements for CI/CD stability.
- **Professional Meta**: Revamped `pyproject.toml` with complete author metadata and SEO keywords.

### v0.1.1

- **Bug Fixes**: Minor improvements to dependency scanning reliability.
- **Metadata Update**: Initial professional README branding.

### v0.1.0

- **Initial Release**: Core diagnostic engine with support for Environment, Dependencies, Outdated Packages, Security, and Unused Package scans.
- **Remediation**: Initial support for auto-fixing issues via `pydoctor fix`.

---

## Verified Details

- **Homepage**: [GitHub Repository](https://github.com/iamAgbaCoder/pydoctor-cli)
- **Issue Tracker**: [GitHub Issues](https://github.com/iamAgbaCoder/pydoctor-cli/issues)
- **Repository**: [iamAgbaCoder/pydoctor-cli](https://github.com/iamAgbaCoder/pydoctor-cli)

---

## 👥 Maintainers

- **Favour Bamgboye** ([@iamAgbaCoder](https://github.com/iamAgbaCoder))

## 📄 Meta

- **License**: Apache License 2.0
- **Author**: Favour Bamgboye
- **Requires**: Python >=3.10
- **Classifiers**:
  - Development Status :: 4 - Beta
  - Intended Audience :: Developers
  - License :: OSI Approved :: Apache Software License
  - Operating System :: OS Independent
  - Programming Language :: Python :: 3
  - Programming Language :: Python :: 3.10
  - Programming Language :: Python :: 3.11
  - Programming Language :: Python :: 3.12
  - Topic :: Software Development :: Quality Assurance

---

<div align="center">

Developed with ❤️ by [Favour Bamgboye](https://iamagbacoder.github.io)

</div>
