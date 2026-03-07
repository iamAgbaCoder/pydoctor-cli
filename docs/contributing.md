# 🏥 Contributing to PyDoctor

Thank you for helping make PyDoctor better! As a professional developer tool, we maintain high standards for code quality and documentation.

## 🚀 Getting Started

1. **Fork and Clone:**

   ```bash
   git clone https://github.com/iamAgbaCoder/pydoctor-cli.git
   cd pydoctor-cli
   ```

2. **Setup Environment:**
   We recommend using a virtual environment and installing in editable mode:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

## 🛠️ Development Standards

### 🧬 Code Style

We use **Ruff** for linting and **Black** for formatting.

- Run `black pydoctor tests` to format.
- Run `ruff check pydoctor` to lint.

### 🧪 Testing

Every new feature or bug fix must include a test.

- Run `pytest` to execute the suite.
- Run `pytest --cov=pydoctor` to check coverage.

### 🏷️ Typing

We use **Mypy** for static type checking. All public APIs must have type hints.

- Run `mypy pydoctor`.

## 📬 Pull Request Process

1. Create a descriptive branch: `feat/new-scanner` or `fix/osv-timeout`.
2. Ensure all tests pass and coverage hasn't dropped.
3. Update `CHANGELOG.md` (if applicable).
4. Submit the PR with a clear description of the "Diagnosis" (the problem) and "Treatment" (your solution).

---

Healthy code makes for happy developers! 🩺
