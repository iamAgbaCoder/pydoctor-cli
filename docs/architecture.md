# 🏗️ PyDoctor Architecture

PyDoctor is built with a focus on **modularity, testability, and speed**. It follows a standard "Collection -> Analysis -> Reporting" pipeline.

## 📂 Project Structure

```text
pydoctor/
├── cli/          # Typer command definitions and user interaction logic
├── core/         # The heart of the engine
│   ├── project.py    # Gathers "ProjectContext" (the snapshot of truth)
│   ├── analyzer.py   # Orchestrates the scanners in parallel
│   └── report.py     # Data structures for Issues and DiagnosisReports
├── scanners/     # Independent diagnostic modules
│   ├── env_scanner.py     # OS, Python, and venv health
│   ├── dependency_scanner.py # Version constraints and conflicts
│   ├── vulnerability_scanner.py # Security flaws via OSV.dev
│   └── unused_package_scanner.py # Import analysis via AST
├── reports/      # Logic for transforming data into beauty
│   ├── table_formatter.py # Rich terminal UI
│   └── json_formatter.py  # Structured exports
├── security/     # Network clients and batch processing for OSV.dev
└── utils/        # Shared low-level helpers (pip, subprocess, AST)
```

## 🔄 The Scanning Lifecycle

1. **Initialization:** The user runs a command. `ProjectContext.from_path()` scans the target directory to identify Python files, dependencies, and environment state.
2. **Orchestration:** The `Analyzer` is instantiated with the context. It initializes the requested scanners.
3. **Execution:** Scanners run concurrently using `ThreadPoolExecutor`. Each scanner produces a list of `Issue` objects.
4. **Aggregation:** The `Analyzer` collects all issues into a `DiagnosisReport`, calculates a health score, and generates a verdict.
5. **Rendering:** The report is passed to either the `TableFormatter` (default) or `JsonFormatter` (`--json`).

## 🛠️ Design Patterns

- **Snapshotting:** We collect all expensive information (like `pip list`) exactly once in the `ProjectContext`.
- **Stateless Scanners:** Scanners are pure functions or classes that take a context and return data. They don't modify the environment.
- **Fail-Safe Networking:** The OSV client uses local caching and retry logic to remain functional even when offline or during API hiccups.
