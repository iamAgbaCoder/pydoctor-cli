# 📟 PyDoctor Command Reference

PyDoctor provides a suite of commands designed to be used both by humans and CI systems.

## 🩺 Core Diagnosis

### `pydoctor diagnose`

The master command. Runs every scanner available and provides a comprehensive report.

- **Flags:**
  - `--path, -p`: Directory to scan (default: `.`)
  - `--json, -j`: Output results as raw JSON.
  - `--verbose, -v`: Show full issue histories and trace.
  - `--no-cache`: Force refresh security data from OSV.dev.

---

## 🔬 Targeted Scans

### `pydoctor check-env`

Checks the health of your Python installation and virtual environment.

- Verifies Python version.
- Detects virtual environment presence.
- Checks `pip` version.
- Reports OS and architecture details.

### `pydoctor scan-security`

Queries the [OSV.dev](https://osv.dev) database for vulnerabilities in your installed packages.

- Uses batch processing for speed.
- Normalizes GHSA and CVE IDs.
- Provides direct upgrade recommendations.

### `pydoctor scan-unused`

Analyzes your imports to find packages you are paying for in `requirements.txt` but never actually using.

- Uses AST parsing (not regex).
- Aware of dependency trees (won't flag transitive deps of used packages).

### `pydoctor scan-deps`

Checks for version conflicts and missing dependencies in your environment.

---

## 🔧 Remediation

### `pydoctor fix`

The "Treatment" command. Attempts to solve problems automatically.

- **Actions:**
  - Upgrades vulnerable and outdated packages.
  - Updates `requirements.txt` versions.
  - Purges unused packages.
  - Can initialize missing virtual environments.
- **Modes:**
  - `Safe` (default): Asks for confirmation before every destructive step.
  - `--no-safe`: Runs non-interactively (ideal for automation).

---

## 🗄️ Utility

### `pydoctor version`

Displays the current version of the tool.

### `pydoctor cache`

Management for the local vulnerability cache.

- `cache clear`: Deletes all cached data.
- `cache info`: Shows size and location of the cache database.
