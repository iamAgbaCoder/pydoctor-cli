#!/usr/bin/env bash
# Install pydoctor-cli into its own virtual environment so it can't change, or
# be counted as part of, the project's environment. Prints `bin=<path>` to
# $GITHUB_OUTPUT.
set -euo pipefail

spec="pydoctor-cli"
version="${PYDOCTOR_VERSION:-}"
ref="${ACTION_REF:-}"

if [[ "$version" == "local" ]]; then
  spec="${GITHUB_ACTION_PATH:?}"
elif [[ -n "$version" ]]; then
  spec="pydoctor-cli==${version#v}"
elif [[ "$ref" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  spec="pydoctor-cli==${ref#v}"
elif [[ "$ref" =~ ^v([0-9]+)$ ]]; then
  major="${BASH_REMATCH[1]}"
  spec="pydoctor-cli>=${major},<$((major + 1))"
fi

if [[ -n "${PYDOCTOR_DRY_RUN:-}" ]]; then
  echo "$spec"
  exit 0
fi

base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pydoctor-venv"
# On Windows runners RUNNER_TEMP is a Windows path; use the POSIX form in bash.
if command -v cygpath >/dev/null 2>&1; then
  base="$(cygpath -u "$base")"
fi
py="$(command -v python3 || command -v python)"
"$py" -m venv "$base"
if [[ -x "$base/bin/python" ]]; then
  venv_py="$base/bin/python"; bin="$base/bin/pydoctor"
else
  venv_py="$base/Scripts/python.exe"; bin="$base/Scripts/pydoctor.exe"
fi
"$venv_py" -m pip install --quiet --disable-pip-version-check "$spec"
"$bin" --version
echo "bin=$bin" >> "${GITHUB_OUTPUT:-/dev/null}"
