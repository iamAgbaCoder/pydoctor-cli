#!/usr/bin/env bash
# Run `pydoctor check`, write SARIF, and record the exit code without failing,
# so the SARIF upload step still runs. The action's last step fails the job.
set -uo pipefail

args=(check --path "${INPUT_PATH:-.}" --sarif "${INPUT_SARIF_FILE:-pydoctor.sarif}")
[[ "${INPUT_CI_ONLY:-false}" == "true" ]] && args+=(--ci)
[[ -n "${INPUT_PYTHON:-}" ]] && args+=(--python "$INPUT_PYTHON")
if [[ -n "${INPUT_ARGS:-}" ]]; then
  read -r -a extra <<< "$INPUT_ARGS"
  args+=("${extra[@]}")
fi

"${PYDOCTOR_BIN:?}" "${args[@]}"
code=$?

out="${GITHUB_OUTPUT:-/dev/null}"
echo "exit-code=$code" >> "$out"
echo "sarif-file=${INPUT_SARIF_FILE:-pydoctor.sarif}" >> "$out"
if [[ -f "${INPUT_SARIF_FILE:-pydoctor.sarif}" ]]; then
  echo "sarif-written=true" >> "$out"
else
  echo "sarif-written=false" >> "$out"
fi
exit 0
