#!/usr/bin/env bash
set -euo pipefail

AUTO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${AUTO_DIR}/../../.." && pwd)"
TESTBED_DIR="${REPO_ROOT}/testbed/tests"
PROM_MODULE_DIR="${REPO_ROOT}/receiver/prometheusreceiver"
PARSER="${AUTO_DIR}/parse_benchmarks.py"
BASELINE_FILE="${AUTO_DIR}/baseline.json"

MODE="${1:-compare}"
TRIALS="${TRIALS:-5}"
TESTCASE_DURATION="${TESTCASE_DURATION:-30s}"
RUNS_DIR="${RUNS_DIR:-${AUTO_DIR}/out}"
SESSION_NAME="${SESSION_NAME:-$(date +%Y%m%d-%H%M%S)-${MODE}}"
SESSION_DIR="${RUNS_DIR}/${SESSION_NAME}"
BUILD_OTELETESTBEDCOL="${BUILD_OTELETESTBEDCOL:-1}"
HYPOTHESIS="${HYPOTHESIS:-}"
SUMMARY_PATH="${SESSION_DIR}/summary.json"
DECISION_PATH="${SESSION_DIR}/decision.txt"

DIRTY_HYPOTHESIS_TRACKED_PATHS=()
DIRTY_HYPOTHESIS_UNTRACKED_PATHS=()
DIRTY_UNSAFE_PATHS=()

if [[ "${MODE}" != "baseline" && "${MODE}" != "compare" ]]; then
  echo "usage: $0 [baseline|compare]" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

mkdir -p "${SESSION_DIR}"

path_is_ignored_generated() {
  local path="$1"

  case "${path}" in
    receiver/prometheusreceiver/auto/out/*|receiver/prometheusreceiver/auto/baseline.json|receiver/prometheusreceiver/auto/__pycache__/*)
      return 0
      ;;
  esac

  return 1
}

path_is_hypothesis_candidate() {
  local path="$1"

  if [[ "${path}" != receiver/prometheusreceiver/* ]]; then
    return 1
  fi
  if [[ "${path}" == receiver/prometheusreceiver/auto/* ]]; then
    return 1
  fi
  if [[ "${path}" == *_test.go ]]; then
    return 1
  fi

  return 0
}

refresh_dirty_path_sets() {
  DIRTY_HYPOTHESIS_TRACKED_PATHS=()
  DIRTY_HYPOTHESIS_UNTRACKED_PATHS=()
  DIRTY_UNSAFE_PATHS=()

  local path=""

  while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    if path_is_ignored_generated "${path}"; then
      continue
    fi
    if path_is_hypothesis_candidate "${path}"; then
      DIRTY_HYPOTHESIS_TRACKED_PATHS+=("${path}")
    else
      DIRTY_UNSAFE_PATHS+=("${path}")
    fi
  done < <(git -C "${REPO_ROOT}" diff --name-only HEAD --)

  while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    if path_is_ignored_generated "${path}"; then
      continue
    fi
    if path_is_hypothesis_candidate "${path}"; then
      DIRTY_HYPOTHESIS_UNTRACKED_PATHS+=("${path}")
    else
      DIRTY_UNSAFE_PATHS+=("${path}")
    fi
  done < <(git -C "${REPO_ROOT}" ls-files --others --exclude-standard)
}

print_path_block() {
  local title="$1"
  shift

  echo "${title}"
  printf ' - %s\n' "$@"
}

require_compare_git_state() {
  local branch=""

  if ! git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "compare mode requires a git worktree" >&2
    exit 1
  fi

  if [[ -z "${HYPOTHESIS}" ]]; then
    echo "compare mode requires HYPOTHESIS=name" >&2
    exit 1
  fi

  if [[ "${HYPOTHESIS}" == *$'\n'* ]]; then
    echo "HYPOTHESIS must be a single line" >&2
    exit 1
  fi

  branch="$(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD)"
  if [[ -z "${branch}" || "${branch}" == "HEAD" ]]; then
    echo "compare mode requires a named branch" >&2
    exit 1
  fi
  if [[ "${branch}" == "main" || "${branch}" == "master" ]]; then
    echo "compare mode must not run on ${branch}" >&2
    exit 1
  fi

  refresh_dirty_path_sets

  if [[ "${#DIRTY_UNSAFE_PATHS[@]}" -gt 0 ]]; then
    print_path_block \
      "compare mode found unrelated dirty paths; commit or discard them before benchmarking:" \
      "${DIRTY_UNSAFE_PATHS[@]}" >&2
    exit 1
  fi

  if [[ "${#DIRTY_HYPOTHESIS_TRACKED_PATHS[@]}" -eq 0 && "${#DIRTY_HYPOTHESIS_UNTRACKED_PATHS[@]}" -eq 0 ]]; then
    echo "compare mode requires one active hypothesis change under receiver/prometheusreceiver (excluding auto/ and tests)." >&2
    exit 1
  fi
}

ensure_no_prometheusreceiver_test_changes() {
  local offenders=()
  local path=""

  if ! git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 0
  fi

  while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    if [[ "${path}" == receiver/prometheusreceiver/* ]] && [[ "${path}" == *_test.go ]]; then
      offenders+=("${path}")
    fi
  done < <(git -C "${REPO_ROOT}" diff --name-only HEAD -- "receiver/prometheusreceiver")

  while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    if [[ "${path}" == receiver/prometheusreceiver/* ]] && [[ "${path}" == *_test.go ]]; then
      offenders+=("${path}")
    fi
  done < <(git -C "${REPO_ROOT}" ls-files --others --exclude-standard -- "receiver/prometheusreceiver")

  if [[ "${#offenders[@]}" -gt 0 ]]; then
    {
      echo "Prometheus receiver autoresearch does not allow test changes."
      echo "Remove changes to these files before running the workflow:"
      printf ' - %s\n' "${offenders[@]}"
    } >&2
    exit 1
  fi
}

run_correctness_gate() {
  local test_status=0

  echo "==> Running Prometheus receiver tests"
  set +e
  (
    cd "${PROM_MODULE_DIR}"
    go test ./...
  ) 2>&1 | tee "${SESSION_DIR}/prometheusreceiver-tests.log"
  test_status="${PIPESTATUS[0]}"
  set -e

  if [[ "${test_status}" -ne 0 ]]; then
    echo "Prometheus receiver correctness gate failed." >&2
    exit "${test_status}"
  fi
}

build_testbed_binary() {
  if [[ "${BUILD_OTELETESTBEDCOL}" != "1" ]]; then
    echo "==> Skipping oteltestbedcol build"
    return
  fi

  echo "==> Building oteltestbedcol"
  (
    cd "${REPO_ROOT}"
    make oteltestbedcol
  ) | tee "${SESSION_DIR}/build-oteltestbedcol.log"
}

run_harness_trial() {
  local harness_slug="$1"
  local harness_label="$2"
  local harness_regex="$3"
  local profile_relpath="$4"
  local trial="$5"
  local run_dir="${SESSION_DIR}/${harness_slug}/trial-${trial}"

  mkdir -p "${run_dir}"
  rm -rf "${TESTBED_DIR}/results"

  echo "==> Running ${harness_label} trial ${trial}/${TRIALS}"
  (
    cd "${TESTBED_DIR}"
    RUN_TESTBED=1 TESTCASE_DURATION="${TESTCASE_DURATION}" go test -count=1 -v -run "${harness_regex}"
  ) | tee "${run_dir}/go-test.log"

  cp "${TESTBED_DIR}/results/benchmarks.json" "${run_dir}/benchmarks.json"
  cp "${TESTBED_DIR}/results/TESTRESULTS.md" "${run_dir}/TESTRESULTS.md"
  cp "${TESTBED_DIR}/results/${profile_relpath}/cpu.prof" "${run_dir}/cpu.prof"
  cp "${TESTBED_DIR}/results/${profile_relpath}/agent.log" "${run_dir}/agent.log"
  cp "${TESTBED_DIR}/results/${profile_relpath}/backend.log" "${run_dir}/backend.log"

  python3 "${PARSER}" extract \
    --benchmarks "${run_dir}/benchmarks.json" \
    --harness-slug "${harness_slug}" \
    --harness-label "${harness_label}" \
    --trial "${trial}" \
    --output "${run_dir}/metrics.json"
}

run_harness() {
  local harness_slug="$1"
  local harness_label="$2"
  local harness_regex="$3"
  local profile_relpath="$4"
  local trial=1

  while [[ "${trial}" -le "${TRIALS}" ]]; do
    run_harness_trial "${harness_slug}" "${harness_label}" "${harness_regex}" "${profile_relpath}" "${trial}"
    trial=$((trial + 1))
  done
}

build_run_list() {
  local run_files=()
  local harness_slug

  for harness_slug in baseline-10k with-target-info-10k native-histogram-10k; do
    local trial=1
    while [[ "${trial}" -le "${TRIALS}" ]]; do
      run_files+=("${SESSION_DIR}/${harness_slug}/trial-${trial}/metrics.json")
      trial=$((trial + 1))
    done
  done

  printf '%s\n' "${run_files[@]}"
}

summarize_session() {
  local run_files=()
  while IFS= read -r run_file; do
    run_files+=("${run_file}")
  done < <(build_run_list)

  if [[ "${MODE}" == "baseline" ]]; then
    python3 "${PARSER}" summarize \
      --runs "${run_files[@]}" \
      --output "${SUMMARY_PATH}" \
      --trials "${TRIALS}" \
      --testcase-duration "${TESTCASE_DURATION}" \
      --mode baseline
    python3 "${PARSER}" write-baseline \
      --summary "${SUMMARY_PATH}" \
      --output "${BASELINE_FILE}"
  else
    if [[ ! -f "${BASELINE_FILE}" ]]; then
      echo "baseline file not found: ${BASELINE_FILE}" >&2
      exit 1
    fi
    python3 "${PARSER}" summarize \
      --runs "${run_files[@]}" \
      --output "${SUMMARY_PATH}" \
      --trials "${TRIALS}" \
      --testcase-duration "${TESTCASE_DURATION}" \
      --mode compare \
      --baseline "${BASELINE_FILE}"
  fi

  python3 "${PARSER}" print-decision --summary "${SUMMARY_PATH}" | tee "${DECISION_PATH}"
}

build_commit_message() {
  cat <<EOF
prometheusreceiver: accept ${HYPOTHESIS} hypothesis

Accept the ${HYPOTHESIS} autoresearch hypothesis after a pareto win on the
Prometheus receiver average CPU and RAM benchmark harnesses.
EOF
}

commit_hypothesis_changes() {
  local commit_paths=("${DIRTY_HYPOTHESIS_TRACKED_PATHS[@]}" "${DIRTY_HYPOTHESIS_UNTRACKED_PATHS[@]}")

  if [[ "${#DIRTY_UNSAFE_PATHS[@]}" -gt 0 ]]; then
    print_path_block \
      "refusing to auto-commit because unrelated dirty paths are present:" \
      "${DIRTY_UNSAFE_PATHS[@]}" >&2
    exit 1
  fi

  if [[ "${#commit_paths[@]}" -eq 0 ]]; then
    echo "pareto_win produced no hypothesis changes to commit" >&2
    exit 1
  fi

  echo "==> Accepting hypothesis ${HYPOTHESIS}"
  git -C "${REPO_ROOT}" add -- "${commit_paths[@]}"
  git -C "${REPO_ROOT}" commit -m "$(build_commit_message)"
}

discard_hypothesis_changes() {
  local path=""

  if [[ "${#DIRTY_UNSAFE_PATHS[@]}" -gt 0 ]]; then
    print_path_block \
      "refusing to auto-discard because unrelated dirty paths are present:" \
      "${DIRTY_UNSAFE_PATHS[@]}" >&2
    exit 1
  fi

  if [[ "${#DIRTY_HYPOTHESIS_TRACKED_PATHS[@]}" -eq 0 && "${#DIRTY_HYPOTHESIS_UNTRACKED_PATHS[@]}" -eq 0 ]]; then
    echo "==> Nothing to discard for hypothesis ${HYPOTHESIS}"
    return
  fi

  echo "==> Discarding hypothesis ${HYPOTHESIS}"

  if [[ "${#DIRTY_HYPOTHESIS_TRACKED_PATHS[@]}" -gt 0 ]]; then
    git -C "${REPO_ROOT}" restore --source=HEAD --staged --worktree -- "${DIRTY_HYPOTHESIS_TRACKED_PATHS[@]}"
  fi

  for path in "${DIRTY_HYPOTHESIS_UNTRACKED_PATHS[@]}"; do
    rm -f "${REPO_ROOT}/${path}"
  done
}

post_compare_git_action() {
  local decision_status=""

  if [[ "${MODE}" != "compare" ]]; then
    return
  fi

  refresh_dirty_path_sets
  decision_status="$(python3 "${PARSER}" decision-status --summary "${SUMMARY_PATH}")"

  case "${decision_status}" in
    pareto_win)
      commit_hypothesis_changes
      ;;
    pareto_neutral|pareto_regression)
      discard_hypothesis_changes
      ;;
    *)
      echo "unknown decision status: ${decision_status}" >&2
      exit 1
      ;;
  esac
}

main() {
  if [[ "${MODE}" == "compare" ]]; then
    require_compare_git_state
  fi

  build_testbed_binary
  ensure_no_prometheusreceiver_test_changes
  run_correctness_gate

  run_harness \
    "baseline-10k" \
    "PrometheusReceiver/Baseline/10k" \
    '^TestPrometheusReceiver$/^Baseline$/^10k$' \
    "TestPrometheusReceiver/Baseline/10k"

  run_harness \
    "with-target-info-10k" \
    "PrometheusReceiver/WithTargetInfo/10k" \
    '^TestPrometheusReceiver$/^WithTargetInfo$/^10k$' \
    "TestPrometheusReceiver/WithTargetInfo/10k"

  run_harness \
    "native-histogram-10k" \
    "PrometheusReceiver/NativeHistogram/10k" \
    '^TestPrometheusReceiver$/^NativeHistogram$/^10k$' \
    "TestPrometheusReceiver/NativeHistogram/10k"

  summarize_session
  post_compare_git_action

  echo
  echo "Session results written to ${SESSION_DIR}"
  if [[ "${MODE}" == "baseline" ]]; then
    echo "Baseline updated at ${BASELINE_FILE}"
  fi
}

main "$@"
