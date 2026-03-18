# Prometheus Autoresearch Reference

## Goal
This skill supports repeated optimization work for `receiver/prometheusreceiver`
using the existing Prometheus testbed harnesses and the package-local
autoresearch assets.

## Sources Of Truth
- `receiver/prometheusreceiver/auto/autoresearch.md`
- `receiver/prometheusreceiver/auto/autoresearch.sh`
- `receiver/prometheusreceiver/auto/parse_benchmarks.py`
- `receiver/prometheusreceiver/auto/baseline.json`

## Branch Bootstrap
Start each campaign on one clean dedicated branch and keep all accepted hypotheses
on that branch.

Suggested flow:

```bash
git checkout -b "prometheusreceirver/performance-autoresearch"
cd receiver/prometheusreceiver
./auto/autoresearch.sh baseline
```


## Correctness Gate
Run from `receiver/prometheusreceiver`:

```bash
go test ./...
```

If this fails, do not keep the experiment.

The workflow also rejects any modified or newly added `*_test.go` file under
`receiver/prometheusreceiver` before benchmarking starts.

## Benchmark Commands
Use the package-local runner:

```bash
./auto/autoresearch.sh baseline
HYPOTHESIS=my-change ./auto/autoresearch.sh compare
```

Useful overrides:

```bash
TRIALS=5 TESTCASE_DURATION=30s HYPOTHESIS=my-change ./auto/autoresearch.sh compare
SESSION_NAME=my-run BUILD_OTELETESTBEDCOL=0 HYPOTHESIS=my-change ./auto/autoresearch.sh compare
```

## Outputs
The runner writes:

- `receiver/prometheusreceiver/auto/baseline.json`
- `receiver/prometheusreceiver/auto/out/<session>/summary.json`
- `receiver/prometheusreceiver/auto/out/<session>/decision.txt`
- `receiver/prometheusreceiver/auto/out/<session>/<harness>/trial-*/cpu.prof`
- copied `benchmarks.json`, `TESTRESULTS.md`, `agent.log`, and `backend.log`

## Metrics
Optimization targets:

- `cpu_percentage_avg`
- `ram_mib_avg`

Ignored for keep-discard decisions:

- throughput
- dropped spans
- `cpu_percentage_max`
- `ram_mib_max`

## Pareto Rule
Keep an experiment only if:

- there is no meaningful average CPU regression on any harness
- there is no meaningful average RAM regression on any harness
- at least one harness meaningfully improves average CPU or average RAM

The noise threshold for each harness/metric pair is derived from the stored
baseline variance.

## Hypothesis Workflow
1. Read the per-harness `cpu.prof` artifacts from the latest session.
2. Start with `go tool pprof -top <path-to-cpu.prof>`.
3. Use `list <function>` or `weblist <function>` on the hottest measured paths.
4. Form a small local hypothesis.
5. Re-run `HYPOTHESIS=<slug> ./auto/autoresearch.sh compare`.
6. A Pareto win is committed automatically on the current experiment branch.
7. A neutral or regression result is discarded automatically.
8. Refresh the CPU profiles after wins and use the new bottlenecks for the next round.

## Scope Limits
Allowed modifications:

- files under `receiver/prometheusreceiver`

Do not modify:

- `receiver/prometheusreceiver/**/*_test.go`
- `testbed/`
- other component packages outside `receiver/prometheusreceiver`
