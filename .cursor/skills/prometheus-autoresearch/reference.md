# Prometheus Autoresearch Reference

## Goal
This skill supports repeated optimization work for `receiver/prometheusreceiver`
using the existing Prometheus testbed harnesses and the package-local
autoresearch assets.

## Sources Of Truth
- `receiver/prometheusreceiver/auto/autoresearch.md`
- `receiver/prometheusreceiver/auto/autoresearch.sh`

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
Keep the `receiver/prometheusreceiver` package tests green throughout the experiment.

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

## Hypothesis Workflow
1. Read the latest per-harness `cpu.prof` artifacts.
2. Start with `go tool pprof -top <path-to-cpu.prof>`.
3. Use `list <function>` or `weblist <function>` on the hottest measured paths.
4. Form a small local hypothesis.
5. Re-run `HYPOTHESIS=<slug> ./auto/autoresearch.sh compare`.
6. Refresh the CPU profiles after meaningful progress and use the new bottlenecks for the next round.

## Scope Limits
Allowed modifications:

- files under `receiver/prometheusreceiver`

Do not modify:

- `receiver/prometheusreceiver/**/*_test.go`
- `testbed/`
- other component packages outside `receiver/prometheusreceiver`
