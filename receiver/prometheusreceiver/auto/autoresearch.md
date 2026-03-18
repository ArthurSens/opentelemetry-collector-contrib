# Autoresearch: Prometheus Receiver CPU and RAM

## Objective
Optimize the Prometheus receiver using the existing testbed harnesses.
The optimization targets are:

- `cpu_percentage_avg` (lower is better)
- `ram_mib_avg` (lower is better)

Ignore throughput, dropped span count, max CPU, and max RAM for accept/reject
decisions.

## Benchmark Harnesses
Use only these read-only harnesses from `testbed/tests/prometheus_test.go`:

- `TestPrometheusReceiver/Baseline/10k`
- `TestPrometheusReceiver/WithTargetInfo/10k`
- `TestPrometheusReceiver/NativeHistogram/10k`

Do not optimize one while sacrificing another. Treat the three harnesses as a
Pareto set.

## Campaign Setup
Start one clean branch for the whole experiment before the first hypothesis:

```bash
git checkout -b "prometheusreceirver/performance-autoresearch"
cd receiver/prometheusreceiver
./auto/autoresearch.sh baseline
```

Keep accepted hypotheses on that same branch. Do not create a new branch per
hypothesis.

## Per-Hypothesis Loop
From `receiver/prometheusreceiver`:

```bash
HYPOTHESIS=my-change ./auto/autoresearch.sh compare
```

Environment overrides:

- `TRIALS` defaults to `5`
- `TESTCASE_DURATION` defaults to `30s`
- `BUILD_OTELETESTBEDCOL=0` skips rebuilding the testbed collector
- `SESSION_NAME=name` overrides the output directory suffix
- `HYPOTHESIS=name` is required for `compare`

## Hypothesis Source
Start with the latest saved `cpu.prof` artifacts from the harness runs.

Use `go tool pprof -top` first, then follow up with narrower views such as
`list` and `weblist` for the hottest functions. Derive experiment ideas from
measured hot paths and refresh the profiles after meaningful wins so the next
round targets the current bottlenecks.

## Scope
Allowed code changes:

- anything under `receiver/prometheusreceiver`

Out of scope:

- any change to `receiver/prometheusreceiver/**/*_test.go`
- `testbed/`
- other receivers, exporters, processors, or shared packages outside
  `receiver/prometheusreceiver`

## Notes
- The testbed already writes a valid collector CPU profile to `cpu.prof`.
