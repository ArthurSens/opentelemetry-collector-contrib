---
name: prometheus-autoresearch
description: Runs and interprets the Prometheus receiver autoresearch workflow using the repo's three 10k testbed harnesses, average CPU and RAM metrics, saved CPU profiles, and a Pareto keep-discard rule. Use when the user asks to optimize, benchmark, profile, or rerun autoresearch for `receiver/prometheusreceiver`.
---

# Prometheus Autoresearch

## When To Use
Use this skill when the user wants to:

- optimize `receiver/prometheusreceiver`
- derive optimization ideas from the Prometheus receiver testbed CPU profiles

## Workflow
1. Read `receiver/prometheusreceiver/auto/autoresearch.md`.
2. Start the experiment on a clean dedicated branch, for example `prometheusreceirver/performance-autoresearch`.
3. Establish the baseline with `receiver/prometheusreceiver/auto/autoresearch.sh baseline` if it is missing or stale.
4. Keep code changes inside `receiver/prometheusreceiver`.
5. Do not modify any `*_test.go` file under `receiver/prometheusreceiver`.
6. For each hypothesis, make one small change and run `HYPOTHESIS=<slug> receiver/prometheusreceiver/auto/autoresearch.sh compare`.
7. Let the script auto-commit Pareto wins and auto-discard neutral/regression results on the same branch.
8. Use the saved `cpu.prof` artifacts as the primary source of optimization hypotheses.
9. Open the final PR from that same experiment branch.

## Benchmark Contract
The workflow uses exactly these harnesses:

- `TestPrometheusReceiver/Baseline/10k`
- `TestPrometheusReceiver/WithTargetInfo/10k`
- `TestPrometheusReceiver/NativeHistogram/10k`

Ignore throughput, dropped spans, max CPU, and max RAM for keep-discard decisions.

## Additional Resources
- For the detailed workflow, commands, outputs, and decision logic, see [reference.md](reference.md).
- For the repository-local benchmark contract, see [`receiver/prometheusreceiver/auto/autoresearch.md`](../../../receiver/prometheusreceiver/auto/autoresearch.md).
