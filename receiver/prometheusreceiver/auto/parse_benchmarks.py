#!/usr/bin/env python3
"""Parse Prometheus receiver testbed benchmark outputs."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any


METRIC_NAMES = {
    "cpu_avg": "cpu_percentage_avg",
    "ram_avg": "ram_mib_avg",
}

METRIC_FLOORS = {
    "cpu_avg": 0.5,
    "ram_avg": 2.0,
}


@dataclass(frozen=True)
class RunMetric:
    harness_slug: str
    harness_label: str
    trial: int
    cpu_avg: float
    ram_avg: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "harness_slug": self.harness_slug,
            "harness_label": self.harness_label,
            "trial": self.trial,
            "cpu_avg": self.cpu_avg,
            "ram_avg": self.ram_avg,
        }


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def load_runs(paths: list[Path]) -> list[RunMetric]:
    runs: list[RunMetric] = []
    for path in paths:
        payload = load_json(path)
        runs.append(
            RunMetric(
                harness_slug=payload["harness_slug"],
                harness_label=payload["harness_label"],
                trial=int(payload["trial"]),
                cpu_avg=float(payload["cpu_avg"]),
                ram_avg=float(payload["ram_avg"]),
            )
        )
    return runs


def compute_metric_stats(values: list[float], floor: float) -> dict[str, Any]:
    mean_value = statistics.fmean(values)
    variance = statistics.variance(values) if len(values) > 1 else 0.0
    stdev = math.sqrt(variance)
    threshold = max(2 * stdev, floor)
    return {
        "runs": values,
        "mean": mean_value,
        "variance": variance,
        "stdev": stdev,
        "noise_threshold": threshold,
    }


def summarize_runs(runs: list[RunMetric]) -> dict[str, Any]:
    grouped: dict[str, list[RunMetric]] = {}
    labels: dict[str, str] = {}
    for run in runs:
        grouped.setdefault(run.harness_slug, []).append(run)
        labels[run.harness_slug] = run.harness_label

    harnesses: dict[str, Any] = {}
    aggregate_cpu: list[float] = []
    aggregate_ram: list[float] = []

    for harness_slug in sorted(grouped):
        harness_runs = sorted(grouped[harness_slug], key=lambda item: item.trial)
        cpu_values = [run.cpu_avg for run in harness_runs]
        ram_values = [run.ram_avg for run in harness_runs]
        aggregate_cpu.extend(cpu_values)
        aggregate_ram.extend(ram_values)
        harnesses[harness_slug] = {
            "label": labels[harness_slug],
            "trials": len(harness_runs),
            "cpu_avg": compute_metric_stats(cpu_values, METRIC_FLOORS["cpu_avg"]),
            "ram_avg": compute_metric_stats(ram_values, METRIC_FLOORS["ram_avg"]),
        }

    return {
        "harnesses": harnesses,
        "aggregate": {
            "cpu_avg_mean": statistics.fmean(aggregate_cpu) if aggregate_cpu else 0.0,
            "ram_avg_mean": statistics.fmean(aggregate_ram) if aggregate_ram else 0.0,
        },
    }


def evaluate_against_baseline(summary: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []

    for harness_slug, experiment in summary["harnesses"].items():
        base = baseline["harnesses"][harness_slug]
        for metric_name in ("cpu_avg", "ram_avg"):
            experiment_mean = float(experiment[metric_name]["mean"])
            baseline_mean = float(base[metric_name]["mean"])
            threshold = float(base[metric_name]["noise_threshold"])
            delta = experiment_mean - baseline_mean
            record = {
                "harness_slug": harness_slug,
                "harness_label": experiment["label"],
                "metric": metric_name,
                "baseline_mean": baseline_mean,
                "experiment_mean": experiment_mean,
                "delta": delta,
                "threshold": threshold,
            }
            if delta > threshold:
                regressions.append(record)
            elif delta < -threshold:
                improvements.append(record)

    if regressions:
        status = "pareto_regression"
    elif improvements:
        status = "pareto_win"
    else:
        status = "pareto_neutral"

    return {
        "status": status,
        "regressions": regressions,
        "improvements": improvements,
    }


def command_extract(args: argparse.Namespace) -> int:
    payload = load_json(Path(args.benchmarks))
    cpu_avg = None
    ram_avg = None
    cpu_extra = f"{args.harness_label} - Cpu Percentage"
    ram_extra = f"{args.harness_label} - RAM (MiB)"

    for row in payload:
        if row["name"] == METRIC_NAMES["cpu_avg"] and row["extra"] == cpu_extra:
            cpu_avg = float(row["value"])
        if row["name"] == METRIC_NAMES["ram_avg"] and row["extra"] == ram_extra:
            ram_avg = float(row["value"])

    if cpu_avg is None or ram_avg is None:
        raise SystemExit(
            f"could not find cpu/ram averages for harness label {args.harness_label!r}"
        )

    run_metric = RunMetric(
        harness_slug=args.harness_slug,
        harness_label=args.harness_label,
        trial=args.trial,
        cpu_avg=cpu_avg,
        ram_avg=ram_avg,
    )
    dump_json(Path(args.output), run_metric.to_dict())
    return 0


def command_summarize(args: argparse.Namespace) -> int:
    runs = load_runs([Path(path) for path in args.runs])
    summary = summarize_runs(runs)
    summary["meta"] = {
        "trials": args.trials,
        "testcase_duration": args.testcase_duration,
        "mode": args.mode,
    }
    if args.baseline:
        baseline = load_json(Path(args.baseline))
        summary["decision"] = evaluate_against_baseline(summary, baseline)
    else:
        summary["decision"] = {"status": "baseline_capture", "regressions": [], "improvements": []}
    dump_json(Path(args.output), summary)
    return 0


def command_write_baseline(args: argparse.Namespace) -> int:
    summary = load_json(Path(args.summary))
    baseline = {
        "meta": {
            "trials": summary["meta"]["trials"],
            "testcase_duration": summary["meta"]["testcase_duration"],
        },
        "harnesses": summary["harnesses"],
        "aggregate": summary["aggregate"],
    }
    dump_json(Path(args.output), baseline)
    return 0


def command_print_decision(args: argparse.Namespace) -> int:
    summary = load_json(Path(args.summary))
    decision = summary["decision"]
    print(f"DECISION status={decision['status']}")
    for harness_slug, harness in sorted(summary["harnesses"].items()):
        print(
            "HARNESS "
            f"slug={harness_slug} "
            f"cpu_avg_mean={harness['cpu_avg']['mean']:.3f} "
            f"cpu_avg_stdev={harness['cpu_avg']['stdev']:.3f} "
            f"ram_avg_mean={harness['ram_avg']['mean']:.3f} "
            f"ram_avg_stdev={harness['ram_avg']['stdev']:.3f}"
        )
    for record in decision["improvements"]:
        print(
            "IMPROVEMENT "
            f"slug={record['harness_slug']} metric={record['metric']} "
            f"delta={record['delta']:.3f} threshold={record['threshold']:.3f}"
        )
    for record in decision["regressions"]:
        print(
            "REGRESSION "
            f"slug={record['harness_slug']} metric={record['metric']} "
            f"delta={record['delta']:.3f} threshold={record['threshold']:.3f}"
        )
    return 0


def command_decision_status(args: argparse.Namespace) -> int:
    summary = load_json(Path(args.summary))
    print(summary["decision"]["status"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract = subparsers.add_parser("extract", help="Extract CPU/RAM averages for a single harness")
    extract.add_argument("--benchmarks", required=True)
    extract.add_argument("--harness-slug", required=True)
    extract.add_argument("--harness-label", required=True)
    extract.add_argument("--trial", type=int, required=True)
    extract.add_argument("--output", required=True)
    extract.set_defaults(func=command_extract)

    summarize = subparsers.add_parser("summarize", help="Summarize multiple harness runs")
    summarize.add_argument("--runs", nargs="+", required=True)
    summarize.add_argument("--output", required=True)
    summarize.add_argument("--trials", type=int, required=True)
    summarize.add_argument("--testcase-duration", required=True)
    summarize.add_argument("--mode", choices=("baseline", "compare"), required=True)
    summarize.add_argument("--baseline")
    summarize.set_defaults(func=command_summarize)

    write_baseline = subparsers.add_parser("write-baseline", help="Write a baseline artifact")
    write_baseline.add_argument("--summary", required=True)
    write_baseline.add_argument("--output", required=True)
    write_baseline.set_defaults(func=command_write_baseline)

    print_decision = subparsers.add_parser("print-decision", help="Print a human-readable decision")
    print_decision.add_argument("--summary", required=True)
    print_decision.set_defaults(func=command_print_decision)

    decision_status = subparsers.add_parser("decision-status", help="Print the machine-readable decision status")
    decision_status.add_argument("--summary", required=True)
    decision_status.set_defaults(func=command_decision_status)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
