"""Offline LLM efficiency metrics shared by benchmarks, reports and the viewer."""

from __future__ import annotations

import csv
import math
from collections.abc import Iterable
from pathlib import Path
from typing import Any


TOKEN_FIELDS = ("input_tokens", "output_tokens", "total_tokens", "reasoning_tokens", "cached_input_tokens")
PERFORMANCE_FIELDS = (
    ("input_tokens", "Input tokens"),
    ("output_tokens", "Output tokens"),
    ("total_tokens", "Total tokens"),
    ("reasoning_tokens", "Reasoning tokens"),
    ("cached_input_tokens", "Cached input tokens"),
    ("attempts", "LLM attempts"),
    ("retry_attempts", "Retry attempts"),
    ("failed_attempts", "Failed LLM attempts"),
    ("failed_request_rate", "LLM failure rate"),
    ("request_latency_seconds", "Total LLM time"),
    ("average_request_latency_seconds", "Mean LLM latency"),
    ("average_ttft_seconds", "Mean TTFT"),
    ("output_tokens_per_second", "Observed output tok/s"),
)
RUN_PERFORMANCE_FIELDS = (
    ("saved_questions", "Saved responses"),
    ("questions_with_request_logs", "Responses with logs"),
    ("questions_with_llm_call", "Questions calling LLM"),
    *PERFORMANCE_FIELDS,
    ("average_total_tokens_per_question", "Mean tokens/question"),
    ("p50_request_latency_seconds", "LLM latency p50"),
    ("p95_request_latency_seconds", "LLM latency p95"),
    ("p99_request_latency_seconds", "LLM latency p99"),
    ("p95_ttft_seconds", "TTFT p95"),
    ("average_pipeline_latency_seconds", "Mean pipeline latency"),
)
QUALITY_FIELDS = (
    "questions", "errors", "version_check_questions", "abstention_questions", "conflict_questions",
    "cve_and_status_accuracy", "cve_exact_match_accuracy", "status_accuracy", "version_status_accuracy",
    "cve_precision", "cve_recall", "cve_f1", "evidence_cve_recall", "citation_url_precision",
    "citation_url_coverage", "correct_abstention_rate", "manual_factual_correctness",
    "manual_faithfulness", "manual_citation_support", "manual_factual_correctness_questions",
    "manual_faithfulness_questions", "manual_citation_support_questions",
)


def _duration(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lower, upper = math.floor(index), math.ceil(index)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def summarize_usage(attempts: Iterable[dict[str, Any]]) -> dict[str, Any]:
    recorded = list(attempts)
    count = len(recorded)
    reported = {
        field: [a[field] for a in recorded if type(a.get(field)) is int and a[field] >= 0]
        for field in TOKEN_FIELDS
    }
    durations = [a["latency_seconds"] for a in recorded if _duration(a.get("latency_seconds"))]
    statuses = [a["succeeded"] for a in recorded if type(a.get("succeeded")) is bool]
    first_text_times = [a["ttft_seconds"] for a in recorded if _duration(a.get("ttft_seconds"))]
    # Pair each output count with its own successful request duration. Missing
    # usage and failed attempts must not contribute unmatched time or tokens.
    speed_samples = [
        a for a in recorded if a.get("succeeded") is True
        and type(a.get("output_tokens")) is int and a["output_tokens"] >= 0
        and _duration(a.get("latency_seconds")) and a["latency_seconds"] > 0
    ]
    return {
        "attempts": count,
        "failed_attempts": sum(not status for status in statuses) if statuses or not count else None,
        "failed_request_rate": sum(not status for status in statuses) / len(statuses) if statuses else None,
        "status_reported_attempts": len(statuses),
        "request_latency_seconds": sum(durations) if durations or not count else None,
        "average_request_latency_seconds": sum(durations) / len(durations) if durations else None,
        "p50_request_latency_seconds": _percentile(durations, 0.5),
        "p95_request_latency_seconds": _percentile(durations, 0.95),
        "p99_request_latency_seconds": _percentile(durations, 0.99),
        "latency_reported_attempts": len(durations),
        "average_ttft_seconds": sum(first_text_times) / len(first_text_times) if first_text_times else None,
        "p95_ttft_seconds": _percentile(first_text_times, 0.95),
        "ttft_reported_attempts": len(first_text_times),
        "output_tokens_per_second": (
            sum(a["output_tokens"] for a in speed_samples) / sum(a["latency_seconds"] for a in speed_samples)
            if speed_samples else None
        ),
        "throughput_reported_attempts": len(speed_samples),
        **{field: sum(values) if values or not count else None for field, values in reported.items()},
        "reported_attempts": {field: len(values) for field, values in reported.items()},
    }


def summarize_performance(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Include every saved response, even failed, filtered and zero-call ones."""
    saved = list(rows)
    logs = [
        row["llm_requests"] for row in saved
        if isinstance(row.get("llm_requests"), list) and all(isinstance(a, dict) for a in row["llm_requests"])
    ]
    usage = summarize_usage(a for requests in logs for a in requests)
    if saved and not logs:
        # A legacy response without instrumentation does not mean zero usage.
        usage.update({key: None for key in usage if key != "reported_attempts"})
    latencies = [row["latency_seconds"] for row in saved if _duration(row.get("latency_seconds"))]
    complete_tokens = len(logs) == len(saved) and usage["reported_attempts"]["total_tokens"] == usage["attempts"]
    return {
        **usage,
        "saved_questions": len(saved),
        "questions_with_request_logs": len(logs),
        "request_log_coverage": len(logs) / len(saved) if saved else None,
        "questions_with_llm_call": sum(bool(requests) for requests in logs) if logs or not saved else None,
        # The benchmark makes one logical generation call per question; extra
        # attempts within that question are retries.
        "retry_attempts": sum(max(0, len(requests) - 1) for requests in logs) if logs or not saved else None,
        "average_total_tokens_per_question": usage["total_tokens"] / len(saved) if saved and complete_tokens else None,
        "average_pipeline_latency_seconds": sum(latencies) / len(latencies) if latencies else None,
        "pipeline_latency_reported_questions": len(latencies),
    }


def format_performance(usage: dict[str, Any], key: str) -> str:
    value = usage.get(key)
    if value is None:
        missing = key in TOKEN_FIELDS or usage.get("attempts") is None or ("ttft" in key and usage.get("attempts", 0) > 0)
        return "NOT RECORDED" if missing else "N/A"
    if key in TOKEN_FIELDS:
        text = f"{value:,}"
    elif key.endswith("_seconds"):
        text = f"{value:.3f}s"
    elif key.endswith("_rate"):
        text = f"{value:.1%}"
    elif type(value) is int:
        text = str(value)
    else:
        text = f"{value:.2f}"
    reported = None
    denominator = usage.get("attempts") or 0
    if key in TOKEN_FIELDS:
        reported = usage["reported_attempts"][key]
    elif key == "average_pipeline_latency_seconds":
        reported = usage.get("pipeline_latency_reported_questions")
        denominator = usage["saved_questions"]
    elif "latency_seconds" in key:
        reported = usage.get("latency_reported_attempts")
    elif "ttft" in key:
        reported = usage.get("ttft_reported_attempts")
    elif key in {"failed_attempts", "failed_request_rate"}:
        reported = usage.get("status_reported_attempts")
    if reported is not None and reported < denominator:
        unit = "responses" if key == "average_pipeline_latency_seconds" else "calls"
        text += f" ({reported}/{denominator} {unit})"
    if key == "output_tokens_per_second":
        text += f" ({usage['throughput_reported_attempts']} calls)"
    return text


def write_metrics_csv(path: Path, report: dict[str, Any], score_keys: dict[str, str]) -> None:
    """Export quality and LLM efficiency as the two main metric groups."""
    with path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["mode", "metric_group", "metric", "value"])
        for mode in report["modes"]:
            quality = report.get(score_keys[mode]) or {}
            writer.writerows([mode, "answer_quality", key, quality.get(key)] for key in QUALITY_FIELDS)
            usage = report["llm_usage"][mode]
            writer.writerows([mode, "llm_efficiency", key, value] for key, value in usage.items() if key != "reported_attempts")
            writer.writerows([mode, "llm_efficiency", f"{key}_reported_attempts", value] for key, value in usage["reported_attempts"].items())
