"""Pure evaluation helpers for comparing LLM-only and RAG answers."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cves(text: str) -> set[str]:
    return {match.group(0).upper() for match in CVE_PATTERN.finditer(text or "")}


def infer_status(text: str) -> str:
    """Infer a coarse answer status from Vietnamese or English answer text."""

    normalized = " ".join((text or "").lower().split())
    insufficient_markers = (
        "không đủ bằng chứng",
        "chưa đủ bằng chứng",
        "không tìm thấy",
        "không có thông tin",
        "không thể xác nhận",
        "insufficient evidence",
        "cannot confirm",
    )
    not_affected_markers = (
        "không bị ảnh hưởng",
        "không ảnh hưởng",
        "nằm ngoài phạm vi",
        "không thuộc phạm vi",
        "not affected",
    )
    affected_markers = (
        "bị ảnh hưởng",
        "có ảnh hưởng",
        "nằm trong phạm vi ảnh hưởng",
        "affected",
    )
    if any(marker in normalized for marker in insufficient_markers):
        return "insufficient_evidence"
    if any(marker in normalized for marker in not_affected_markers):
        return "not_affected"
    if any(marker in normalized for marker in affected_markers):
        return "affected"
    return "answered"


def score_record(record: dict[str, Any], known_cves: set[str]) -> dict[str, Any]:
    expected = {str(item).upper() for item in record.get("expected_cves", [])}
    predicted = extract_cves(str(record.get("answer", "")))
    status = str(record.get("predicted_status") or infer_status(record.get("answer", "")))
    expected_status = str(record.get("expected_status", ""))

    true_positive = len(expected & predicted)
    false_positive = len(predicted - expected)
    false_negative = len(expected - predicted)
    unknown_cves = predicted - known_cves
    hallucinated = unknown_cves if status != "insufficient_evidence" else set()

    return {
        **record,
        "predicted_cves": sorted(predicted),
        "cve_exact_match": predicted == expected,
        "status_correct": status == expected_status,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "unsupported_cves": sorted(predicted - expected),
        "unknown_cves": sorted(unknown_cves),
        "hallucinated_cves": sorted(hallucinated),
    }


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def summarize(records: Iterable[dict[str, Any]], known_cves: set[str]) -> dict[str, Any]:
    scored = [score_record(record, known_cves) for record in records]
    total = len(scored)
    true_positive = sum(item["true_positive"] for item in scored)
    false_positive = sum(item["false_positive"] for item in scored)
    false_negative = sum(item["false_negative"] for item in scored)
    predicted_cve_count = sum(len(item["predicted_cves"]) for item in scored)
    hallucinated_count = sum(len(item["hallucinated_cves"]) for item in scored)
    error_count = sum(1 for item in scored if item.get("error"))
    citation_count = sum(1 for item in scored if item.get("citations"))

    precision = _safe_ratio(true_positive, true_positive + false_positive)
    recall = _safe_ratio(true_positive, true_positive + false_negative)
    f1 = _safe_ratio(2 * precision * recall, precision + recall)

    return {
        "questions": total,
        "errors": error_count,
        "cve_exact_match_accuracy": _safe_ratio(
            sum(bool(item["cve_exact_match"]) for item in scored), total
        ),
        "status_accuracy": _safe_ratio(
            sum(bool(item["status_correct"]) for item in scored), total
        ),
        "cve_precision": precision,
        "cve_recall": recall,
        "cve_f1": f1,
        "hallucinated_cve_count": hallucinated_count,
        "hallucinated_cve_rate": _safe_ratio(hallucinated_count, predicted_cve_count),
        "citation_answer_rate": _safe_ratio(citation_count, total),
        "average_latency_seconds": _safe_ratio(
            sum(float(item.get("latency_seconds", 0.0)) for item in scored), total
        ),
    }


def compare_summaries(
    baseline: dict[str, Any], rag: dict[str, Any]
) -> dict[str, float]:
    comparable_metrics = (
        "cve_exact_match_accuracy",
        "status_accuracy",
        "cve_precision",
        "cve_recall",
        "cve_f1",
        "hallucinated_cve_rate",
        "citation_answer_rate",
        "average_latency_seconds",
    )
    return {
        metric: float(rag.get(metric, 0.0)) - float(baseline.get(metric, 0.0))
        for metric in comparable_metrics
    }

