"""Evaluation metrics for answer, citation, conflict, and CVE hallucination."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from rag.identifiers import find_cve_ids

def extract_cves(text: str) -> set[str]:
    return set(find_cve_ids(text or ""))


def infer_status(text: str) -> str:
    normalized = " ".join((text or "").lower().split())
    insufficient = ("không đủ bằng chứng", "chưa đủ bằng chứng", "không tìm thấy", "không có thông tin", "không thể xác nhận", "insufficient evidence", "cannot confirm")
    not_affected = ("không bị ảnh hưởng", "không ảnh hưởng", "nằm ngoài phạm vi", "không thuộc phạm vi", "not affected")
    affected = ("bị ảnh hưởng", "có ảnh hưởng", "nằm trong phạm vi ảnh hưởng", "affected")
    if any(marker in normalized for marker in insufficient):
        return "insufficient_evidence"
    if any(marker in normalized for marker in not_affected):
        return "not_affected"
    if any(marker in normalized for marker in affected):
        return "affected"
    return "answered"


def _citation_urls(record: dict[str, Any]) -> set[str]:
    return {
        str(item.get("url", "")).rstrip("/")
        for item in record.get("citations", [])
        if item.get("url")
    }


def score_record(record: dict[str, Any], all_cve_ids: set[str] | None) -> dict[str, Any]:
    expected = {str(item).upper() for item in record.get("expected_cves", [])}
    mentioned = extract_cves(str(record.get("answer", "")))
    status = str(record.get("predicted_status") or infer_status(record.get("answer", "")))
    failed = record.get("error") is not None or status == "error"
    # A correct abstention may repeat the identifier from the question; it is not an asserted CVE.
    predicted = set() if failed or status == "insufficient_evidence" else mentioned
    cve_exact = not failed and predicted == expected
    status_correct = not failed and status == record.get("expected_status")
    nonexistent = sorted(predicted - all_cve_ids) if all_cve_ids is not None else None
    unsupported = predicted - expected
    retrieved = {str(item).upper() for item in record.get("retrieved_evidence_cves", [])}
    unsupported_by_evidence = predicted - retrieved if record.get("mode") == "rag" else set()
    expected_urls = {str(item).rstrip("/") for item in record.get("expected_source_urls", [])}
    citation_urls = set() if failed else _citation_urls(record)
    valid_citations = citation_urls & expected_urls

    return {
        **record,
        "predicted_cves": sorted(predicted),
        "response_failed": failed,
        "cve_exact_match": cve_exact,
        "status_correct": status_correct,
        "cve_and_status_correct": cve_exact and status_correct,
        "true_positive": len(expected & predicted),
        "false_positive": len(unsupported),
        "false_negative": len(expected - predicted),
        "nonexistent_cves": nonexistent,
        "unsupported_cves": sorted(unsupported),
        "unsupported_by_retrieved_evidence": sorted(unsupported_by_evidence),
        "citation_count": len(citation_urls),
        "valid_citation_count": len(valid_citations),
        "citation_required": bool(expected_urls),
        "citation_covered": bool(expected_urls and valid_citations),
        "correct_abstention": status_correct and status == "insufficient_evidence",
    }


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _summary(scored: list[dict[str, Any]], has_catalog: bool) -> dict[str, Any]:
    total = len(scored)
    tp = sum(item["true_positive"] for item in scored)
    fp = sum(item["false_positive"] for item in scored)
    fn = sum(item["false_negative"] for item in scored)
    predicted_count = sum(len(item["predicted_cves"]) for item in scored)
    nonexistent_count = sum(len(item["nonexistent_cves"]) for item in scored) if has_catalog else None
    nonexistent_rate = _safe_ratio(nonexistent_count, predicted_count) if nonexistent_count is not None else None
    unsupported_count = sum(len(item["unsupported_cves"]) for item in scored)
    evidence_unsupported_count = sum(len(item["unsupported_by_retrieved_evidence"]) for item in scored)
    citation_count = sum(item["citation_count"] for item in scored)
    valid_citation_count = sum(item["valid_citation_count"] for item in scored)
    citation_required = [item for item in scored if item["citation_required"]]
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    abstention_cases = [item for item in scored if item.get("expected_status") == "insufficient_evidence"]
    conflict_cases = [item for item in scored if item.get("has_conflict")]
    version_checks = [item for item in scored if item.get("question_type") == "cve_version_check"]
    return {
        "questions": total,
        "errors": sum(item["response_failed"] for item in scored),
        "cve_exact_match_accuracy": _safe_ratio(sum(item["cve_exact_match"] for item in scored), total),
        "status_accuracy": _safe_ratio(sum(item["status_correct"] for item in scored), total),
        "cve_and_status_accuracy": _safe_ratio(sum(item["cve_and_status_correct"] for item in scored), total),
        "version_status_accuracy": (
            _safe_ratio(sum(item["status_correct"] for item in version_checks), len(version_checks))
            if version_checks else None
        ),
        "cve_precision": precision,
        "cve_recall": recall,
        "cve_f1": _safe_ratio(2 * precision * recall, precision + recall),
        "nonexistent_cve_count": nonexistent_count,
        "nonexistent_cve_level_rate": nonexistent_rate,
        "nonexistent_answer_level_rate": _safe_ratio(sum(bool(item["nonexistent_cves"]) for item in scored), total) if has_catalog else None,
        "unsupported_cve_count": unsupported_count,
        "unsupported_cve_precision": _safe_ratio(tp, tp + unsupported_count),
        "unsupported_cve_level_rate": _safe_ratio(unsupported_count, predicted_count),
        "unsupported_answer_level_rate": _safe_ratio(sum(bool(item["unsupported_cves"]) for item in scored), total),
        "retrieved_evidence_unsupported_cve_count": evidence_unsupported_count,
        "retrieved_evidence_unsupported_answer_rate": _safe_ratio(sum(bool(item["unsupported_by_retrieved_evidence"]) for item in scored), total),
        "citation_precision": _safe_ratio(valid_citation_count, citation_count),
        "citation_coverage": _safe_ratio(sum(item["citation_covered"] for item in citation_required), len(citation_required)),
        "conflict_case_accuracy": _safe_ratio(sum(item["status_correct"] for item in conflict_cases), len(conflict_cases)),
        "correct_abstention_rate": _safe_ratio(sum(item["correct_abstention"] for item in abstention_cases), len(abstention_cases)),
        "average_latency_seconds": _safe_ratio(sum(float(item.get("latency_seconds", 0.0)) for item in scored), total),
        # Compatibility aliases retained in artifacts while the report migrates.
        "hallucinated_cve_count": nonexistent_count,
        "hallucinated_cve_rate": nonexistent_rate,
        "citation_answer_rate": _safe_ratio(sum(item["citation_count"] > 0 for item in scored), total),
    }


def summarize(records: Iterable[dict[str, Any]], all_cve_ids: set[str] | None) -> dict[str, Any]:
    scored = [score_record(record, all_cve_ids) for record in records]
    has_catalog = all_cve_ids is not None
    result = _summary(scored, has_catalog)
    slices: dict[str, dict[str, dict[str, Any]]] = {}
    for dimension in ("product_id", "question_type", "famous", "has_conflict"):
        values = sorted({str(item.get(dimension)) for item in scored})
        slices[dimension] = {
            value: _summary([item for item in scored if str(item.get(dimension)) == value], has_catalog)
            for value in values
        }
    result["slices"] = slices
    return result


def compare_summaries(baseline: dict[str, Any], rag: dict[str, Any]) -> dict[str, float | None]:
    metrics = (
        "cve_exact_match_accuracy", "status_accuracy", "cve_and_status_accuracy",
        "version_status_accuracy", "cve_precision", "cve_recall", "cve_f1",
        "nonexistent_cve_level_rate", "unsupported_cve_level_rate", "citation_precision",
        "citation_coverage", "conflict_case_accuracy", "correct_abstention_rate", "average_latency_seconds",
    )
    differences: dict[str, float | None] = {}
    for metric in metrics:
        left, right = baseline.get(metric, 0.0), rag.get(metric, 0.0)
        differences[metric] = right - left if left is not None and right is not None else None
    return differences
