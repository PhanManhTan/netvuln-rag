"""Evaluation metrics for answer, citation, conflict, and CVE hallucination."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from rag.identifiers import find_cve_ids


SCORER_VERSION = "2.0"
VERDICTS = {"affected", "not_affected", "insufficient_evidence", "answered"}
FILTER_ERRORS = {"unsupported_identifier_or_citation", "version_verdict_conflict"}


def extract_cves(text: str) -> set[str]:
    return set(find_cve_ids(text or ""))


def _clause_status(text: str) -> str:
    normalized = " ".join(text.lower().split())
    insufficient = ("không đủ bằng chứng", "chưa đủ bằng chứng", "không tìm thấy", "không có thông tin", "không thể xác nhận", "insufficient evidence", "cannot confirm")
    not_affected = ("không bị ảnh hưởng", "không ảnh hưởng", "nằm ngoài phạm vi", "không thuộc phạm vi", "not affected")
    affected = ("bị ảnh hưởng", "có ảnh hưởng", "nằm trong phạm vi ảnh hưởng")
    if any(marker in normalized for marker in insufficient):
        return "insufficient_evidence"
    if any(marker in normalized for marker in not_affected):
        return "not_affected"
    if any(marker in normalized for marker in affected) or re.search(r"\b(?:affected|affects?)\b", normalized):
        return "affected"
    return "answered"


def _conclusion_clauses(text: str) -> list[str]:
    # Legacy text has no reliable schema. Restrict the heuristic to conclusions;
    # a recommendation to upgrade to an unaffected version is not a verdict.
    cleaned = re.sub(r"[*_#]", "", text or "")
    conclusion = re.split(
        r"(?:khuyến\s*nghị|recommendations?|remediation|mitigation|nguồn kiểm chứng)\s*:",
        cleaned, maxsplit=1, flags=re.IGNORECASE,
    )[0]
    return re.split(r"(?<=[.!?])\s+|[;\n]+", conclusion)


def infer_status(text: str) -> str:
    """Best-effort legacy conclusion parser; structured verdicts take precedence."""
    for clause in _conclusion_clauses(text):
        status = _clause_status(clause)
        if status != "answered":
            return status
    return "answered"


def _legacy_assertions(text: str, status: str) -> set[str]:
    mentioned = extract_cves(text)
    if status != "insufficient_evidence":
        return mentioned
    # A pure abstention may repeat the question CVE. Mixed responses still retain
    # explicit claims in other clauses instead of clearing the entire answer.
    return {
        cve
        for clause in _conclusion_clauses(text)
        if _clause_status(clause) in {"affected", "not_affected"}
        for cve in extract_cves(clause)
    }


def _citation_urls(record: dict[str, Any]) -> set[str]:
    return {
        str(item.get("url", "")).rstrip("/")
        for item in record.get("citations", [])
        if item.get("url")
    }


def score_record(record: dict[str, Any], all_cve_ids: set[str] | None) -> dict[str, Any]:
    expected = {str(item).upper() for item in record.get("expected_cves", [])}
    mentioned = extract_cves(str(record.get("answer", "")))
    verdict = record.get("verdict")
    status = str(
        record.get("predicted_status") if record.get("review_correction")
        else verdict if verdict in VERDICTS
        else record.get("predicted_status") or infer_status(record.get("answer", ""))
    )
    failed = record.get("error") is not None or bool(record.get("output_error")) or status == "error"
    explicit = record.get("asserted_cves")
    assertions = (
        {str(item).upper() for item in explicit}
        if isinstance(explicit, (list, tuple))
        else _legacy_assertions(str(record.get("answer", "")), status)
    )
    predicted = set() if failed else assertions
    cve_exact = not failed and predicted == expected
    status_correct = not failed and status == record.get("expected_status")
    nonexistent = sorted(predicted - all_cve_ids) if all_cve_ids is not None else None
    unsupported = predicted - expected
    evidence_cves = record.get("document_evidence_cves", record.get("retrieved_evidence_cves"))
    retrieved = {str(item).upper() for item in evidence_cves or []}
    unsupported_by_evidence = predicted - retrieved if record.get("mode") == "rag" else set()
    expected_urls = {str(item).rstrip("/") for item in record.get("expected_source_urls", [])}
    citation_urls = set() if failed else _citation_urls(record)
    valid_citations = citation_urls & expected_urls
    raw_mentions = extract_cves(str(record.get("raw_answer") or record.get("answer", "")))
    raw_nonexistent = sorted(raw_mentions - all_cve_ids) if all_cve_ids is not None else None

    return {
        **record,
        "scorer_version": SCORER_VERSION,
        "scored_status": status,
        "mentioned_cves": sorted(mentioned),
        "predicted_cves": sorted(predicted),
        "assertion_source": "explicit" if isinstance(explicit, (list, tuple)) else "legacy_heuristic",
        "unlisted_cve_mentions": sorted(mentioned - assertions) if isinstance(explicit, (list, tuple)) else [],
        "response_failed": failed,
        "cve_exact_match": cve_exact,
        "status_correct": status_correct,
        "cve_and_status_correct": cve_exact and status_correct,
        "true_positive": len(expected & predicted),
        "false_positive": len(unsupported),
        "false_negative": len(expected - predicted),
        "nonexistent_cves": nonexistent,
        "raw_model_mentioned_cves": sorted(raw_mentions),
        "raw_model_nonexistent_mentions": raw_nonexistent,
        "raw_model_unsupported_by_evidence_mentions": sorted(raw_mentions - retrieved) if evidence_cves is not None else None,
        "unsupported_cves": sorted(unsupported),
        "unsupported_by_retrieved_evidence": sorted(unsupported_by_evidence),
        "evidence_cve_hits": len(expected & retrieved),
        "evidence_cve_expected": len(expected) if evidence_cves is not None else 0,
        "citation_count": len(citation_urls),
        "valid_citation_count": len(valid_citations),
        "citation_required": bool(expected_urls),
        "citation_covered": bool(expected_urls and valid_citations),
        "correct_abstention": status_correct and status == "insufficient_evidence" and not predicted,
    }


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _optional_ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _has_review_provenance(review: Any) -> bool:
    if not isinstance(review, dict) or not str(review.get("reviewed_by") or "").strip():
        return False
    try:
        reviewed_at = datetime.fromisoformat(str(review.get("reviewed_at") or "").replace("Z", "+00:00"))
        if reviewed_at.tzinfo is None or reviewed_at.utcoffset() is None:
            return False
        sources = review.get("source_urls") or review.get("evidence_sources")
        if not isinstance(sources, (list, tuple)) or not sources:
            return False
        return all(
            isinstance(source, str)
            and urlsplit(source).scheme in {"http", "https"}
            and bool(urlsplit(source).hostname)
            for source in sources
        )
    except (ValueError, TypeError):
        return False


def _review_summary(scored: list[dict[str, Any]]) -> dict[str, Any]:
    reviews = [
        item["manual_review"] for item in scored
        if _has_review_provenance(item.get("manual_review"))
    ]
    result: dict[str, Any] = {"manual_reviewed_questions": len(reviews)}
    for field in ("factual_correctness", "faithfulness", "citation_support"):
        values = [review[field] for review in reviews if type(review.get(field)) is bool]
        result[f"manual_{field}_questions"] = len(values)
        result[f"manual_{field}"] = _optional_ratio(sum(values), len(values))
    return result


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
    evidence_expected = sum(item["evidence_cve_expected"] for item in scored)
    citation_count = sum(item["citation_count"] for item in scored)
    valid_citation_count = sum(item["valid_citation_count"] for item in scored)
    citation_required = [item for item in scored if item["citation_required"]]
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    abstention_cases = [item for item in scored if item.get("expected_status") == "insufficient_evidence"]
    conflict_cases = [item for item in scored if item.get("has_conflict")]
    version_checks = [item for item in scored if item.get("question_type") == "cve_version_check"]
    return {
        "scorer_version": SCORER_VERSION,
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
        "true_positive_cves": tp,
        "false_positive_cves": fp,
        "false_negative_cves": fn,
        "predicted_cve_mentions": predicted_count,
        "expected_cve_mentions": tp + fn,
        "nonexistent_cve_count": nonexistent_count,
        "nonexistent_cve_level_rate": nonexistent_rate,
        "nonexistent_answer_level_rate": _safe_ratio(sum(bool(item["nonexistent_cves"]) for item in scored), total) if has_catalog else None,
        "raw_model_nonexistent_cve_mentions": sum(len(item["raw_model_nonexistent_mentions"]) for item in scored) if has_catalog else None,
        "raw_model_nonexistent_answer_rate": _optional_ratio(sum(bool(item["raw_model_nonexistent_mentions"]) for item in scored), total) if has_catalog else None,
        "raw_model_unsupported_by_evidence_mentions": sum(len(item["raw_model_unsupported_by_evidence_mentions"] or []) for item in scored),
        "unsupported_cve_count": unsupported_count,
        "unsupported_cve_precision": _safe_ratio(tp, tp + unsupported_count),
        "unsupported_cve_level_rate": _safe_ratio(unsupported_count, predicted_count),
        "unsupported_answer_level_rate": _safe_ratio(sum(bool(item["unsupported_cves"]) for item in scored), total),
        "retrieved_evidence_unsupported_cve_count": evidence_unsupported_count,
        "retrieved_evidence_unsupported_answer_rate": _safe_ratio(sum(bool(item["unsupported_by_retrieved_evidence"]) for item in scored), total),
        "evidence_cve_recall": (
            sum(item["evidence_cve_hits"] for item in scored) / evidence_expected if evidence_expected else None
        ),
        # URL overlap is not a measure of whether the source supports a claim.
        "citation_url_precision": _optional_ratio(valid_citation_count, citation_count),
        "citation_url_coverage": _optional_ratio(sum(item["citation_covered"] for item in citation_required), len(citation_required)),
        "citation_urls": citation_count,
        "expected_citation_questions": len(citation_required),
        "version_check_questions": len(version_checks),
        "conflict_questions": len(conflict_cases),
        "abstention_questions": len(abstention_cases),
        "conflict_case_accuracy": _optional_ratio(sum(item["status_correct"] for item in conflict_cases), len(conflict_cases)),
        "correct_abstention_rate": _optional_ratio(sum(item["correct_abstention"] for item in abstention_cases), len(abstention_cases)),
        "explicit_assertion_questions": sum(item["assertion_source"] == "explicit" for item in scored),
        "legacy_heuristic_questions": sum(item["assertion_source"] == "legacy_heuristic" for item in scored),
        "unlisted_cve_mentions_questions": sum(bool(item["unlisted_cve_mentions"]) for item in scored),
        "output_format_errors": sum(bool(item.get("output_error")) and item["output_error"] not in FILTER_ERRORS for item in scored),
        "filtered_responses": sum(item.get("output_error") in FILTER_ERRORS or bool(item.get("filtered_response")) for item in scored),
        "average_latency_seconds": _safe_ratio(sum(float(item.get("latency_seconds", 0.0)) for item in scored), total),
        **_review_summary(scored),
        # Compatibility aliases retained in artifacts while the report migrates.
        "citation_precision": _optional_ratio(valid_citation_count, citation_count),
        "citation_coverage": _optional_ratio(sum(item["citation_covered"] for item in citation_required), len(citation_required)),
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
    result["macro_by"] = {
        dimension: {
            metric: sum(values) / len(values) if values else None
            for metric in ("cve_exact_match_accuracy", "cve_and_status_accuracy", "cve_f1", "status_accuracy")
            for values in [[group[metric] for group in groups.values() if group[metric] is not None]]
        }
        for dimension, groups in slices.items() if dimension in {"product_id", "question_type"}
    }
    statuses = sorted({str(item.get("expected_status")) for item in scored} | {item["scored_status"] for item in scored})
    result["status_confusion_matrix"] = {
        expected: {
            predicted: sum(str(item.get("expected_status")) == expected and item["scored_status"] == predicted for item in scored)
            for predicted in statuses
        }
        for expected in statuses
    }
    return result


def compare_summaries(baseline: dict[str, Any], rag: dict[str, Any]) -> dict[str, float | None]:
    metrics = (
        "cve_exact_match_accuracy", "status_accuracy", "cve_and_status_accuracy",
        "version_status_accuracy", "cve_precision", "cve_recall", "cve_f1",
        "evidence_cve_recall", "nonexistent_cve_level_rate", "unsupported_cve_level_rate", "citation_url_precision",
        "citation_url_coverage", "citation_precision",
        "citation_coverage", "conflict_case_accuracy", "correct_abstention_rate", "average_latency_seconds",
    )
    differences: dict[str, float | None] = {}
    for metric in metrics:
        left, right = baseline.get(metric, 0.0), rag.get(metric, 0.0)
        differences[metric] = right - left if left is not None and right is not None else None
    return differences
