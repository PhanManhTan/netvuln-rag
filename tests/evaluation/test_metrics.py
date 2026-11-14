import pytest

from evaluation.metrics import SCORER_VERSION, extract_cves, infer_status, score_record, summarize


def test_extract_cves_is_case_insensitive() -> None:
    assert extract_cves("cve-2024-21762 và CVE-2023-12345") == {
        "CVE-2024-21762",
        "CVE-2023-12345",
    }


def test_extract_cves_accepts_typographic_hyphens() -> None:
    assert extract_cves("CVE‑2023‑51384, cve–2025–26466") == {
        "CVE-2023-51384",
        "CVE-2025-26466",
    }


def test_negative_status_checked_before_affected_status() -> None:
    assert infer_status("Phiên bản này không bị ảnh hưởng.") == "not_affected"


def test_unknown_cve_is_hallucination_when_answer_asserts_affected() -> None:
    summary = summarize(
        [
            {
                "answer": "CVE-2099-99999 bị ảnh hưởng.",
                "expected_cves": [],
                "expected_status": "insufficient_evidence",
                "predicted_status": "affected",
                "citations": [],
                "latency_seconds": 0.1,
            }
        ],
        all_cve_ids={"CVE-2024-21762"},
    )

    assert summary["hallucinated_cve_count"] == 1
    assert summary["nonexistent_cve_count"] == 1


def test_existing_but_wrong_product_cve_is_unsupported_not_nonexistent() -> None:
    summary = summarize(
        [
            {
                "mode": "rag",
                "answer": "CVE-2024-99999 bị ảnh hưởng.",
                "expected_cves": ["CVE-2024-21762"],
                "expected_status": "affected",
                "predicted_status": "affected",
                "retrieved_evidence_cves": ["CVE-2024-21762"],
                "product_id": "fortios",
                "question_type": "cve_version_check",
                "famous": False,
                "has_conflict": False,
            }
        ],
        all_cve_ids={"CVE-2024-21762", "CVE-2024-99999"},
    )
    assert summary["nonexistent_cve_count"] == 0
    assert summary["unsupported_cve_count"] == 1
    assert summary["retrieved_evidence_unsupported_cve_count"] == 1
    assert summary["slices"]["product_id"]["fortios"]["questions"] == 1
    assert summary["slices"]["question_type"]["cve_version_check"]["unsupported_cve_count"] == 1


def test_failed_empty_answer_is_not_counted_as_an_exact_match() -> None:
    summary = summarize(
        [{
            "answer": "",
            "question_type": "cve_version_check",
            "expected_cves": [],
            "expected_status": "insufficient_evidence",
            "predicted_status": "error",
            "error": "Provider unavailable",
        }],
        all_cve_ids=None,
    )
    assert summary["errors"] == 1
    assert summary["cve_exact_match_accuracy"] == 0
    assert summary["cve_and_status_accuracy"] == 0
    assert summary["version_status_accuracy"] == 0


@pytest.mark.parametrize("answer", [
    "Có. Theo NVD, CVE-2008-3844 affects OpenSSH 9.6p1. Khuyến nghị: dùng phiên bản không bị ảnh hưởng.",
    "CVE-2024-21762 bị ảnh hưởng.\n**Khuyến nghị:** cập nhật lên bản không bị ảnh hưởng.",
    "OpenSSH is affected. Recommendation: upgrade to a version not affected.",
    "CVE-2024-21762 bị ảnh hưởng. Không đủ bằng chứng cho các CVE khác.",
])
def test_legacy_verdict_reads_conclusion_not_recommendations(answer) -> None:
    assert infer_status(answer) == "affected"


def test_structured_verdict_takes_precedence_over_explanation_markers() -> None:
    result = score_record({
        "answer": "CVE-2024-21762 bị ảnh hưởng; khuyến nghị dùng phiên bản không bị ảnh hưởng.",
        "verdict": "affected", "predicted_status": "not_affected",
        "asserted_cves": ["CVE-2024-21762"],
        "expected_cves": ["CVE-2024-21762"], "expected_status": "affected",
    }, None)
    assert result["cve_and_status_correct"] is True
    assert result["scorer_version"] == SCORER_VERSION
    assert result["assertion_source"] == "explicit"


def test_partial_assertion_is_not_hidden_by_overall_abstention() -> None:
    result = score_record({
        "answer": "Không đủ bằng chứng cho phiên bản này. CVE-2099-99999 bị ảnh hưởng.",
        "verdict": "insufficient_evidence", "asserted_cves": ["CVE-2099-99999"],
        "expected_cves": [], "expected_status": "insufficient_evidence",
    }, {"CVE-2024-21762"})
    assert result["nonexistent_cves"] == ["CVE-2099-99999"]
    assert result["cve_exact_match"] is False
    assert result["correct_abstention"] is False


def test_legacy_abstention_preserves_claims_elsewhere_but_not_repeated_question_id() -> None:
    result = score_record({
        "answer": "Không đủ bằng chứng cho CVE-2024-21762. CVE-2099-99999 bị ảnh hưởng.",
        "predicted_status": "insufficient_evidence",
        "expected_cves": [], "expected_status": "insufficient_evidence",
    }, None)
    assert result["mentioned_cves"] == ["CVE-2024-21762", "CVE-2099-99999"]
    assert result["predicted_cves"] == ["CVE-2099-99999"]


def test_url_match_is_reported_separately_from_unreviewed_factual_quality() -> None:
    summary = summarize([{
        "answer": "CVE-2024-21762 bị ảnh hưởng.",
        "expected_cves": ["CVE-2024-21762"], "expected_status": "affected",
        "expected_source_urls": ["https://example.com/advisory"],
        "citations": [{"url": "https://example.com/advisory"}],
    }], None)
    assert summary["citation_url_precision"] == summary["citation_precision"] == 1
    assert summary["expected_citation_questions"] == 1
    assert summary["manual_factual_correctness"] is None
    assert summary["manual_faithfulness"] is None
    assert summary["manual_citation_support"] is None
    assert summary["conflict_questions"] == summary["abstention_questions"] == 0
    assert summary["conflict_case_accuracy"] is summary["correct_abstention_rate"] is None


def test_manual_quality_metrics_use_only_reviewed_denominators() -> None:
    summary = summarize([
        {"manual_review": {"factual_correctness": True}},
        {"manual_review": {
            "reviewed_by": "reviewer", "reviewed_at": "2026-11-09T00:00:00Z",
            "source_urls": ["https://example.com/advisory"],
            "factual_correctness": False, "faithfulness": True, "citation_support": None,
        }},
    ], None)
    assert summary["manual_reviewed_questions"] == 1
    assert summary["manual_factual_correctness_questions"] == 1
    assert summary["manual_factual_correctness"] == 0
    assert summary["manual_faithfulness"] == 1
    assert summary["manual_citation_support"] is None


@pytest.mark.parametrize("invalid", [
    {"reviewed_by": "  "},
    {"reviewed_at": "2026-11-09"},
    {"reviewed_at": "not-a-date"},
    {"source_urls": ["file:///tmp/advisory"]},
    {"source_urls": ["https:///missing-host"]},
    {"source_urls": "https://example.com/advisory"},
])
def test_malformed_review_provenance_does_not_count_as_factual_validation(invalid) -> None:
    review = {
        "reviewed_by": "reviewer", "reviewed_at": "2026-11-09T00:00:00Z",
        "source_urls": ["https://example.com/advisory"], "factual_correctness": True,
        **invalid,
    }
    summary = summarize([{"manual_review": review}], None)
    assert summary["manual_reviewed_questions"] == 0
    assert summary["manual_factual_correctness"] is None


def test_filtered_response_is_not_a_correct_abstention() -> None:
    result = score_record({
        "answer": "Phản hồi đã bị loại.", "verdict": "insufficient_evidence", "asserted_cves": [],
        "output_error": "unsupported_identifier_or_citation",
        "expected_cves": [], "expected_status": "insufficient_evidence",
    }, None)
    assert result["response_failed"] is True
    assert result["correct_abstention"] is False
    assert result["cve_exact_match"] is False


def test_filter_diagnostics_keep_raw_model_ids_without_counting_format_failure() -> None:
    summary = summarize([{
        "answer": "Phản hồi đã bị loại.", "verdict": "insufficient_evidence", "asserted_cves": [],
        "raw_answer": '{"answer":"CVE-2099-99999 bị ảnh hưởng"}',
        "model_asserted_cves": ["CVE-2099-99999"],
        "output_error": "unsupported_identifier_or_citation", "retrieved_evidence_cves": ["CVE-2024-21762"],
        "expected_cves": [], "expected_status": "insufficient_evidence",
    }], {"CVE-2024-21762"})
    assert summary["filtered_responses"] == 1
    assert summary["output_format_errors"] == 0
    assert summary["correct_abstention_rate"] == 0
    assert summary["raw_model_nonexistent_cve_mentions"] == 1
    assert summary["raw_model_unsupported_by_evidence_mentions"] == 1
    assert summary["nonexistent_cve_count"] == 0


def test_audited_correction_overrides_original_structured_verdict() -> None:
    result = score_record({
        "answer": "CVE-2024-21762 bị ảnh hưởng.", "verdict": "not_affected",
        "predicted_status": "affected", "review_correction": {"reviewed_by": "reviewer"},
        "asserted_cves": ["CVE-2024-21762"],
        "expected_cves": ["CVE-2024-21762"], "expected_status": "affected",
    }, None)
    assert result["cve_and_status_correct"] is True
