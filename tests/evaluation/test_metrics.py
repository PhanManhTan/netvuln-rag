from evaluation.metrics import extract_cves, infer_status, summarize


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
