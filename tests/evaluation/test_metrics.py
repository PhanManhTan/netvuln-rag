from tests.evaluation.metrics import extract_cves, infer_status, summarize


def test_extract_cves_is_case_insensitive() -> None:
    assert extract_cves("cve-2024-21762 và CVE-2023-12345") == {
        "CVE-2024-21762",
        "CVE-2023-12345",
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
        known_cves={"CVE-2024-21762"},
    )

    assert summary["hallucinated_cve_count"] == 1

