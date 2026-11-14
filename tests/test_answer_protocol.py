import json

import pytest

from rag.generation.answers import parse_answer


def test_explicit_verdict_is_separate_from_recommendation():
    parsed = parse_answer(json.dumps({
        "verdict": "affected",
        "answer": "CVE-2024-6387 bị ảnh hưởng. Nâng cấp sang phiên bản không bị ảnh hưởng [S1].",
        "asserted_cves": ["cve-2024-6387"],
    }, ensure_ascii=False))
    assert parsed.verdict == "affected"
    assert parsed.asserted_cves == ("CVE-2024-6387",)
    assert parsed.structured and parsed.error is None


def test_partial_abstention_does_not_erase_assertions():
    parsed = parse_answer(json.dumps({
        "verdict": "insufficient_evidence",
        "answer": "CVE-2024-6387 is supported; other candidates cannot be confirmed.",
        "asserted_cves": ["CVE-2024-6387"],
    }))
    assert parsed.verdict == "insufficient_evidence"
    assert parsed.asserted_cves == ("CVE-2024-6387",)


@pytest.mark.parametrize("payload", [
    '{"verdict": "affected",',
    '{"verdict": "affected", "verdict": "not_affected", "answer": "x", "asserted_cves": []}',
    '[{"verdict": "affected"}]',
    '{"verdict": [], "answer": "x", "asserted_cves": []}',
    '{"verdict": "affected", "answer": "x", "asserted_cves": "CVE-2024-6387"}',
    '{"verdict": "affected", "answer": "x", "asserted_cves": ["CVE-2024-6387"]}',
    '{"verdict": "affected", "answer": "x", "asserted_cves": [123]}',
    'Here is the result: {"verdict": "affected", "answer": "x", "asserted_cves": []}',
    '{"verdict": "affected", "answer": "CVE-2024-6387 is affected.", "asserted_cves": []}',
    '```json\n{"verdict": "affected"}\n```',
])
def test_invalid_envelopes_are_not_successful_legacy_answers(payload):
    parsed = parse_answer(payload)
    assert parsed.structured and parsed.error


def test_legacy_text_is_explicitly_distinguished():
    parsed = parse_answer("CVE-2024-6387 is affected [S1].")
    assert parsed.verdict is None and parsed.asserted_cves is None
    assert not parsed.structured and parsed.error is None


def test_fenced_json_normalizes_unicode_ids_and_deduplicates():
    parsed = parse_answer('```json\n{"verdict":"affected","answer":"CVE‑2024‑6387 [S1]","asserted_cves":["CVE‑2024‑6387","cve-2024-6387"]}\n```')
    assert parsed.asserted_cves == ("CVE-2024-6387",)
    assert parsed.error is None
