import json
from unittest.mock import Mock

import pytest

from config.settings import Settings
from data_pipeline.versioning import MatchStatus, VersionDecision
from rag.generation.chatbot import RAGChatbot
from rag.retrieval.models import ParsedQuery, QueryIntent, SearchBundle, SearchResult
from rag.retrieval.retriever import Retriever


@pytest.mark.parametrize(
    ("answer", "status", "citations"),
    [
        ("CVE‑2024‑0001 is affected 【 S1 】.", "answered", ["S1"]),
        ("CVE-2024-0001 is affected.", "answered", []),
        ("CVE‑2024‑9999 is affected [S1].", "insufficient_evidence", []),
        ("CVE-2024-0001 is affected [S3].", "insufficient_evidence", []),
    ],
)
def test_rag_validates_cve_mentions_and_reports_only_cited_sources(answer, status, citations, monkeypatch) -> None:
    settings = Settings()
    retriever = Retriever(settings)
    bundle = SearchBundle(
        query=ParsedQuery("What vulnerabilities affect OpenSSH?", QueryIntent.SEMANTIC),
        results=[
            SearchResult("first", 1, "CVE-2024-0001", "overview", "First", "https://example.test/first"),
            SearchResult("second", 1, "CVE-2024-0002", "overview", "Second", "https://example.test/second"),
        ],
        version_matches=[],
    )
    monkeypatch.setattr(retriever, "search", Mock(return_value=bundle))
    llm = Mock()
    llm.generate.return_value = answer

    result = RAGChatbot(settings, retriever, llm).ask(bundle.query.original)

    assert result["status"] == status
    assert [item["source_id"] for item in result["citations"]] == citations
    assert result["retrieved_evidence_cves"] == ["CVE-2024-0001", "CVE-2024-0002"]


def test_structured_verdict_survives_negative_recommendation():
    llm = Mock()
    llm.generate.return_value = json.dumps({
        "verdict": "affected",
        "answer": "CVE-2024-6387 bị ảnh hưởng. Hãy nâng cấp sang phiên bản không bị ảnh hưởng [S1].",
        "asserted_cves": ["CVE-2024-6387"],
    })
    bot = RAGChatbot(Settings(), retriever=Mock(), llm=llm)
    response = bot.answer_with_evidence("Có ảnh hưởng không?", "Evidence", [
        {"source_id": "S1", "vulnerability_id": "CVE-2024-6387", "url": "https://example.test/advisory"},
    ])
    assert response["status"] == "answered" and response["verdict"] == "affected"
    assert response["asserted_cves"] == ["CVE-2024-6387"]
    assert response["answer_format"] == "structured"
    assert '"asserted_cves"' in llm.generate.call_args.args[0]
    assert response["raw_answer"] == llm.generate.return_value


def test_filtered_model_assertions_are_preserved_for_audit():
    llm = Mock()
    llm.generate.return_value = json.dumps({
        "verdict": "affected", "answer": "CVE-2024-9999 is affected [S1].",
        "asserted_cves": ["CVE-2024-9999"],
    })
    bot = RAGChatbot(Settings(), retriever=Mock(), llm=llm)
    response = bot.answer_with_evidence("Question", "Evidence", [
        {"source_id": "S1", "vulnerability_id": "CVE-2024-6387", "url": "https://example.test/advisory"},
    ])
    assert response["status"] == "insufficient_evidence"
    assert response["asserted_cves"] == []
    assert response["model_asserted_cves"] == response["rejected_cves"] == ["CVE-2024-9999"]
    assert response["model_verdict"] == "affected"
    assert response["output_error"] == "unsupported_identifier_or_citation"
    assert response["raw_answer"] == llm.generate.return_value


def test_invalid_model_json_is_an_error_not_a_valid_abstention():
    llm = Mock()
    llm.generate.return_value = '{"verdict": "affected",'
    bot = RAGChatbot(Settings(), retriever=Mock(), llm=llm)
    response = bot.answer_with_evidence("Question", "Evidence", [
        {"source_id": "S1", "vulnerability_id": "CVE-2024-6387", "url": "https://example.test/advisory"},
    ])
    assert response["status"] == "error"
    assert response["output_error"] == "invalid_structured_answer"


def test_structured_answer_cannot_reverse_version_decision():
    llm = Mock()
    llm.generate.return_value = json.dumps({
        "verdict": "not_affected", "answer": "CVE-2024-6387 is not affected [S1].",
        "asserted_cves": ["CVE-2024-6387"],
    })
    retriever = Retriever(Settings())
    retriever.search = Mock(return_value=SearchBundle(
        query=ParsedQuery("OpenSSH 9.7p1 CVE-2024-6387?", QueryIntent.VULNERABILITY_CHECK),
        results=[SearchResult("chunk", 1, "CVE-2024-6387", "applicability", "Affected", "https://example.test/advisory")],
        version_matches=[VersionDecision("CVE-2024-6387", "9.7p1", MatchStatus.AFFECTED, "NVD membership")],
    ))
    response = RAGChatbot(Settings(), retriever=retriever, llm=llm).ask("Question")
    assert response["status"] == response["verdict"] == "insufficient_evidence"
    assert response["model_verdict"] == "not_affected"
    assert response["output_error"] == "version_verdict_conflict"
    assert response["citations"] == []
