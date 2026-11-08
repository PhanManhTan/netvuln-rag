from unittest.mock import Mock

import pytest

from config.settings import Settings
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
