import sys
from types import SimpleNamespace
from unittest.mock import Mock

from qdrant_client import models

from config.settings import Settings
from data_pipeline.schemas import TextChunk
from rag.retrieval.bm25 import BM25Index
from rag.retrieval.models import SearchResult
from rag.retrieval.retriever import Retriever


def result(identifier: str, point_id: str, score: float) -> SearchResult:
    return SearchResult(point_id, score, identifier, "overview", identifier, "https://example.test")


def test_bm25_ranks_matching_document_first() -> None:
    index = BM25Index(["FortiOS SSL VPN vulnerability", "RouterOS Winbox issue"])
    scores = index.scores("FortiOS VPN")
    assert scores[0] > scores[1]


def test_bm25_matches_identifiers_with_adjacent_punctuation() -> None:
    index = BM25Index(["Loại điểm yếu CWE-1284.", "Loại điểm yếu CWE-284."])

    scores = index.scores("CWE‑1284")

    assert scores[0] > 0
    assert scores[1] == 0


def test_rrf_rewards_chunk_returned_by_both_retrievers(monkeypatch) -> None:
    retriever = Retriever(Settings())
    shared = result("CVE-2024-0001", "shared", 0.8)
    monkeypatch.setattr(retriever, "_bm25_search", lambda *args: [shared, result("CVE-2024-0002", "bm25", 0.7)])
    monkeypatch.setattr(retriever, "_dense_search", lambda *args: [result("CVE-2024-0003", "dense", 0.9), shared])

    fused = retriever._hybrid_search("query", 3, "fortios")

    assert fused[0].point_id == "shared"
    assert {item.point_id for item in fused} == {"shared", "bm25", "dense"}


def test_dense_search_sends_text_to_cloud_inference(monkeypatch) -> None:
    settings = Settings(
        embedding_provider="qdrant_cloud",
        embedding_model="intfloat/multilingual-e5-small",
        embedding_query_prefix="query: ",
    )
    client = Mock()
    client.query_points.return_value.points = []
    connect = Mock(return_value=client)
    monkeypatch.setattr("rag.retrieval.retriever.QdrantClient", connect)
    retriever = Retriever(settings)

    assert retriever._dense_search("OpenSSH weakness", 5, "openssh") == []
    assert connect.call_args.kwargs["cloud_inference"] is True
    assert client.query_points.call_args.kwargs["query"] == models.Document(
        text="query: OpenSSH weakness", model=settings.embedding_model,
    )


def test_dense_search_resolves_only_chunks_from_the_current_snapshot() -> None:
    retriever = Retriever(Settings(embedding_provider="qdrant_cloud"))
    current = TextChunk(
        chunk_id="current", record_id="openssh:CVE-2024-0001", vulnerability_id="CVE-2024-0001",
        product_id="openssh", vendor="openbsd", product="openssh", section="overview",
        text="Verified chunk", source_id="nvd", source_url="https://example.test", content_hash="hash",
    )
    retriever._chunks = [current]
    retriever._client = Mock()
    retriever._client.query_points.return_value.points = [
        SimpleNamespace(id="old", payload={"chunk_id": "removed"}, score=0.9),
        SimpleNamespace(id="wrong-model", payload={"chunk_id": "current", "embedding_model": "different-model"}, score=0.85),
        SimpleNamespace(id="new", payload={"chunk_id": "current", "text": "stale text"}, score=0.8),
    ]

    results = retriever._dense_search("OpenSSH weakness", 5, "openssh")

    assert [(result.point_id, result.text, result.score) for result in results] == [
        ("current", "Verified chunk", 0.8),
    ]


def test_local_embedding_uses_configured_device_and_cache(monkeypatch, tmp_path) -> None:
    constructor = Mock()
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=constructor))
    settings = Settings(
        embedding_provider="local", embedding_device="cpu", embedding_cache_dir=tmp_path,
        embedding_query_prefix="query: ",
    )
    retriever = Retriever(settings)
    retriever._client = Mock()
    retriever._client.query_points.return_value.points = []

    assert retriever._dense_search("OpenSSH weakness", 5, "openssh") == []
    constructor.assert_called_once_with(settings.embedding_model, device="cpu", cache_folder=str(tmp_path))
    constructor.return_value.encode.assert_called_once_with("query: OpenSSH weakness", normalize_embeddings=True)
