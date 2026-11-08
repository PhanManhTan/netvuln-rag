"""Structured-first retrieval with BM25/dense reciprocal-rank fusion."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import replace
from functools import cached_property
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any

from qdrant_client import QdrantClient, models

from config.products import get_product_catalog
from config.settings import Settings, get_settings
from data_pipeline.process import processed_snapshot_paths
from data_pipeline.schemas import TextChunk, VulnerabilityRecord
from data_pipeline.versioning import MatchStatus, VersionDecision, VersionMatcher, rule_matches
from rag.retrieval.bm25 import BM25Index
from rag.retrieval.models import ParsedQuery, QueryIntent, SearchBundle, SearchResult
from rag.retrieval.parser import parse_query

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer


class Retriever:
    """Use validated records for conclusions and chunks only as supporting evidence."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        snapshot_paths: dict[str, list[Path]] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.catalog = get_product_catalog(self.settings.product_config_file)
        self.version_matcher = VersionMatcher()
        self._client: QdrantClient | None = None
        self._embedding_model: SentenceTransformer | None = None
        self._records: dict[tuple[str, str], VulnerabilityRecord] | None = None
        self._chunks: list[TextChunk] | None = None
        self._bm25: BM25Index | None = None
        self._snapshot_paths = snapshot_paths
        self._snapshot_lock = Lock()

    @property
    def client(self) -> QdrantClient:
        if self._client is None:
            cloud = self.settings.embedding_provider == "qdrant_cloud"
            self._client = QdrantClient(
                url=self.settings.qdrant_url,
                api_key=self.settings.qdrant_api_key or None,
                cloud_inference=cloud,
                timeout=60 if cloud else None,
            )
        return self._client

    @property
    def embedding_model(self) -> SentenceTransformer:
        if self._embedding_model is None:
            from sentence_transformers import SentenceTransformer

            cache_folder = self.settings.embedding_cache_dir
            self._embedding_model = SentenceTransformer(
                self.settings.embedding_model,
                device=self.settings.embedding_device,
                cache_folder=str(cache_folder) if cache_folder else None,
            )
        return self._embedding_model

    @property
    def _artifact_paths(self) -> dict[str, list[Path]]:
        with self._snapshot_lock:
            if self._snapshot_paths is None:
                self._snapshot_paths = processed_snapshot_paths(self.settings)
            return self._snapshot_paths

    @property
    def records(self) -> dict[tuple[str, str], VulnerabilityRecord]:
        if self._records is None:
            records = {}
            for path in self._artifact_paths["structured"]:
                with path.open("r", encoding="utf-8") as file:
                    for line in file:
                        if line.strip():
                            record = VulnerabilityRecord.model_validate_json(line)
                            records[(record.product_id, record.vulnerability_id)] = record
            self._records = records
        return self._records

    @property
    def chunks(self) -> list[TextChunk]:
        if self._chunks is None:
            chunks = []
            for path in self._artifact_paths["chunks"]:
                with path.open("r", encoding="utf-8") as file:
                    chunks.extend(TextChunk.model_validate_json(line) for line in file if line.strip())
            self._chunks = chunks
        return self._chunks

    @cached_property
    def _chunks_by_id(self) -> dict[str, TextChunk]:
        return {chunk.chunk_id: chunk for chunk in self.chunks}

    @property
    def bm25(self) -> BM25Index:
        if self._bm25 is None:
            self._bm25 = BM25Index([chunk.text for chunk in self.chunks])
        return self._bm25

    def search(self, question: str, top_k: int | None = None) -> SearchBundle:
        query = parse_query(
            question,
            default_product=self.settings.default_product_id,
            catalog=self.catalog,
        )
        limit = top_k if top_k is not None else self.settings.top_k
        if limit < 1:
            raise ValueError("top_k phải lớn hơn 0")

        decisions = self._structured_decisions(query)
        if query.intent in {QueryIntent.VULNERABILITY_CHECK, QueryIntent.VERSION_INVENTORY}:
            results = self._evidence_for_decisions(query, decisions)
        elif query.intent == QueryIntent.VULNERABILITY_DETAIL:
            results = self._local_exact(query.vulnerability_id, query.product_id)
        else:
            results = self._hybrid_search(query.original, limit, query.product_id)
        ranked = self._deduplicate(results)
        if query.intent not in {QueryIntent.VULNERABILITY_CHECK, QueryIntent.VERSION_INVENTORY}:
            ranked = ranked[:limit]
        return SearchBundle(query, ranked, decisions)

    def _structured_decisions(self, query: ParsedQuery) -> list[VersionDecision]:
        if not query.version or not query.product_id:
            return []
        candidates = [
            record for (product_id, cve), record in self.records.items()
            if product_id == query.product_id and (not query.vulnerability_id or cve == query.vulnerability_id)
        ]
        return [self.version_matcher.evaluate_record(record, query.version) for record in sorted(candidates, key=lambda item: item.vulnerability_id)]

    def _evidence_for_decisions(self, query: ParsedQuery, decisions: list[VersionDecision]) -> list[SearchResult]:
        selected: list[SearchResult] = []
        for decision in decisions:
            if decision.status == MatchStatus.UNKNOWN:
                continue
            if query.intent == QueryIntent.VERSION_INVENTORY and decision.status != MatchStatus.AFFECTED:
                continue
            candidate_chunks = [
                chunk for chunk in self.chunks
                if chunk.product_id == query.product_id and chunk.vulnerability_id == decision.vulnerability_id
            ]
            if decision.source_ids:
                candidate_chunks = [chunk for chunk in candidate_chunks if chunk.source_id in decision.source_ids]
            if query.version:
                candidate_chunks = [
                    chunk for chunk in candidate_chunks
                    if chunk.version_rule is None or rule_matches(chunk.version_rule, query.version)
                ]
            applicability = [chunk for chunk in candidate_chunks if chunk.version_rule is not None]
            if applicability and query.intent == QueryIntent.VERSION_INVENTORY:
                candidate_chunks = applicability
            selected.extend(self._chunk_result(chunk, 1.0) for chunk in candidate_chunks)
        return selected

    def _local_exact(self, vulnerability_id: str | None, product_id: str | None) -> list[SearchResult]:
        return [
            self._chunk_result(chunk, 1.0)
            for chunk in self.chunks
            if (not vulnerability_id or chunk.vulnerability_id == vulnerability_id)
            and (not product_id or chunk.product_id == product_id)
        ]

    def _bm25_search(self, question: str, top_k: int, product_id: str | None) -> list[SearchResult]:
        scored = [
            (score, chunk) for score, chunk in zip(self.bm25.scores(question), self.chunks, strict=True)
            if score > 0 and (not product_id or chunk.product_id == product_id)
        ]
        scored.sort(key=lambda item: item[0], reverse=True)
        return [self._chunk_result(chunk, score) for score, chunk in scored[:top_k]]

    def _dense_search(self, question: str, top_k: int, product_id: str | None) -> list[SearchResult]:
        if self.settings.embedding_provider == "qdrant_cloud":
            vector = models.Document(
                text=self.settings.embedding_query_prefix + question,
                model=self.settings.embedding_model,
            )
        else:
            vector = self.embedding_model.encode(question, normalize_embeddings=True).tolist()
        response = self.client.query_points(
            collection_name=self.settings.qdrant_collection,
            query=vector,
            query_filter=self._make_filter(product_id=product_id),
            limit=top_k,
            score_threshold=self.settings.min_score or None,
            with_payload=["chunk_id", "embedding_model"],
        )
        results = []
        for point in response.points:
            payload = point.payload or {}
            embedding_model = payload.get("embedding_model")
            if embedding_model and embedding_model != self.settings.embedding_model:
                continue
            chunk = self._chunks_by_id.get(str(payload.get("chunk_id") or point.id))
            if chunk is not None and (not product_id or chunk.product_id == product_id):
                results.append(self._chunk_result(chunk, point.score))
        return results

    def _hybrid_search(self, question: str, top_k: int, product_id: str | None) -> list[SearchResult]:
        bm25 = self._bm25_search(question, max(top_k * 3, 10), product_id)
        dense = self._dense_search(question, max(top_k * 3, 10), product_id)
        scores: defaultdict[str, float] = defaultdict(float)
        values: dict[str, SearchResult] = {}
        for ranked in (bm25, dense):
            for rank, result in enumerate(ranked, 1):
                scores[result.point_id] += 1 / (60 + rank)
                values[result.point_id] = result
        return [
            replace(values[point_id], score=score)
            for point_id, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)[:top_k]
        ]

    def format_context(self, bundle: SearchBundle) -> tuple[str, list[dict[str, str]]]:
        matches = {match.vulnerability_id: match for match in bundle.version_matches}
        blocks: list[str] = []
        citations: list[dict[str, str]] = []
        for index, result in enumerate(bundle.results, 1):
            label = f"S{index}"
            decision = matches.get(result.vulnerability_id)
            decision_text = f"\nVersion decision: {decision.status.value}. {decision.reason}" if decision else ""
            blocks.append(f"[{label}] {result.vulnerability_id}\nSource: {result.source_url}{decision_text}\n{result.text}")
            citations.append({"source_id": label, "vulnerability_id": result.vulnerability_id, "url": result.source_url})
        return "\n\n---\n\n".join(blocks), citations

    def health(self) -> dict[str, Any]:
        if not self.records or not self.chunks:
            raise ValueError("Processed snapshot is empty")
        collection = self.client.get_collection(self.settings.qdrant_collection)
        return {
            "vector_store": "ok",
            "collection": self.settings.qdrant_collection,
            "points_count": collection.points_count,
            "structured_records": len(self.records),
            "local_chunks": len(self.chunks),
        }

    @staticmethod
    def _deduplicate(results: list[SearchResult]) -> list[SearchResult]:
        unique: dict[str, SearchResult] = {}
        for result in results:
            previous = unique.get(result.point_id)
            if previous is None or result.score > previous.score:
                unique[result.point_id] = result
        return sorted(unique.values(), key=lambda item: item.score, reverse=True)

    @staticmethod
    def _make_filter(vulnerability_id: str | None = None, product_id: str | None = None) -> models.Filter | None:
        conditions: list[models.FieldCondition] = []
        if vulnerability_id:
            conditions.append(models.FieldCondition(key="vulnerability_id", match=models.MatchValue(value=vulnerability_id.upper())))
        if product_id:
            conditions.append(models.FieldCondition(key="product_id", match=models.MatchValue(value=product_id)))
        return models.Filter(must=conditions) if conditions else None

    @staticmethod
    def _chunk_result(chunk: TextChunk, score: float) -> SearchResult:
        payload = chunk.model_dump(mode="json")
        return SearchResult(chunk.chunk_id, score, chunk.vulnerability_id, chunk.section, chunk.text, chunk.source_url, payload)

