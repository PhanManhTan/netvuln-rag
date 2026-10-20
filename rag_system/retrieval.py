"""Query parsing, Qdrant retrieval and evidence preparation."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer

from rag_system.config import Settings, get_settings
from rag_system.models import (
    MatchStatus,
    ParsedQuery,
    QueryIntent,
    SearchBundle,
    SearchResult,
    VersionDecision,
)
from rag_system.versioning import VersionMatcher


VULNERABILITY_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
EXPLICIT_VERSION_PATTERN = re.compile(
    r"(?:phiên\s*bản|version)\s*v?([0-9]+(?:\.[0-9A-Za-z-]+)+)",
    re.IGNORECASE,
)


def parse_query(
    question: str,
    default_product: str | None = None,
    product_aliases: tuple[str, ...] = (),
) -> ParsedQuery:
    """Parse a query using a configurable product profile."""
    text = question.strip()
    identifier_match = VULNERABILITY_ID_PATTERN.search(text)
    vulnerability_id = (
        identifier_match.group(0).upper() if identifier_match else None
    )

    aliases = tuple(alias for alias in product_aliases if alias)
    matched_alias = next(
        (alias for alias in aliases if alias.lower() in text.lower()),
        None,
    )
    product = default_product if matched_alias else None

    version = None
    match = EXPLICIT_VERSION_PATTERN.search(text)
    if match:
        version = match.group(1)
    else:
        for alias in aliases:
            alias_pattern = re.compile(
                rf"\b{re.escape(alias)}\s+v?([0-9]+(?:\.[0-9A-Za-z-]+)+)",
                re.IGNORECASE,
            )
            match = alias_pattern.search(text)
            if match:
                version = match.group(1)
                break

    if version and default_product:
        product = default_product

    if vulnerability_id and version:
        intent = QueryIntent.VULNERABILITY_CHECK
    elif product and version:
        intent = QueryIntent.VERSION_INVENTORY
    elif vulnerability_id:
        intent = QueryIntent.VULNERABILITY_DETAIL
    else:
        intent = QueryIntent.SEMANTIC

    return ParsedQuery(text, intent, vulnerability_id, product, version)


class Retriever:
    """Return filtered evidence without invoking an LLM."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.version_matcher = VersionMatcher()
        self._client: QdrantClient | None = None
        self._embedding_model: SentenceTransformer | None = None

    @property
    def client(self) -> QdrantClient:
        if self._client is None:
            self._client = QdrantClient(
                url=self.settings.qdrant_url,
                api_key=self.settings.qdrant_api_key or None,
            )
        return self._client

    @property
    def embedding_model(self) -> SentenceTransformer:
        if self._embedding_model is None:
            self._embedding_model = SentenceTransformer(self.settings.embedding_model)
        return self._embedding_model

    def search(self, question: str, top_k: int | None = None) -> SearchBundle:
        query = parse_query(
            question,
            default_product=self.settings.target_product,
            product_aliases=(
                self.settings.target_product,
                *self.settings.target_product_aliases,
            ),
        )
        limit = top_k if top_k is not None else self.settings.top_k
        if limit < 1:
            raise ValueError("top_k phải lớn hơn 0")

        results = self._deduplicate(self._retrieve(query, limit))
        version_matches = self._match_versions(query, results)

        if query.intent == QueryIntent.VERSION_INVENTORY:
            affected = {
                match.vulnerability_id
                for match in version_matches
                if match.status == MatchStatus.AFFECTED
            }
            results = [
                result
                for result in results
                if result.vulnerability_id in affected
            ]

        return SearchBundle(query, results[:limit], version_matches)

    def format_context(self, bundle: SearchBundle) -> tuple[str, list[dict[str, str]]]:
        matches = {
            match.vulnerability_id: match for match in bundle.version_matches
        }
        context_blocks: list[str] = []
        citations: list[dict[str, str]] = []
        for index, result in enumerate(bundle.results, 1):
            source_id = f"S{index}"
            version_line = ""
            if result.vulnerability_id in matches:
                decision = matches[result.vulnerability_id]
                version_line = (
                    f"\nKết quả version matcher: {decision.status.value}. "
                    f"{decision.reason}"
                )
            context_blocks.append(
                f"[{source_id}] {result.vulnerability_id}\n"
                f"Nguồn: {result.source_url}{version_line}\n"
                f"{result.text}"
            )
            if result.source_url:
                citations.append(
                    {
                        "source_id": source_id,
                        "vulnerability_id": result.vulnerability_id,
                        "url": result.source_url,
                    }
                )
        return "\n\n---\n\n".join(context_blocks), citations

    def health(self) -> dict[str, Any]:
        collection = self.client.get_collection(self.settings.qdrant_collection)
        return {
            "vector_store": "ok",
            "collection": self.settings.qdrant_collection,
            "points_count": collection.points_count,
        }

    def _retrieve(self, query: ParsedQuery, top_k: int) -> list[SearchResult]:
        if query.intent in {
            QueryIntent.VULNERABILITY_CHECK,
            QueryIntent.VULNERABILITY_DETAIL,
        }:
            return self._exact_lookup(query.vulnerability_id, query.product)
        if query.intent == QueryIntent.VERSION_INVENTORY:
            return self._exact_lookup(product=query.product)
        return self._semantic_search(query.original, top_k, query.product)

    def _semantic_search(
        self,
        question: str,
        top_k: int,
        product: str | None,
    ) -> list[SearchResult]:
        vector = self.embedding_model.encode(
            question, normalize_embeddings=True
        ).tolist()
        response = self.client.query_points(
            collection_name=self.settings.qdrant_collection,
            query=vector,
            query_filter=self._make_filter(product=product),
            limit=top_k,
            score_threshold=self.settings.min_score or None,
            with_payload=True,
        )
        return [self._to_result(point) for point in response.points]

    def _exact_lookup(
        self,
        vulnerability_id: str | None = None,
        product: str | None = None,
    ) -> list[SearchResult]:
        results: list[SearchResult] = []
        offset: Any = None
        while True:
            points, offset = self.client.scroll(
                collection_name=self.settings.qdrant_collection,
                scroll_filter=self._make_filter(vulnerability_id, product),
                limit=256,
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )
            results.extend(self._to_result(point) for point in points)
            if offset is None:
                return results

    def _match_versions(
        self,
        query: ParsedQuery,
        results: list[SearchResult],
    ) -> list[VersionDecision]:
        if not query.version:
            return []

        rules_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for result in results:
            rules_by_id.setdefault(result.vulnerability_id, [])
            for rule in result.payload.get("affected_versions", []):
                if rule not in rules_by_id[result.vulnerability_id]:
                    rules_by_id[result.vulnerability_id].append(rule)

        return [
            self.version_matcher.evaluate(identifier, query.version, rules)
            for identifier, rules in sorted(rules_by_id.items())
        ]

    @staticmethod
    def _deduplicate(results: list[SearchResult]) -> list[SearchResult]:
        unique: dict[tuple[str, str], SearchResult] = {}
        for result in results:
            key = (result.vulnerability_id, result.section)
            previous = unique.get(key)
            if previous is None or result.score > previous.score:
                unique[key] = result
        return list(unique.values())

    @staticmethod
    def _make_filter(
        vulnerability_id: str | None = None,
        product: str | None = None,
    ) -> models.Filter | None:
        conditions: list[models.FieldCondition] = []
        if vulnerability_id:
            conditions.append(
                models.FieldCondition(
                    key="vulnerability_id",
                    match=models.MatchValue(value=vulnerability_id.upper()),
                )
            )
        if product:
            conditions.append(
                models.FieldCondition(
                    key="product",
                    match=models.MatchValue(value=product.lower()),
                )
            )
        return models.Filter(must=conditions) if conditions else None

    @staticmethod
    def _to_result(point: Any) -> SearchResult:
        payload = dict(point.payload or {})
        raw_score = getattr(point, "score", None)
        return SearchResult(
            point_id=str(point.id),
            score=float(raw_score) if raw_score is not None else 1.0,
            vulnerability_id=str(payload.get("vulnerability_id", "")),
            section=str(payload.get("section", "overview")),
            text=str(payload.get("text", "")),
            source_url=str(payload.get("source_url", "")),
            payload=payload,
        )
