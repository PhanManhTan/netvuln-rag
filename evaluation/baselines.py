"""Select the evidence supplied to the document and BM25 baselines."""

from __future__ import annotations

import json
from typing import Any

from config.products import ProductCatalog
from config.settings import Settings
from data_pipeline.nvd import NVDAdapter, cve_url
from data_pipeline.process import select_run
from rag.retrieval.models import SearchResult
from rag.retrieval.retriever import Retriever, format_evidence_context


Evidence = tuple[str, list[dict[str, str]]]


def document_contexts(retriever: Retriever, product_ids: set[str], max_chars: int) -> dict[str, Evidence]:
    by_product: dict[str, list[SearchResult]] = {product: [] for product in sorted(product_ids)}
    for chunk in retriever.chunks:
        if chunk.product_id in by_product:
            by_product[chunk.product_id].append(SearchResult(
                point_id=chunk.chunk_id,
                score=1.0,
                vulnerability_id=chunk.vulnerability_id,
                section=chunk.section,
                text=chunk.text,
                source_url=chunk.source_url,
            ))
    return {product: format_evidence_context(chunks, max_chars=max_chars) for product, chunks in by_product.items()}


def raw_snapshot_ids(
    questions: list[dict[str, Any]], products: list[dict[str, Any]], source: str,
) -> dict[str, str]:
    processed_runs = {row["product_id"]: row["input_runs"].get(source) for row in products}
    raw_runs: dict[str, str] = {}
    for item in questions:
        product = item["product_id"]
        run = item.get("raw_run_id") or processed_runs.get(product)
        if not run or run == "latest":
            raise ValueError(f"LLM + Raw needs a pinned raw_run_id for {product}. Build questions from the raw snapshot.")
        if raw_runs.setdefault(product, run) != run:
            raise ValueError(f"LLM + Raw needs one raw snapshot per product. {product} has multiple run IDs.")
    return raw_runs


def raw_contexts(
    settings: Settings, catalog: ProductCatalog, raw_runs: dict[str, str], max_chars: int,
) -> dict[str, Evidence]:
    contexts = {}
    for product, run in raw_runs.items():
        profile = catalog.by_id(product)
        adapter = NVDAdapter(settings, profile)
        run_dir = select_run(settings.raw_product_source_dir(product, "nvd"), run)
        if profile.versions:
            raw_rows = (
                row
                for _, records in adapter.read_version_queries(run_dir, require_complete=True)
                for row in records.values()
            )
        else:
            raw_rows = adapter.read_product_records(run_dir)
        unique: dict[str, dict[str, Any]] = {}
        for _, raw in raw_rows:
            unique.setdefault(raw["id"].upper(), raw)
        records = [
            SearchResult(cve, 1.0, cve, "raw", json.dumps(raw, ensure_ascii=False, separators=(",", ":")), cve_url(cve))
            for cve, raw in sorted(unique.items())
        ]
        context = format_evidence_context(records, max_chars=max_chars)
        if records and not context[1]:
            raise ValueError(f"No whole raw CVE record for {product} fits in {max_chars} characters. Increase --context-max-chars.")
        contexts[product] = context
    return contexts


def bm25_context(retriever: Retriever, question: str, top_k: int, max_chars: int) -> Evidence:
    ranked = retriever.search_bm25(question, top_k)
    return format_evidence_context(ranked, max_chars=max_chars)
