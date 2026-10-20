"""Convert normalized vulnerability records into vector-store points."""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Iterable

from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer

from rag_system.config import Settings, get_settings


POINT_NAMESPACE = uuid.UUID("9cf154ef-4f68-48be-9125-b7ab813663c5")


def load_records(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                yield json.loads(line)


def format_version_rule(rule: dict[str, Any]) -> str:
    exact_version = rule.get("version")
    if exact_version and exact_version not in {"*", "-"}:
        return f"version {exact_version}"

    boundaries = []
    labels = (
        ("version_start_including", ">="),
        ("version_start_excluding", ">"),
        ("version_end_including", "<="),
        ("version_end_excluding", "<"),
    )
    for field, operator in labels:
        if rule.get(field):
            boundaries.append(f"version {operator} {rule[field]}")
    return " và ".join(boundaries) if boundaries else "all versions"


def create_chunks(record: dict[str, Any]) -> list[dict[str, str]]:
    """Create source-independent overview and applicability chunks."""
    identifier = str(
        record.get("vulnerability_id") or record.get("cve_id") or ""
    )
    vendor = str(record.get("vendor", "unknown"))
    product = str(record.get("product", "unknown"))
    cvss = record.get("cvss") or {}
    overview = (
        f"{identifier} affects {vendor} {product}.\n"
        f"Description: {record.get('description', '')}\n"
        f"CVSS: {cvss.get('score', 'unknown')} "
        f"({cvss.get('severity', 'unknown')}).\n"
        f"Weaknesses: {', '.join(record.get('weaknesses', [])) or 'unknown'}."
    )
    chunks = [{"section": "overview", "text": overview}]

    vulnerable_rules = [
        rule
        for rule in record.get("affected_versions", [])
        if rule.get("vulnerable", True)
    ]
    if vulnerable_rules:
        formatted_rules = "\n".join(
            f"- {format_version_rule(rule)}" for rule in vulnerable_rules
        )
        chunks.append(
            {
                "section": "applicability",
                "text": (
                    f"{identifier} affected {product} version rules:\n"
                    f"{formatted_rules}"
                ),
            }
        )
    return chunks


def _connect(settings: Settings) -> QdrantClient:
    return QdrantClient(
        url=settings.qdrant_url,
        api_key=settings.qdrant_api_key or None,
    )


def _prepare_collection(
    client: QdrantClient,
    settings: Settings,
    vector_size: int,
    recreate: bool,
) -> None:
    exists = client.collection_exists(settings.qdrant_collection)
    if exists and recreate:
        client.delete_collection(settings.qdrant_collection)
        exists = False

    if not exists:
        client.create_collection(
            collection_name=settings.qdrant_collection,
            vectors_config=models.VectorParams(
                size=vector_size,
                distance=models.Distance.COSINE,
            ),
        )
        for field_name in (
            "vulnerability_id",
            "vendor",
            "product",
            "source",
            "section",
        ):
            client.create_payload_index(
                collection_name=settings.qdrant_collection,
                field_name=field_name,
                field_schema=models.PayloadSchemaType.KEYWORD,
            )
        return

    collection = client.get_collection(settings.qdrant_collection)
    existing_size = getattr(collection.config.params.vectors, "size", None)
    if existing_size is not None and existing_size != vector_size:
        raise ValueError(
            f"Collection vector size={existing_size}, model vector size={vector_size}. "
            "Dùng --recreate nếu muốn thay index hiện tại."
        )


def build_index(
    input_path: Path,
    settings: Settings,
    recreate: bool = False,
) -> int:
    if not input_path.exists():
        raise FileNotFoundError(f"Processed dataset không tồn tại: {input_path}")

    chunk_rows: list[dict[str, Any]] = []
    chunk_texts: list[str] = []
    for record in load_records(input_path):
        identifier = record.get("vulnerability_id") or record.get("cve_id")
        if not identifier:
            continue
        record["vulnerability_id"] = str(identifier).upper()
        for chunk in create_chunks(record):
            chunk_rows.append({"record": record, **chunk})
            chunk_texts.append(chunk["text"])

    if not chunk_texts:
        raise ValueError("Dataset không có chunk để index.")

    embedding_model = SentenceTransformer(settings.embedding_model)
    vectors = embedding_model.encode(
        chunk_texts,
        batch_size=settings.embedding_batch_size,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    vector_size = embedding_model.get_sentence_embedding_dimension()
    if vector_size is None:
        raise ValueError("Không xác định được vector dimension của embedding model.")

    client = _connect(settings)
    _prepare_collection(client, settings, vector_size, recreate)

    points: list[models.PointStruct] = []
    for row, vector in zip(chunk_rows, vectors, strict=True):
        record = row["record"]
        identifier = record["vulnerability_id"]
        point_key = f"{record.get('source', 'unknown')}:{identifier}:{row['section']}"
        points.append(
            models.PointStruct(
                id=str(uuid.uuid5(POINT_NAMESPACE, point_key)),
                vector=vector.tolist(),
                payload={
                    "vulnerability_id": identifier,
                    "vendor": record.get("vendor", ""),
                    "product": record.get("product", ""),
                    "source": record.get("source", ""),
                    "section": row["section"],
                    "text": row["text"],
                    "source_url": record.get("source_url", ""),
                    "published": record.get("published"),
                    "last_modified": record.get("last_modified"),
                    "cvss": record.get("cvss"),
                    "affected_versions": record.get("affected_versions", []),
                    "embedding_model": settings.embedding_model,
                    "content_hash": hashlib.sha256(row["text"].encode()).hexdigest(),
                },
            )
        )

    for start in range(0, len(points), 128):
        client.upsert(
            collection_name=settings.qdrant_collection,
            points=points[start : start + 128],
            wait=True,
        )
    return len(points)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Embed and index normalized records")
    parser.add_argument("--input", type=Path, default=settings.processed_file)
    parser.add_argument("--recreate", action="store_true")
    args = parser.parse_args()
    count = build_index(args.input, settings, recreate=args.recreate)
    print(f"Indexed {count} chunks into: {settings.qdrant_collection}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
