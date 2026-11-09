"""Embed normalized chunks and store them in the configured vector database."""

from __future__ import annotations

import argparse
import uuid
from pathlib import Path
from typing import Any, Iterable

from qdrant_client import QdrantClient, models

from config.settings import Settings, get_settings
from data_pipeline.process import processed_snapshot_paths
from data_pipeline.schemas import TextChunk


POINT_NAMESPACE = uuid.UUID("9cf154ef-4f68-48be-9125-b7ab813663c5")


def _read_chunks(files: Iterable[Path]) -> Iterable[TextChunk]:
    for chunk_file in files:
        with chunk_file.open("r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    yield TextChunk.model_validate_json(line)


def load_chunks(path: Path, product_ids: set[str] | None = None) -> Iterable[TextChunk]:
    files = [path] if path.is_file() else sorted(path.glob("*/chunks.jsonl"))
    if path.is_dir() and product_ids is not None:
        files = [file for file in files if file.parent.name in product_ids]
    return _read_chunks(files)


def _connect(settings: Settings) -> QdrantClient:
    cloud = settings.embedding_provider == "qdrant_cloud"
    return QdrantClient(
        url=settings.qdrant_url,
        api_key=settings.qdrant_api_key or None,
        cloud_inference=cloud,
        timeout=60 if cloud else None,
    )


def _check_new_collection(client: QdrantClient, settings: Settings) -> None:
    if client.collection_exists(settings.qdrant_collection):
        raise ValueError(
            f"Collection {settings.qdrant_collection} already exists. "
            "Select a new collection or pass --recreate-index to replace it."
        )


def check_new_collection(settings: Settings) -> None:
    client = _connect(settings)
    try:
        _check_new_collection(client, settings)
    finally:
        client.close()


def _prepare_collection(
    client: QdrantClient,
    settings: Settings,
    vector_size: int,
    recreate: bool,
    require_new_collection: bool,
) -> None:
    if require_new_collection:
        _check_new_collection(client, settings)
        exists = False
    else:
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
            "product_id",
            "vendor",
            "product",
            "source_id",
            "section",
            "branch",
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


def _encode_local(chunk_texts: list[str], settings: Settings) -> tuple[list[list[float]], int]:
    from sentence_transformers import SentenceTransformer

    cache_folder = str(settings.embedding_cache_dir) if settings.embedding_cache_dir is not None else None
    model = SentenceTransformer(settings.embedding_model, device=settings.embedding_device, cache_folder=cache_folder)
    vectors = model.encode(
        chunk_texts,
        batch_size=settings.embedding_batch_size,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    vector_size = model.get_sentence_embedding_dimension()
    if vector_size is None:
        raise ValueError("Không xác định được vector dimension của embedding model.")
    return [vector.tolist() for vector in vectors], vector_size


def build_index(
    input_path: Path,
    settings: Settings,
    recreate: bool = False,
    *,
    product_ids: set[str] | None = None,
    require_new_collection: bool = False,
) -> int:
    if input_path.resolve() == settings.chunks_data_dir.resolve():
        files = processed_snapshot_paths(settings)["chunks"]
        chunk_rows = list(_read_chunks(
            path for path in files if product_ids is None or path.parent.name in product_ids
        ))
    elif not input_path.exists():
        raise FileNotFoundError(f"Processed dataset không tồn tại: {input_path}")
    else:
        chunk_rows = list(load_chunks(input_path, product_ids))

    chunk_texts = [settings.embedding_document_prefix + chunk.text for chunk in chunk_rows]

    if not chunk_texts:
        raise ValueError("Dataset không có chunk để index.")

    cloud = settings.embedding_provider == "qdrant_cloud"
    vectors: list[models.Document] | list[list[float]]
    if cloud:
        vectors = [
            models.Document(text=text, model=settings.embedding_model)
            for text in chunk_texts
        ]
        vector_size = settings.embedding_dimensions
    else:
        vectors, vector_size = _encode_local(chunk_texts, settings)

    client = _connect(settings)
    _prepare_collection(client, settings, vector_size, recreate, require_new_collection)

    points: list[models.PointStruct] = []
    for row, vector in zip(chunk_rows, vectors, strict=True):
        points.append(
            models.PointStruct(
                id=str(uuid.uuid5(POINT_NAMESPACE, row.chunk_id)),
                vector=vector,
                payload={**row.model_dump(mode="json"), "embedding_model": settings.embedding_model},
            )
        )

    batch_size = settings.embedding_batch_size if cloud else 128
    for start in range(0, len(points), batch_size):
        client.upsert(
            collection_name=settings.qdrant_collection,
            points=points[start : start + batch_size],
            wait=True,
        )
    return len(points)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Embed and index normalized records")
    parser.add_argument("--input", type=Path, default=settings.chunks_data_dir)
    parser.add_argument("--recreate", action="store_true")
    args = parser.parse_args()
    count = build_index(args.input, settings, recreate=args.recreate)
    print(f"Indexed {count} chunks into: {settings.qdrant_collection}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
