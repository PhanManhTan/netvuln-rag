"""Embed normalized chunks and store them in the configured vector database."""

from __future__ import annotations

import argparse
import uuid
from math import isfinite
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterable, Literal

from pydantic import BaseModel, Field, model_validator
from qdrant_client import QdrantClient, models

from config.settings import Settings, get_settings
from data_pipeline.process import processed_snapshot_paths
from data_pipeline.schemas import TextChunk


POINT_NAMESPACE = uuid.UUID("9cf154ef-4f68-48be-9125-b7ab813663c5")


class IndexInput(BaseModel):
    """Portable points and the embedding settings needed to upload them."""

    schema_version: Literal[1] = 1
    embedding_provider: Literal["local", "qdrant_cloud"]
    embedding_model: str
    embedding_document_prefix: str
    embedding_query_prefix: str
    vector_size: int = Field(gt=0)
    points: list[models.PointStruct] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_vectors(self) -> "IndexInput":
        for point in self.points:
            vector = point.vector
            if self.embedding_provider == "qdrant_cloud":
                if not isinstance(vector, models.Document) or vector.model != self.embedding_model:
                    raise ValueError(f"Point {point.id} needs text for model {self.embedding_model}")
            elif (
                not isinstance(vector, list)
                or len(vector) != self.vector_size
                or not all(isinstance(value, float) and isfinite(value) for value in vector)
            ):
                raise ValueError(f"Point {point.id} needs a finite dense vector of size {self.vector_size}")
        return self


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


def prepare_index_input(
    input_path: Path,
    settings: Settings,
    *,
    product_ids: set[str] | None = None,
) -> IndexInput:
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

    points: list[models.PointStruct] = []
    for row, vector in zip(chunk_rows, vectors, strict=True):
        points.append(
            models.PointStruct(
                id=str(uuid.uuid5(POINT_NAMESPACE, row.chunk_id)),
                vector=vector,
                payload={**row.model_dump(mode="json"), "embedding_model": settings.embedding_model},
            )
        )
    return IndexInput(
        embedding_provider=settings.embedding_provider,
        embedding_model=settings.embedding_model,
        embedding_document_prefix=settings.embedding_document_prefix,
        embedding_query_prefix=settings.embedding_query_prefix,
        vector_size=vector_size,
        points=points,
    )


def push_index_input(
    prepared: IndexInput,
    settings: Settings,
    recreate: bool = False,
    *,
    require_new_collection: bool = False,
) -> int:
    for name in ("embedding_provider", "embedding_model", "embedding_document_prefix", "embedding_query_prefix"):
        if getattr(prepared, name) != getattr(settings, name):
            raise ValueError(f"Prepared index input does not match {name.upper()}. Prepare it again with the current settings.")
    cloud = prepared.embedding_provider == "qdrant_cloud"
    if cloud and prepared.vector_size != settings.embedding_dimensions:
        raise ValueError("Prepared index input does not match EMBEDDING_DIMENSIONS")

    client = _connect(settings)
    _prepare_collection(client, settings, prepared.vector_size, recreate, require_new_collection)

    batch_size = settings.embedding_batch_size if cloud else 128
    for start in range(0, len(prepared.points), batch_size):
        client.upsert(
            collection_name=settings.qdrant_collection,
            points=prepared.points[start : start + batch_size],
            wait=True,
        )
    return len(prepared.points)


def build_index(
    input_path: Path,
    settings: Settings,
    recreate: bool = False,
    *,
    product_ids: set[str] | None = None,
    require_new_collection: bool = False,
) -> int:
    prepared = prepare_index_input(input_path, settings, product_ids=product_ids)
    return push_index_input(prepared, settings, recreate, require_new_collection=require_new_collection)


def _write_index_input(path: Path, prepared: IndexInput) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(dir=path.parent, mode="w", encoding="utf-8", delete=False) as file:
            temporary = Path(file.name)
            file.write(prepared.model_dump_json())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Embed chunks and upsert vectors and source metadata into Qdrant")
    parser.add_argument("--stage", choices=("all", "prepare", "push"), default="all")
    parser.add_argument("--input", type=Path, help="Chunk file or directory for all or prepare")
    parser.add_argument("--bundle", type=Path, help="Input/output file for prepare or push (default: ARTIFACTS_DIR/index/points.json)")
    parser.add_argument("--recreate", action="store_true")
    args = parser.parse_args()
    if args.stage == "prepare" and args.recreate:
        parser.error("--recreate applies to an upload")
    if args.stage == "push" and args.input is not None:
        parser.error("Use --bundle to select the prepared input for push")
    if args.stage == "all" and args.bundle is not None:
        parser.error("--bundle applies to prepare or push")
    bundle = args.bundle or settings.artifacts_dir / "index" / "points.json"
    input_path = args.input or settings.chunks_data_dir
    try:
        if args.stage == "prepare":
            prepared = prepare_index_input(input_path, settings)
            _write_index_input(bundle, prepared)
            kind = "Cloud Inference text" if prepared.embedding_provider == "qdrant_cloud" else "local vectors"
            print(f"Prepared {len(prepared.points)} points ({kind}) in {bundle}")
            return 0
        if args.stage == "push":
            prepared = IndexInput.model_validate_json(bundle.read_text(encoding="utf-8"))
            count = push_index_input(prepared, settings, recreate=args.recreate)
        else:
            count = build_index(input_path, settings, recreate=args.recreate)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Upserted {count} vectors into Qdrant collection {settings.qdrant_collection}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
