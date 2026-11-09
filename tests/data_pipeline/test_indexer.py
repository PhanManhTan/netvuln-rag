import json
from dataclasses import replace
from pathlib import Path

import pytest
from qdrant_client import models

from config.settings import Settings
from data_pipeline import index as indexer
from data_pipeline.schemas import TextChunk


class FakeClient:
    def __init__(self) -> None:
        self.points = []

    def collection_exists(self, name):
        return False

    def create_collection(self, **kwargs):
        return None

    def create_payload_index(self, **kwargs):
        return None

    def upsert(self, collection_name, points, wait):
        self.points.extend(points)


@pytest.mark.parametrize("provider", ["local", "qdrant_cloud"])
def test_indexer_uses_prebuilt_source_attributed_chunks(tmp_path: Path, monkeypatch, provider: str) -> None:
    chunk = TextChunk(
        chunk_id="a" * 64,
        record_id="fortios:CVE-2024-12345",
        vulnerability_id="CVE-2024-12345",
        product_id="fortios",
        vendor="fortinet",
        product="fortios",
        section="applicability",
        branch="7.2",
        text="affected evidence",
        source_id="FG-IR-test",
        source_url="https://fortiguard.fortinet.com/psirt/FG-IR-test",
        content_hash="b" * 64,
    )
    path = tmp_path / "fortios" / "chunks.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(chunk.model_dump(mode="json")) + "\n", encoding="utf-8")
    client = FakeClient()

    def encode_locally(texts, settings):
        assert provider == "local"
        assert texts == ["passage: " + chunk.text]
        return [[1.0, 0.0]], 2

    monkeypatch.setattr(indexer, "_encode_local", encode_locally)
    monkeypatch.setattr(indexer, "_connect", lambda settings: client)
    settings = Settings(
        embedding_provider=provider,
        embedding_model="intfloat/multilingual-e5-small",
        embedding_document_prefix="passage: ",
    )

    count = indexer.build_index(tmp_path, settings, recreate=True)

    assert count == 1
    assert client.points[0].payload["product_id"] == "fortios"
    assert client.points[0].payload["source_id"] == "FG-IR-test"
    if provider == "qdrant_cloud":
        assert client.points[0].vector == models.Document(
            text="passage: affected evidence", model=settings.embedding_model,
        )
    else:
        assert client.points[0].vector == [1.0, 0.0]

    bundle = tmp_path / "index-input.json"
    monkeypatch.setattr(indexer, "get_settings", lambda: settings)
    monkeypatch.setattr(indexer, "_connect", lambda _: pytest.fail("Preparing input must not open Qdrant"))
    monkeypatch.setattr("sys.argv", ["data_pipeline.index", "--stage", "prepare", "--input", str(path), "--bundle", str(bundle)])
    assert indexer.main() == 0

    prepared = indexer.IndexInput.model_validate_json(bundle.read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="EMBEDDING_MODEL"):
        indexer.push_index_input(prepared, replace(settings, embedding_model="another-model"))

    uploaded = FakeClient()
    monkeypatch.setattr(indexer, "_connect", lambda _: uploaded)
    monkeypatch.setattr(indexer, "_encode_local", lambda *args: pytest.fail("Push must reuse the saved input"))
    monkeypatch.setattr(indexer, "prepare_index_input", lambda *args: pytest.fail("Push must not read chunks"))
    monkeypatch.setattr("sys.argv", ["data_pipeline.index", "--stage", "push", "--bundle", str(bundle)])
    assert indexer.main() == 0
    assert [point.model_dump(mode="json") for point in uploaded.points] == [
        point.model_dump(mode="json") for point in client.points
    ]


def test_implicit_prepare_refuses_existing_collection(monkeypatch) -> None:
    client = FakeClient()
    monkeypatch.setattr(client, "collection_exists", lambda name: True)

    with pytest.raises(ValueError, match="--recreate-index"):
        indexer._prepare_collection(client, Settings(), 2, recreate=False, require_new_collection=True)
