import json

import pytest

from config.products import get_product_catalog
from data_pipeline.schemas import CuratedRouterOSAdvisory, SourceReference, VersionRule, VulnerabilityRecord
from data_pipeline.chunker import create_chunks


def test_product_catalog_matches_proposal() -> None:
    catalog = get_product_catalog()
    assert {item.product_id: len(item.versions) for item in catalog.products} == {
        "openssh": 5, "openvpn": 5, "fortios": 6,
    }
    assert all(item.vendor_source is None for item in catalog.products)
    assert catalog.by_id("openssh").versions[2].version == "9.7p1"


def test_raw_paths_are_isolated_by_product_and_source(tmp_path) -> None:
    from config.settings import Settings

    settings = Settings(raw_data_dir=tmp_path)
    assert settings.raw_product_source_dir("routeros", "nvd") == tmp_path / "routeros" / "nvd"
    assert settings.raw_product_source_dir("fortios", "nvd") == tmp_path / "fortios" / "nvd"


def test_storage_roots_are_portable_across_working_directories(tmp_path, monkeypatch) -> None:
    from config.settings import PROJECT_ROOT, Settings

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DATA_DIR", "portable-data")
    monkeypatch.setenv("ARTIFACTS_DIR", "portable-artifacts")
    monkeypatch.setenv("RAW_DATA_DIR", "legacy-raw")
    monkeypatch.setenv("PRODUCT_CONFIG_FILE", "config/products.json")

    settings = Settings()

    assert settings.raw_data_dir == PROJECT_ROOT / "portable-data" / "raw"
    assert settings.processed_data_dir == PROJECT_ROOT / "portable-data" / "processed"
    assert settings.curated_data_dir == PROJECT_ROOT / "portable-data" / "curated"
    assert settings.reference_data_dir == PROJECT_ROOT / "portable-data" / "reference"
    assert settings.product_config_file == PROJECT_ROOT / "config" / "products.json"
    assert settings.evaluation_questions_file == PROJECT_ROOT / "portable-artifacts" / "evaluation" / "questions.jsonl"
    page = settings.raw_product_source_dir("openssh", "nvd") / "run-1" / "page_0001.json"
    assert settings.source_file_reference(page) == "raw/openssh/nvd/run-1/page_0001.json"

    monkeypatch.delenv("DATA_DIR")
    assert Settings().raw_data_dir == PROJECT_ROOT / "legacy-raw"


def test_manifest_reader_translates_absolute_paths_from_old_snapshots(tmp_path) -> None:
    from config.settings import Settings
    from data_pipeline.process import load_processed_manifest

    settings = Settings(processed_data_dir=tmp_path)
    product = {
        "product_id": "example",
        "input_runs": {"nvd": "sample-run"},
        "structured_path": "D:/old-machine/processed/structured/example/vulnerabilities.jsonl",
        "chunks_path": "/old-server/processed/chunks/example/chunks.jsonl",
    }
    settings.processed_manifest.write_text(json.dumps({"products": [product]}), encoding="utf-8")

    assert load_processed_manifest(settings)["products"][0] == {
        **product,
        "structured_path": "structured/example/vulnerabilities.jsonl",
        "chunks_path": "chunks/example/chunks.jsonl",
    }


def test_processing_publishes_one_snapshot_after_all_products_succeed(tmp_path, monkeypatch) -> None:
    from config.settings import Settings
    from data_pipeline import process

    settings = Settings(processed_data_dir=tmp_path)

    def build_product(profile, run, staged_settings):
        if profile.product_id == "openvpn":
            raise RuntimeError("invalid second product")
        paths = {
            "structured": staged_settings.structured_file(profile.product_id),
            "chunks": staged_settings.chunks_file(profile.product_id),
        }
        result = {"product_id": profile.product_id, "record_count": 1, "chunk_count": 1}
        for kind, path in paths.items():
            path.parent.mkdir(parents=True)
            path.write_text(run, encoding="utf-8")
            result[f"{kind}_path"] = path.relative_to(staged_settings.processed_data_dir).as_posix()
            result[f"{kind}_sha256"] = process._sha256(path)
        return result

    monkeypatch.setattr(process, "process_product", build_product)
    process.process_data(["openssh"], "first", settings)
    first_paths = process.processed_snapshot_paths(settings)
    original_manifest = settings.processed_manifest.read_bytes()

    with pytest.raises(RuntimeError, match="invalid second product"):
        process.process_data(["openssh", "openvpn"], "second", settings)

    assert settings.processed_manifest.read_bytes() == original_manifest
    assert process.processed_snapshot_paths(settings) == first_paths
    assert len(list((tmp_path / "snapshots").iterdir())) == 1

    process.process_data(["fortios"], "third", settings)
    current = process.processed_snapshot_paths(settings)
    assert [path.parent.name for path in current["chunks"]] == ["fortios"]
    assert first_paths["chunks"][0].read_text(encoding="utf-8") == "first"
    current["chunks"][0].write_text("corrupted", encoding="utf-8")
    with pytest.raises(ValueError, match="hash differs"):
        process.processed_snapshot_paths(settings)


def test_approved_curated_row_requires_review_provenance() -> None:
    with pytest.raises(ValueError, match="reviewed_by"):
        CuratedRouterOSAdvisory(
            vulnerability_id="CVE-2024-12345",
            advisory_id="mt-1",
            title="test",
            source_url="https://mikrotik.com/test",
            source_type="announcement",
            retrieved_at="2026-01-01T00:00:00Z",
            evidence_text="test",
            source_content_hash="a" * 64,
            review_status="approved",
            normalized_by="normalizer",
        )


def test_chunks_are_traceable_to_one_rule_source() -> None:
    source = SourceReference(source_id="nvd:CVE-2024-12345", authority="nvd", source_type="nvd", url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345")
    rule = VersionRule(source_id=source.source_id, authority="nvd", status="affected", branch="7.2")
    record = VulnerabilityRecord(
        record_id="fortios:CVE-2024-12345", vulnerability_id="CVE-2024-12345",
        product_id="fortios", vendor="fortinet", product="fortios", display_name="Fortinet FortiOS",
        description="test", sources=(source,), applicability=(rule,), effective_rules=(rule,),
    )
    chunks = create_chunks(record)
    assert {chunk.source_id for chunk in chunks} == {source.source_id}
    assert {chunk.product_id for chunk in chunks} == {"fortios"}
    assert all(len(chunk.content_hash) == 64 for chunk in chunks)
