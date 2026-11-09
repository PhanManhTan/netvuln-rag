from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import requests

from config.settings import Settings
from config.products import ProductCatalog, ProductProfile, VersionTarget
from data_pipeline import process as process_cli
from data_pipeline.contracts import CrawlOptions
from data_pipeline.crawl import crawl_product
from data_pipeline.nvd import NVDAdapter
from rag.retrieval.models import MatchStatus
from rag.retrieval.retriever import Retriever
from evaluation import build as build_questions
from evaluation.dataset import load_questions


class FakeResponse:
    def __init__(
        self,
        payload: dict[str, Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.payload = payload or {}
        self.error = error

    def raise_for_status(self) -> None:
        if self.error:
            raise self.error

    def json(self) -> dict[str, Any]:
        return self.payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = iter(responses)
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return next(self.responses)

    def close(self) -> None:
        self.closed = True


def make_settings(tmp_path: Path, page_size: int = 2) -> Settings:
    return Settings(
        raw_data_dir=tmp_path / "raw",
        processed_data_dir=tmp_path / "processed",
        source_page_size=page_size,
        source_request_delay=0,
        source_request_timeout=15,
    )


def vulnerability(identifier: str, **record: Any) -> dict[str, Any]:
    return {"cve": {"id": identifier, **record}}


def profile() -> ProductProfile:
    return ProductProfile(
        product_id="fortios",
        vendor="fortinet",
        product="fortios",
        display_name="Fortinet FortiOS",
        aliases=("fortios",),
        cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
        vendor_source="fortiguard",
    )


def test_crawl_paginates_and_respects_record_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        [
            FakeResponse(
                {
                    "totalResults": 10,
                    "vulnerabilities": [
                        vulnerability("CVE-2024-0001"),
                        vulnerability("CVE-2024-0002"),
                    ],
                }
            ),
            FakeResponse(
                {
                    "totalResults": 10,
                    "vulnerabilities": [vulnerability("CVE-2024-0003")],
                }
            ),
        ]
    )
    adapter = NVDAdapter(make_settings(tmp_path), profile())
    monkeypatch.setattr(adapter, "_create_session", lambda: session)
    run_dir = tmp_path / "sample-run"

    result = adapter.crawl(CrawlOptions(output_dir=run_dir, limit=3))

    assert result == run_dir
    assert [call["params"]["startIndex"] for call in session.calls] == [0, 2]
    assert [call["params"]["resultsPerPage"] for call in session.calls] == [2, 1]
    assert session.closed is True
    assert (run_dir / "page_0001.json").exists()
    assert (run_dir / "page_0002.json").exists()

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert manifest["requested_limit"] == 3
    assert manifest["downloaded"] == 3
    assert manifest["total_results"] == 10
    assert manifest["stopped_early"] is True
    assert manifest["product_id"] == "fortios"
    assert manifest["pages"] == ["page_0001.json", "page_0002.json"]


def test_crawl_records_failure_in_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession([FakeResponse(error=requests.HTTPError("rate limited"))])
    adapter = NVDAdapter(make_settings(tmp_path), profile())
    monkeypatch.setattr(adapter, "_create_session", lambda: session)
    run_dir = tmp_path / "failed-run"

    with pytest.raises(requests.HTTPError, match="rate limited"):
        adapter.crawl(CrawlOptions(output_dir=run_dir, limit=1))

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["downloaded"] == 0
    assert manifest["error"] == "HTTPError: rate limited"
    assert session.closed is True


def test_crawl_rejects_duplicate_cve_across_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession([
        FakeResponse({"totalResults": 2, "startIndex": 0, "vulnerabilities": [vulnerability("CVE-2024-0001")]}),
        FakeResponse({"totalResults": 2, "startIndex": 1, "vulnerabilities": [vulnerability("cve-2024-0001")]}),
    ])
    adapter = NVDAdapter(make_settings(tmp_path, page_size=1), profile())
    monkeypatch.setattr(adapter, "_create_session", lambda: session)
    run_dir = tmp_path / "duplicate"

    with pytest.raises(ValueError, match="bị trùng"):
        adapter.crawl(CrawlOptions(output_dir=run_dir))

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["pages"] == ["page_0001.json"]


def test_crawl_limit_must_be_positive() -> None:
    with pytest.raises(ValueError, match="lớn hơn 0"):
        CrawlOptions(limit=0)


def test_nvd_range_crossing_minor_releases_is_not_forced_into_start_branch(tmp_path: Path) -> None:
    adapter = NVDAdapter(make_settings(tmp_path), profile())
    record = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionStartIncluding": "6.0",
                                "versionEndIncluding": "6.4.12",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    rule = adapter._version_rules(record)[0]
    assert rule.branch is None


def test_exact_cpe_crawl_drives_retrieval_and_evaluation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = VersionTarget(version="9.7p1", cpe="cpe:2.3:a:demo:ssh:9.7:p1:*:*:*:*:*:*")
    second = VersionTarget(version="9.8p1", cpe="cpe:2.3:a:demo:ssh:9.8:p1:*:*:*:*:*:*")
    product = ProductProfile(
        product_id="demo-ssh", vendor="demo", product="ssh", display_name="Demo SSH",
        cpe="cpe:2.3:a:demo:ssh:*:*:*:*:*:*:*:*", versions=(first, second),
    )
    catalog_path = tmp_path / "products.json"
    catalog_path.write_text(ProductCatalog(products=(product,)).model_dump_json(), encoding="utf-8")
    settings = replace(
        make_settings(tmp_path, page_size=1),
        product_config_file=catalog_path,
        artifacts_dir=tmp_path / "artifacts",
    )
    shared = "CVE-2024-0001"
    first_only = "CVE-2024-0002"
    description = "An unchecked resource allocation can exhaust available memory."
    weaknesses = [{"description": [{"value": "CWE-400"}, {"value": "NVD-CWE-Other"}]}]
    shared_record = vulnerability(shared, descriptions=[{"lang": "en", "value": description}], weaknesses=weaknesses)
    session = FakeSession([
        FakeResponse({"totalResults": 2, "vulnerabilities": [shared_record]}),
        FakeResponse({"totalResults": 2, "vulnerabilities": [vulnerability(first_only, weaknesses=weaknesses)]}),
        FakeResponse({"totalResults": 1, "vulnerabilities": [shared_record]}),
    ])
    monkeypatch.setattr(NVDAdapter, "_create_session", lambda self: session)

    run_dir = crawl_product(product, settings=settings)["nvd"]
    assert [call["params"]["cpeName"] for call in session.calls] == [first.cpe, first.cpe, second.cpe]
    assert [call["params"]["startIndex"] for call in session.calls] == [0, 1, 0]
    assert all("isVulnerable" in call["params"] for call in session.calls)
    monkeypatch.setattr(process_cli, "get_settings", lambda: settings)
    monkeypatch.setattr("sys.argv", ["data_pipeline.process", "--normalize-only", "--all-products"])
    assert process_cli.main() == 0
    normalized, = process_cli.load_processed_manifest(settings, settings.normalized_manifest)["products"]
    assert "chunks_path" not in normalized
    assert not settings.processed_manifest.exists()

    monkeypatch.setattr(process_cli, "get_settings", lambda: replace(settings, raw_data_dir=tmp_path / "missing-raw"))
    monkeypatch.setattr("sys.argv", ["data_pipeline.process", "--chunks-only"])
    assert process_cli.main() == 0
    processed, = process_cli.load_processed_manifest(settings)["products"]
    assert processed["input_runs"] == normalized["input_runs"]
    assert processed["structured_sha256"] == normalized["structured_sha256"]
    assert processed["record_count"] == 2
    structured_path = Path(processed["structured_path"])
    chunks_path = Path(processed["chunks_path"])
    assert structured_path.parts[0] == chunks_path.parts[0] == "snapshots"
    assert structured_path.parts[1] == chunks_path.parts[1]
    assert structured_path.parts[2:] == ("structured", "demo-ssh", "vulnerabilities.jsonl")
    assert chunks_path.parts[2:] == ("chunks", "demo-ssh", "chunks.jsonl")
    first_record = json.loads(
        (settings.processed_data_dir / structured_path).read_text(encoding="utf-8").splitlines()[0]
    )
    assert first_record["sources"][0]["raw_path"] == f"raw/demo-ssh/nvd/{run_dir.name}/page_0001.json"
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert first_record["sources"][0]["retrieved_at"] == manifest["updated_at"]

    monkeypatch.setattr(build_questions, "get_settings", lambda: settings)
    monkeypatch.setattr("sys.argv", ["build_questions"])
    assert build_questions.main() == 0
    rows = {row["id"]: row for row in load_questions(settings.evaluation_questions_file)}

    newer_run = run_dir.with_name("99999999-newer-run")
    newer_run.mkdir()
    (newer_run / "manifest.json").write_text('{"status":"completed"}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["build_questions", "--from-processed"])
    assert build_questions.main() == 0
    assert {row["id"]: row for row in load_questions(settings.evaluation_questions_file)} == rows

    inventory = rows["demo-ssh-9.7p1-inventory"]
    assert inventory["expected_cves"] == [shared, first_only]
    assert inventory["raw_run_id"] == run_dir.name
    absent = rows["demo-ssh-9.8p1-cve-2024-0002"]
    assert absent["expected_status"] == "insufficient_evidence"
    assert absent["expected_cves"] == []
    detail = rows["demo-ssh-detail-cve-2024-0001"]
    assert detail["reference_answer"] == description
    semantic = rows["demo-ssh-semantic-cwe-400"]
    assert semantic["expected_cves"] == [shared, first_only]
    assert shared not in semantic["question"] and first_only not in semantic["question"]
    assert sum(row["question_type"] == "semantic" for row in rows.values()) == 1

    retriever = Retriever(settings)
    monkeypatch.setattr(retriever, "_hybrid_search", lambda *args: pytest.fail("Unexpected dense search"))
    bundle = retriever.search(inventory["question"])
    assert {result.vulnerability_id for result in bundle.results} == {shared, first_only}
    assert retriever.search(absent["question"]).version_matches[0].status == MatchStatus.UNKNOWN
    assert retriever.search("Demo SSH 9.7 có những CVE nào?").results == []

    original_chunks = (settings.processed_data_dir / chunks_path).read_bytes()
    create_chunks = process_cli.create_chunks
    monkeypatch.setattr(process_cli, "create_chunks", lambda record: create_chunks(record)[:1])
    monkeypatch.setattr(process_cli, "get_settings", lambda: replace(settings, raw_data_dir=tmp_path / "missing-raw"))
    monkeypatch.setattr("sys.argv", ["data_pipeline.process", "--rechunk"])

    assert process_cli.main() == 0
    rebuilt, = process_cli.load_processed_manifest(settings)["products"]
    assert rebuilt["input_runs"] == processed["input_runs"]
    assert rebuilt["structured_sha256"] == processed["structured_sha256"]
    assert rebuilt["chunk_count"] == 2 < processed["chunk_count"]
    assert rebuilt["chunks_path"] != processed["chunks_path"]
    assert (settings.processed_data_dir / chunks_path).read_bytes() == original_chunks
    assert len(process_cli.resolve_processed_artifact(settings, rebuilt, "chunks").read_text(encoding="utf-8").splitlines()) == 2


def test_evaluation_rejects_truncated_version_crawl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    product = profile().model_copy(update={
        "versions": (VersionTarget(version="7.2.7", cpe="cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*"),),
    })
    adapter = NVDAdapter(make_settings(tmp_path), product)
    session = FakeSession([FakeResponse({"totalResults": 2, "vulnerabilities": [vulnerability("CVE-2024-0001")]})])
    monkeypatch.setattr(adapter, "_create_session", lambda: session)

    run_dir = adapter.crawl(CrawlOptions(limit=1))

    with pytest.raises(ValueError, match="bỏ --limit"):
        build_questions.build_raw_questions(adapter, run_dir, {})
