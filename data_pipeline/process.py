"""Build validated structured records and source-attributed chunks."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

from config.products import ProductProfile, get_product_catalog
from config.settings import MANIFEST_FILENAME, Settings, get_settings
from data_pipeline.chunker import create_chunks
from data_pipeline.registry import get_source_adapter
from data_pipeline.schemas import (
    CuratedRouterOSAdvisory,
    SourceReference,
    VersionRule,
    VulnerabilityRecord,
)
from data_pipeline.versioning import detect_conflicts


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_processed_manifest(settings: Settings) -> dict[str, Any]:
    """Read a processed snapshot and translate paths from older machines."""
    manifest = json.loads(settings.processed_manifest.read_text(encoding="utf-8"))
    for item in manifest["products"]:
        product_id = item["product_id"]
        for key, artifact in (
            ("structured_path", settings.structured_file(product_id)),
            ("chunks_path", settings.chunks_file(product_id)),
        ):
            saved = item.get(key)
            if saved and (PureWindowsPath(saved).is_absolute() or PurePosixPath(saved).is_absolute()):
                item[key] = artifact.relative_to(settings.processed_data_dir).as_posix()
    return manifest


def resolve_processed_artifact(settings: Settings, item: dict[str, Any], kind: str) -> Path:
    """Validate an artifact from a product entry in a captured manifest."""
    root = settings.processed_data_dir.resolve()
    path = (root / item[f"{kind}_path"]).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"Processed artifact path escapes its data directory: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"Processed artifact is missing: {path}")
    digest = item.get(f"{kind}_sha256")
    if digest and _sha256(path) != digest:
        raise ValueError(f"Processed artifact hash differs from the manifest: {path}")
    return path


def processed_snapshot_paths(settings: Settings) -> dict[str, list[Path]]:
    """Resolve both artifact types against one published manifest."""
    catalog = get_product_catalog(settings.product_config_file)
    product_ids = {profile.product_id for profile in catalog.products}
    paths: dict[str, list[Path]] = {"structured": [], "chunks": []}
    try:
        manifest = load_processed_manifest(settings)
    except FileNotFoundError:
        # Older deployments can supply the original fixed files without a manifest.
        for profile in catalog.products:
            for kind, path in (
                ("structured", settings.structured_file(profile.product_id)),
                ("chunks", settings.chunks_file(profile.product_id)),
            ):
                if path.is_file():
                    paths[kind].append(path)
        return paths

    for item in manifest["products"]:
        if item["product_id"] not in product_ids:
            continue
        for kind, files in paths.items():
            files.append(resolve_processed_artifact(settings, item, kind))
    return paths


def select_run(source_dir: Path, run: str) -> Path:
    """Resolve an explicit run ID or the newest successfully completed run."""

    if run != "latest":
        selected = source_dir / run
        if selected.resolve().parent != source_dir.resolve():
            raise ValueError(f"Run ID must name a direct child of {source_dir}: {run}")
        if not selected.is_dir():
            raise FileNotFoundError(f"Run không tồn tại: {selected}")
        manifest = json.loads((selected / MANIFEST_FILENAME).read_text(encoding="utf-8"))
        if manifest.get("status") != "completed":
            raise ValueError(f"Run chưa crawl thành công: {selected}")
        return selected
    candidates: list[Path] = []
    for directory in source_dir.iterdir() if source_dir.exists() else ():
        manifest_path = directory / MANIFEST_FILENAME
        if not directory.is_dir() or not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if manifest.get("status") == "completed":
            candidates.append(directory)
    if not candidates:
        raise FileNotFoundError(f"Không có completed run trong {source_dir}")
    return max(candidates, key=lambda path: path.name)


def select_related_vendor_run(source_dir: Path, nvd_run_id: str) -> Path:
    """Select only a vendor run explicitly derived from the chosen NVD run."""

    candidates: list[Path] = []
    for directory in source_dir.iterdir() if source_dir.exists() else ():
        manifest_path = directory / MANIFEST_FILENAME
        if not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if manifest.get("status") == "completed" and manifest.get("input_nvd_run") == nvd_run_id:
            candidates.append(directory)
    if not candidates:
        raise FileNotFoundError(f"Không có vendor run ứng với NVD run {nvd_run_id} trong {source_dir}")
    return max(candidates, key=lambda path: path.name)


def _load_records(path: Path) -> dict[str, VulnerabilityRecord]:
    records: dict[str, VulnerabilityRecord] = {}
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                record = VulnerabilityRecord.model_validate_json(line)
            except Exception as exc:
                raise ValueError(f"Structured row lỗi tại {path}:{line_number}: {exc}") from exc
            records[record.vulnerability_id] = record
    return records


def _load_routeros_curated(path: Path) -> tuple[list[CuratedRouterOSAdvisory], dict[str, int | bool]]:
    rows: list[CuratedRouterOSAdvisory] = []
    counts: dict[str, int | bool] = {"total": 0, "approved": 0, "draft": 0, "rejected": 0, "approved_with_rules": 0, "milestone_met": False}
    if not path.exists():
        return rows, counts
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                row = CuratedRouterOSAdvisory.model_validate_json(line)
            except Exception as exc:
                raise ValueError(f"Curated row lỗi tại {path}:{line_number}: {exc}") from exc
            rows.append(row)
            counts["total"] += 1
            counts[row.review_status] += 1
    duplicates = [cve for cve in {row.vulnerability_id for row in rows} if sum(item.vulnerability_id == cve for item in rows) > 1]
    if duplicates:
        raise ValueError(f"Curated RouterOS phải có đúng một row mỗi CVE, bị trùng: {sorted(duplicates)}")
    counts["approved_with_rules"] = sum(row.review_status == "approved" and bool(row.version_rules) for row in rows)
    counts["milestone_met"] = int(counts["approved"]) >= 15 and int(counts["approved_with_rules"]) >= 10
    return rows, counts


def _merge_routeros_curated(
    records: dict[str, VulnerabilityRecord],
    curated_path: Path,
    settings: Settings,
) -> dict[str, int | bool]:
    rows, counts = _load_routeros_curated(curated_path)
    for row in rows:
        if row.review_status != "approved" or row.vulnerability_id not in records:
            continue
        record = records[row.vulnerability_id]
        source = SourceReference(
            source_id=row.advisory_id,
            authority="vendor",
            source_type=row.source_type,
            url=row.source_url,
            title=row.title,
            published=row.published,
            updated=row.updated,
            retrieved_at=row.retrieved_at,
            raw_path=settings.source_file_reference(curated_path),
        )
        sources = tuple(dict.fromkeys((*record.sources, source)))
        rules = tuple((*record.applicability, *row.version_rules))
        conflicts = detect_conflicts(rules)
        records[row.vulnerability_id] = VulnerabilityRecord.model_validate(
            {
                **record.model_dump(mode="python"),
                "sources": sources,
                "applicability": rules,
                # Resolution happens per queried interval; both authorities must remain available.
                "effective_rules": rules,
                "has_source_conflict": bool(conflicts),
                "conflict_intervals": conflicts,
            }
        )
    return counts


def _load_normalized_vendor_rows(path: Path) -> dict[str, list[tuple[SourceReference, tuple[VersionRule, ...]]]]:
    """Load FortiGuard normalized rows emitted beside immutable raw pages."""

    output: dict[str, list[tuple[SourceReference, tuple[VersionRule, ...]]]] = {}
    if not path.exists():
        return output
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                item: dict[str, Any] = json.loads(line)
                cve = str(item["vulnerability_id"]).upper()
                source = SourceReference.model_validate(item["source"])
                rules = tuple(VersionRule.model_validate(rule) for rule in item["version_rules"])
            except Exception as exc:
                raise ValueError(f"Vendor row lỗi tại {path}:{line_number}: {exc}") from exc
            output.setdefault(cve, []).append((source, rules))
    return output


def _merge_fortiguard(records: dict[str, VulnerabilityRecord], run_dir: Path | None) -> int:
    if run_dir is None:
        return 0
    rows = _load_normalized_vendor_rows(run_dir / "advisories.jsonl")
    merged = 0
    for cve, assertions in rows.items():
        if cve not in records:
            continue
        record = records[cve]
        vendor_sources = tuple(source for source, _ in assertions)
        vendor_rules = tuple(rule for _, rules in assertions for rule in rules)
        rules = tuple((*record.applicability, *vendor_rules))
        conflicts = detect_conflicts(rules)
        records[cve] = VulnerabilityRecord.model_validate(
            {
                **record.model_dump(mode="python"),
                "sources": tuple(dict.fromkeys((*record.sources, *vendor_sources))),
                "applicability": rules,
                "effective_rules": rules,
                "has_source_conflict": bool(conflicts),
                "conflict_intervals": conflicts,
            }
        )
        merged += 1
    return merged


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        for row in rows:
            file.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def process_product(
    profile: ProductProfile,
    run: str = "latest",
    settings: Settings | None = None,
) -> dict[str, Any]:
    selected = settings or get_settings()
    source_run = select_run(selected.raw_product_source_dir(profile.product_id), run)
    structured_path = selected.structured_file(profile.product_id)
    get_source_adapter(selected, profile).process(source_run, structured_path)
    records = _load_records(structured_path)

    curated_counts: dict[str, int | bool] | None = None
    vendor_run: Path | None = None
    vendor_merged = 0
    if profile.vendor_source == "mikrotik_curated":
        curated_path = selected.curated_data_dir / profile.product_id / "vendor_advisories.jsonl"
        curated_counts = _merge_routeros_curated(records, curated_path, selected)
    elif profile.vendor_source:
        source_dir = selected.raw_product_source_dir(profile.product_id, profile.vendor_source)
        try:
            vendor_run = select_related_vendor_run(source_dir, source_run.name)
        except FileNotFoundError:
            vendor_run = None
        vendor_merged = _merge_fortiguard(records, vendor_run)

    normalized_records = [record.model_dump(mode="json") for record in sorted(records.values(), key=lambda item: item.vulnerability_id)]
    _write_jsonl(structured_path, normalized_records)
    chunks = [chunk.model_dump(mode="json") for record in records.values() for chunk in create_chunks(record)]
    chunks.sort(key=lambda item: item["chunk_id"])
    chunks_path = selected.chunks_file(profile.product_id)
    _write_jsonl(chunks_path, chunks)
    return {
        "product_id": profile.product_id,
        "input_runs": {selected.data_source: source_run.name, **({profile.vendor_source: vendor_run.name} if profile.vendor_source and vendor_run else {})},
        "record_count": len(records),
        "chunk_count": len(chunks),
        "structured_path": structured_path.relative_to(selected.processed_data_dir).as_posix(),
        "structured_sha256": _sha256(structured_path),
        "chunks_path": chunks_path.relative_to(selected.processed_data_dir).as_posix(),
        "chunks_sha256": _sha256(chunks_path),
        "curated": curated_counts,
        "vendor_records_merged": vendor_merged,
    }


def process_data(
    product_ids: list[str] | None = None,
    run: str = "latest",
    settings: Settings | None = None,
    *,
    nvd_runs: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    selected = settings or get_settings()
    catalog = get_product_catalog(selected.product_config_file)
    profiles = catalog.products if product_ids is None else tuple(catalog.by_id(item) for item in product_ids)
    runs = nvd_runs or {}
    snapshots_dir = selected.processed_data_dir / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    snapshot = snapshots_dir / uuid4().hex
    with TemporaryDirectory(prefix=".build-", dir=snapshots_dir) as temporary_dir:
        staged = Path(temporary_dir)
        staged_settings = replace(selected, processed_data_dir=staged)
        results = [
            process_product(profile, runs.get(profile.product_id, run), staged_settings)
            for profile in profiles
        ]
        staged.rename(snapshot)

    prefix = snapshot.relative_to(selected.processed_data_dir)
    for item in results:
        for key in ("structured_path", "chunks_path"):
            item[key] = (prefix / item[key]).as_posix()
    manifest = {
        "schema_version": "1.0",
        "built_at": datetime.now(UTC).isoformat(),
        "products": results,
        "record_count": sum(item["record_count"] for item in results),
        "chunk_count": sum(item["chunk_count"] for item in results),
    }
    temporary_manifest = selected.processed_data_dir / f".manifest-{snapshot.name}.tmp"
    try:
        with temporary_manifest.open("x", encoding="utf-8") as file:
            json.dump(manifest, file, ensure_ascii=False, indent=2)
        temporary_manifest.replace(selected.processed_manifest)
    finally:
        temporary_manifest.unlink(missing_ok=True)
    return results


def main() -> int:
    settings = get_settings()
    catalog = get_product_catalog(settings.product_config_file)
    parser = argparse.ArgumentParser(description="Build structured records and chunks")
    products = parser.add_mutually_exclusive_group()
    products.add_argument("--product", choices=[item.product_id for item in catalog.products])
    products.add_argument("--all-products", action="store_true")
    parser.add_argument("--run", default="latest", help="Run ID or 'latest'")
    args = parser.parse_args()
    product_ids = None if args.all_products else [args.product or settings.default_product_id]
    for result in process_data(product_ids, args.run, settings):
        print(f"{result['product_id']}: {result['record_count']} records, {result['chunk_count']} chunks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
