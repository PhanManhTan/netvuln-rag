"""Download the complete NVD CVE ID catalog used by hallucination metrics."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from config.settings import MANIFEST_FILENAME, Settings, get_settings
from data_pipeline.nvd import NVDAdapter
from data_pipeline.schemas import CVE_PATTERN


def refresh_catalog(settings: Settings | None = None) -> dict[str, Any]:
    selected = settings or get_settings()
    selected.nvd_catalog_dir.mkdir(parents=True, exist_ok=True)
    ids: set[str] = set()
    start_index = 0
    total_results: int | None = None
    session = NVDAdapter._create_session_for_settings(selected)
    try:
        while total_results is None or start_index < total_results:
            response = session.get(
                selected.source_api_url,
                params={
                    "resultsPerPage": selected.source_page_size,
                    "startIndex": start_index,
                },
                timeout=selected.source_request_timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise ValueError("NVD catalog response field 'vulnerabilities' phải là list")
            vulnerabilities = payload["vulnerabilities"]
            reported_total = payload.get("totalResults")
            page_count = len(vulnerabilities)
            if (
                type(reported_total) is not int
                or reported_total < 1
                or (total_results is not None and reported_total != total_results)
                or payload.get("startIndex", start_index) != start_index
                or not page_count
                or start_index + page_count > reported_total
            ):
                raise ValueError(f"NVD catalog returned an inconsistent page at offset {start_index}")
            total_results = reported_total
            for item in vulnerabilities:
                identifier = str(item.get("cve", {}).get("id", "")).upper()
                if not CVE_PATTERN.fullmatch(identifier) or identifier in ids:
                    raise ValueError(f"NVD catalog returned an invalid or duplicate CVE: {identifier}")
                ids.add(identifier)
            start_index += page_count
            print(f"Catalog: {start_index}/{total_results}")
            if start_index < total_results:
                time.sleep(selected.source_request_delay)
    finally:
        session.close()

    body = "".join(f"{identifier}\n" for identifier in sorted(ids))
    output_path = selected.all_cve_ids_file
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    manifest = {
        "schema_version": "1.0",
        "source": selected.source_api_url,
        "retrieved_at": datetime.now(UTC).isoformat(),
        "cve_count": len(ids),
        "includes_rejected": True,
        "sha256": digest,
        "file": output_path.name,
    }
    with TemporaryDirectory(prefix=".build-", dir=selected.nvd_catalog_dir) as temporary_dir:
        temporary_path = Path(temporary_dir)
        staged_catalog = temporary_path / output_path.name
        staged_manifest = temporary_path / MANIFEST_FILENAME
        staged_catalog.write_text(body, encoding="utf-8", newline="\n")
        staged_manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        staged_catalog.replace(output_path)
        staged_manifest.replace(output_path.with_name(MANIFEST_FILENAME))
    return manifest


def load_catalog(path: Path) -> set[str]:
    if not path.exists():
        raise FileNotFoundError(
            f"NVD CVE catalog không tồn tại: {path}. Chạy python -m data_pipeline.cve_catalog --refresh"
        )
    return {line.strip().upper() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def load_catalog_manifest(path: Path) -> dict[str, Any] | None:
    manifest_path = path.with_name(MANIFEST_FILENAME)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    if not isinstance(manifest, dict) or manifest.get("file") != path.name:
        return None
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest if manifest.get("sha256") == digest else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the complete local NVD CVE ID catalog")
    parser.add_argument("--refresh", action="store_true", help="Download all current NVD CVE IDs")
    args = parser.parse_args()
    if not args.refresh:
        parser.error("catalog chỉ thay đổi khi có --refresh")
    manifest = refresh_catalog()
    print(f"Saved {manifest['cve_count']} CVE IDs ({manifest['sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
