"""NVD API adapter: raw collection and conversion to the common schema."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import requests

from rag_system.config import Settings


class NVDAdapter:
    """Keep all NVD-specific request and response knowledge in one adapter."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @staticmethod
    def _save_json(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)

    def crawl(self, output_dir: Path | None = None) -> Path:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        run_dir = output_dir or self.settings.raw_source_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        session = requests.Session()
        session.headers.update(
            {"Accept": "application/json", "User-Agent": "netvuln-rag/0.1"}
        )
        if self.settings.source_api_key:
            session.headers["apiKey"] = self.settings.source_api_key

        start_index = 0
        page_number = 1
        total_results: int | None = None
        downloaded = 0
        page_files: list[str] = []

        while total_results is None or start_index < total_results:
            response = session.get(
                self.settings.source_api_url,
                params={
                    "virtualMatchString": self.settings.target_cpe,
                    "resultsPerPage": self.settings.source_page_size,
                    "startIndex": start_index,
                    "noRejected": "",
                },
                timeout=60,
            )
            response.raise_for_status()
            payload = response.json()

            vulnerabilities = payload.get("vulnerabilities", [])
            total_results = int(payload.get("totalResults", 0))
            page_path = run_dir / f"page_{page_number:04d}.json"
            self._save_json(page_path, payload)
            page_files.append(page_path.name)

            page_count = len(vulnerabilities)
            downloaded += page_count
            start_index += page_count
            page_number += 1
            print(f"Downloaded {downloaded}/{total_results} records")

            if page_count == 0 or start_index >= total_results:
                break
            time.sleep(self.settings.source_request_delay)

        self._save_json(
            run_dir / "manifest.json",
            {
                "source": self.settings.data_source,
                "created_at": datetime.now(UTC).isoformat(),
                "target_vendor": self.settings.target_vendor,
                "target_product": self.settings.target_product,
                "target_cpe": self.settings.target_cpe,
                "total_results": total_results or 0,
                "downloaded": downloaded,
                "pages": page_files,
            },
        )
        return run_dir

    def process(self, input_path: Path, output_path: Path) -> int:
        page_files = self._find_page_files(input_path)
        if not page_files:
            raise FileNotFoundError(f"Không tìm thấy page_*.json trong {input_path}")

        records_by_id: dict[str, dict[str, Any]] = {}
        for page_path in page_files:
            with page_path.open("r", encoding="utf-8") as file:
                page = json.load(file)
            for item in page.get("vulnerabilities", []):
                record = self._normalize(item.get("cve", {}))
                if record["vulnerability_id"]:
                    records_by_id[record["vulnerability_id"]] = record

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="\n") as file:
            for record_id in sorted(records_by_id):
                file.write(
                    json.dumps(records_by_id[record_id], ensure_ascii=False) + "\n"
                )
        return len(records_by_id)

    @staticmethod
    def _find_page_files(input_path: Path) -> list[Path]:
        if input_path.is_file():
            return [input_path]
        return sorted(input_path.glob("**/page_*.json"))

    @staticmethod
    def _english_description(record: dict[str, Any]) -> str:
        descriptions = record.get("descriptions", [])
        for description in descriptions:
            if description.get("lang") == "en":
                return str(description.get("value", "")).strip()
        if descriptions:
            return str(descriptions[0].get("value", "")).strip()
        return ""

    @staticmethod
    def _cvss(record: dict[str, Any]) -> dict[str, Any] | None:
        metrics = record.get("metrics", {})
        priorities = (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        )
        for metric_name in priorities:
            entries = metrics.get(metric_name, [])
            if not entries:
                continue
            entry = entries[0]
            data = entry.get("cvssData", {})
            return {
                "version": data.get("version"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
        return None

    @classmethod
    def _walk_cpe_matches(cls, value: Any) -> Iterable[dict[str, Any]]:
        if isinstance(value, dict):
            for match in value.get("cpeMatch", []):
                if isinstance(match, dict):
                    yield match
            for child in value.values():
                yield from cls._walk_cpe_matches(child)
        elif isinstance(value, list):
            for child in value:
                yield from cls._walk_cpe_matches(child)

    def _version_rules(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        seen: set[str] = set()
        for match in self._walk_cpe_matches(record.get("configurations", [])):
            criteria = str(match.get("criteria", ""))
            parts = criteria.split(":")
            is_target = (
                len(parts) >= 6
                and parts[3].lower() == self.settings.target_vendor
                and parts[4].lower() == self.settings.target_product
            )
            if not is_target:
                continue

            rule = {
                "criteria": criteria,
                "match_criteria_id": match.get("matchCriteriaId"),
                "vulnerable": bool(match.get("vulnerable", False)),
                "version": parts[5],
                "version_start_including": match.get("versionStartIncluding"),
                "version_start_excluding": match.get("versionStartExcluding"),
                "version_end_including": match.get("versionEndIncluding"),
                "version_end_excluding": match.get("versionEndExcluding"),
            }
            fingerprint = json.dumps(rule, sort_keys=True)
            if fingerprint not in seen:
                rules.append(rule)
                seen.add(fingerprint)
        return rules

    def _normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        references = [
            {
                "url": reference.get("url"),
                "source": reference.get("source"),
                "tags": reference.get("tags", []),
            }
            for reference in record.get("references", [])
            if reference.get("url")
        ]
        weaknesses = sorted(
            {
                description.get("value")
                for weakness in record.get("weaknesses", [])
                for description in weakness.get("description", [])
                if description.get("value")
            }
        )
        vulnerability_id = str(record.get("id", "")).upper()
        return {
            "vulnerability_id": vulnerability_id,
            "vendor": self.settings.target_vendor,
            "product": self.settings.target_product,
            "description": self._english_description(record),
            "published": record.get("published"),
            "last_modified": record.get("lastModified"),
            "status": record.get("vulnStatus"),
            "cvss": self._cvss(record),
            "weaknesses": weaknesses,
            "affected_versions": self._version_rules(record),
            "references": references,
            "source_url": (
                f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"
                if vulnerability_id
                else ""
            ),
            "source": self.settings.data_source,
        }
