"""NVD API adapter: raw collection and conversion to the common schema."""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import MANIFEST_FILENAME, Settings
from config.products import ProductProfile, VersionTarget
from data_pipeline.contracts import CrawlOptions
from data_pipeline.schemas import CVE_PATTERN, SourceReference, VersionRule, VulnerabilityRecord
from data_pipeline.versioning import derive_branch


def cve_url(identifier: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{identifier}"


def cve_description(record: dict[str, Any]) -> str:
    descriptions = record.get("descriptions", [])
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", "")).strip()
    if descriptions:
        return str(descriptions[0].get("value", "")).strip()
    return ""


def cve_weaknesses(record: dict[str, Any]) -> tuple[str, ...]:
    return tuple(sorted({
        description["value"]
        for weakness in record.get("weaknesses", [])
        for description in weakness.get("description", [])
        if description.get("value")
    }))


class NVDAdapter:
    """Keep all NVD-specific request and response knowledge in one adapter."""

    def __init__(self, settings: Settings, profile: ProductProfile) -> None:
        self.settings = settings
        self.profile = profile

    @staticmethod
    def _save_json(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)

    def _create_session(self) -> requests.Session:
        return self._create_session_for_settings(self.settings)

    @staticmethod
    def _create_session_for_settings(settings: Settings) -> requests.Session:
        retries = Retry(
            total=settings.source_max_retries,
            connect=settings.source_max_retries,
            read=settings.source_max_retries,
            status=settings.source_max_retries,
            backoff_factor=settings.source_retry_backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": settings.source_user_agent,
            }
        )
        if settings.source_api_key:
            session.headers["apiKey"] = settings.source_api_key
        return session

    def crawl(self, options: CrawlOptions | None = None) -> Path:
        selected = options or CrawlOptions()
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        run_dir = selected.output_dir or self.settings.raw_product_source_dir(
            self.profile.product_id, "nvd"
        ) / run_id
        if run_dir.exists() and any(run_dir.iterdir()):
            raise FileExistsError(f"Raw run là immutable và đã có dữ liệu: {run_dir}")
        run_dir.mkdir(parents=True, exist_ok=True)

        created_at = datetime.now(UTC).isoformat()
        page_files: list[str] = []
        queries: list[dict[str, Any]] = []
        manifest_path = run_dir / MANIFEST_FILENAME
        manifest_path.touch(exist_ok=False)

        def save_manifest(status: str, error: str | None = None) -> None:
            manifest: dict[str, Any] = {
                "source": self.settings.data_source,
                "status": status,
                "created_at": created_at,
                "updated_at": datetime.now(UTC).isoformat(),
                "product_id": self.profile.product_id,
                "target_vendor": self.profile.vendor,
                "target_product": self.profile.product,
                "target_cpe": self.profile.cpe,
                "api_url": self.settings.source_api_url,
                "requested_limit": selected.limit,
                "total_results": sum(query["total_results"] for query in queries),
                "downloaded": sum(query["downloaded"] for query in queries),
                "stopped_early": any(query["stopped_early"] for query in queries),
                "pages": page_files,
            }
            if self.profile.versions:
                manifest["version_queries"] = queries
            if error:
                manifest["error"] = error
            self._save_json(manifest_path, manifest)

        save_manifest("running")
        session = self._create_session()
        try:
            for target in self.profile.versions or (None,):
                cpe = target.cpe if target else self.profile.cpe
                filters = {"cpeName": cpe, "isVulnerable": ""} if target else {"virtualMatchString": cpe}
                query: dict[str, Any] = {
                    "version": target.version if target else None,
                    "cpe": cpe,
                    "total_results": 0,
                    "downloaded": 0,
                    "stopped_early": False,
                    "pages": [],
                }
                queries.append(query)
                seen_cves: set[str] = set()
                while True:
                    downloaded = query["downloaded"]
                    page_size = self.settings.source_page_size
                    if selected.limit is not None:
                        page_size = min(page_size, selected.limit - downloaded)
                    if page_files:
                        time.sleep(self.settings.source_request_delay)
                    response = session.get(
                        self.settings.source_api_url,
                        params={
                            **filters,
                            "resultsPerPage": page_size,
                            "startIndex": downloaded,
                            "noRejected": "",
                        },
                        timeout=self.settings.source_request_timeout,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                        raise ValueError("NVD API response cần có danh sách vulnerabilities")
                    total_results = payload.get("totalResults")
                    page_count = len(payload["vulnerabilities"])
                    if (
                        type(total_results) is not int
                        or total_results < downloaded + page_count
                        or (query["pages"] and total_results != query["total_results"])
                        or payload.get("startIndex", downloaded) != downloaded
                        or (page_count == 0 and downloaded < total_results)
                        or (selected.limit is not None and downloaded + page_count > selected.limit)
                    ):
                        raise ValueError(f"NVD trả về trang không nhất quán cho {cpe} tại offset {downloaded}")
                    for item in payload["vulnerabilities"]:
                        cve = str(item["cve"]["id"]).upper()
                        if not CVE_PATTERN.fullmatch(cve) or cve in seen_cves:
                            raise ValueError(f"NVD trả về CVE không hợp lệ hoặc bị trùng cho {cpe}: {cve}")
                        seen_cves.add(cve)
                    page_name = f"page_{len(page_files) + 1:04d}.json"
                    self._save_json(run_dir / page_name, payload)
                    page_files.append(page_name)
                    query["pages"].append(page_name)
                    query["total_results"] = total_results
                    query["downloaded"] += page_count
                    query["stopped_early"] = query["downloaded"] == selected.limit and query["downloaded"] < total_results
                    save_manifest("running")
                    print(f"{target.version if target else self.profile.product_id}: {query['downloaded']}/{total_results} records")
                    if query["downloaded"] == total_results or query["stopped_early"]:
                        break
        except Exception as exc:
            save_manifest("failed", f"{type(exc).__name__}: {exc}")
            raise
        finally:
            session.close()

        save_manifest("completed")
        return run_dir

    def process(self, input_path: Path, output_path: Path) -> int:
        run_dir = input_path if input_path.is_dir() else input_path.parent
        manifest_path = run_dir / MANIFEST_FILENAME
        retrieved_at = None
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            retrieved_at = manifest.get("updated_at") or manifest.get("created_at")
        if self.profile.versions:
            records = self._normalize_version_queries(input_path, retrieved_at)
        else:
            records = self._normalize_product_query(input_path, retrieved_at)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="\n") as file:
            for record_id in sorted(records):
                file.write(records[record_id].model_dump_json() + "\n")
        return len(records)

    def _normalize_product_query(
        self, input_path: Path, retrieved_at: str | None = None,
    ) -> dict[str, VulnerabilityRecord]:
        page_files = self._find_page_files(input_path)
        if not page_files:
            raise FileNotFoundError(f"Không tìm thấy page_*.json trong {input_path}")

        records_by_id: dict[str, VulnerabilityRecord] = {}
        for page_path in page_files:
            with page_path.open("r", encoding="utf-8") as file:
                page = json.load(file)
            for item in page.get("vulnerabilities", []):
                record = self._normalize(item.get("cve", {}), page_path, retrieved_at=retrieved_at)
                records_by_id[record.vulnerability_id] = record
        return records_by_id

    def read_version_queries(
        self, run_dir: Path, *, require_complete: bool = False
    ) -> Iterable[tuple[VersionTarget, dict[str, tuple[Path, dict[str, Any]]]]]:
        """Read the raw CVE membership for each configured CPE from one NVD run."""
        manifest = json.loads((run_dir / MANIFEST_FILENAME).read_text(encoding="utf-8"))
        queries = manifest.get("version_queries")
        if manifest.get("status") != "completed" or manifest.get("product_id") != self.profile.product_id or not queries:
            raise ValueError(f"{run_dir} cần là completed run crawl theo CPE từng phiên bản")
        targets = [VersionTarget(version=query["version"], cpe=query["cpe"]) for query in queries]
        if len(targets) != len(self.profile.versions) or set(targets) != set(self.profile.versions):
            raise ValueError(f"Version/CPE trong {run_dir} khác cấu hình hiện tại. Hãy crawl lại.")
        used_pages: set[str] = set()
        for target, query in zip(targets, queries, strict=True):
            records: dict[str, tuple[Path, dict[str, Any]]] = {}
            pages = query["pages"]
            if not pages:
                raise ValueError(f"{run_dir} thiếu trang cho {target.version}")
            for name in pages:
                if not re.fullmatch(r"page_[0-9]+\.json", name) or name in used_pages:
                    raise ValueError(f"Tên page không hợp lệ hoặc bị trùng trong {run_dir}: {name}")
                used_pages.add(name)
                path = run_dir / name
                page = json.loads(path.read_text(encoding="utf-8"))
                if page["totalResults"] != query["total_results"] or page.get("startIndex", len(records)) != len(records):
                    raise ValueError(f"Offset hoặc tổng số CVE trong raw page khác manifest: {path}")
                for item in page["vulnerabilities"]:
                    record = item["cve"]
                    cve = record["id"].upper()
                    if not CVE_PATTERN.fullmatch(cve) or cve in records:
                        raise ValueError(f"CVE không hợp lệ hoặc bị trùng trong {path}: {cve}")
                    records[cve] = (path, record)
            if len(records) != query["downloaded"] or len(records) > query["total_results"]:
                raise ValueError(f"Số CVE trong raw page khác manifest cho {target.version}: {run_dir}")
            if require_complete and len(records) != query["total_results"]:
                raise ValueError(f"Crawl {target.version} chưa đủ CVE trong {run_dir}. Hãy crawl lại bỏ --limit.")
            yield target, records

    def _normalize_version_queries(
        self, run_dir: Path, retrieved_at: str | None = None,
    ) -> dict[str, VulnerabilityRecord]:
        source_records: dict[str, tuple[Path, dict[str, Any]]] = {}
        rules: dict[str, list[VersionRule]] = {}
        for target, records in self.read_version_queries(run_dir):
            for cve, source_record in records.items():
                source_records.setdefault(cve, source_record)
                rules.setdefault(cve, []).append(VersionRule(
                    source_id=f"nvd:{cve}",
                    authority="nvd",
                    status="affected",
                    exact_versions=(target.version,),
                    literal_exact=True,
                    evidence_text=f"NVD CVE API returned this CVE for {target.cpe} with isVulnerable.",
                ))
        return {
            cve: self._normalize(raw, path, rules[cve], retrieved_at=retrieved_at)
            for cve, (path, raw) in source_records.items()
        }

    @staticmethod
    def _find_page_files(input_path: Path) -> list[Path]:
        if input_path.is_file():
            return [input_path]
        return sorted(input_path.glob("**/page_*.json"))

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

    def _version_rules(self, record: dict[str, Any]) -> list[VersionRule]:
        rules: list[VersionRule] = []
        seen: set[str] = set()
        for match in self._walk_cpe_matches(record.get("configurations", [])):
            criteria = str(match.get("criteria", ""))
            parts = criteria.split(":")
            is_target = (
                len(parts) >= 6
                and parts[3].lower() == self.profile.vendor
                and parts[4].lower() == self.profile.product
            )
            if not is_target:
                continue
            # In NVD logical configurations, vulnerable=false commonly denotes a
            # required environment component; it is not proof that the target
            # product/version is safe.
            if not bool(match.get("vulnerable", False)):
                continue

            exact = parts[5]
            exact_versions = () if exact in {"", "*", "-"} else (exact,)
            boundary_values = [
                str(match.get(field))
                for field in (
                    "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding",
                )
                if match.get(field)
            ]
            branches = {branch for value in boundary_values for branch in (derive_branch(value),) if branch}
            branch = derive_branch(exact) if exact_versions else (next(iter(branches)) if len(branches) == 1 else None)
            rule = VersionRule(
                source_id="nvd:pending",
                authority="nvd",
                status="affected",
                branch=branch,
                all_versions=not exact_versions and not any(
                    match.get(field)
                    for field in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding",
                    )
                ),
                exact_versions=exact_versions,
                version_start_including=match.get("versionStartIncluding"),
                version_start_excluding=match.get("versionStartExcluding"),
                version_end_including=match.get("versionEndIncluding"),
                version_end_excluding=match.get("versionEndExcluding"),
                evidence_text=f"NVD CPE configuration {criteria}",
                priority=2,
            )
            fingerprint = rule.model_dump_json()
            if fingerprint not in seen:
                rules.append(rule)
                seen.add(fingerprint)
        return rules

    def _normalize(
        self,
        record: dict[str, Any],
        raw_path: Path | None = None,
        version_rules: Iterable[VersionRule] | None = None,
        *,
        retrieved_at: str | None = None,
    ) -> VulnerabilityRecord:
        vulnerability_id = str(record.get("id", "")).upper()
        source_id = f"nvd:{vulnerability_id}"
        rules = tuple(
            rule.model_copy(update={"source_id": source_id})
            for rule in (self._version_rules(record) if version_rules is None else version_rules)
        )
        source = SourceReference(
            source_id=source_id,
            authority="nvd",
            source_type="nvd_cve",
            url=cve_url(vulnerability_id),
            title=f"NVD record for {vulnerability_id}",
            published=record.get("published"),
            updated=record.get("lastModified"),
            retrieved_at=retrieved_at,
            raw_path=self.settings.source_file_reference(raw_path) if raw_path else None,
        )
        return VulnerabilityRecord(
            record_id=f"{self.profile.product_id}:{vulnerability_id}",
            vulnerability_id=vulnerability_id,
            product_id=self.profile.product_id,
            vendor=self.profile.vendor,
            product=self.profile.product,
            display_name=self.profile.display_name,
            description=cve_description(record),
            published=record.get("published"),
            last_modified=record.get("lastModified"),
            status=record.get("vulnStatus"),
            cvss=self._cvss(record),
            weaknesses=cve_weaknesses(record),
            sources=(source,),
            applicability=rules,
            effective_rules=rules,
        )
