"""Collect and normalize official FortiGuard PSIRT evidence referenced by NVD."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from config.products import ProductProfile
from config.settings import MANIFEST_FILENAME, Settings
from data_pipeline.contracts import CrawlOptions
from data_pipeline.nvd import NVDAdapter
from data_pipeline.schemas import SourceReference, VersionRule
from data_pipeline.versioning import derive_branch


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
ADVISORY_PATTERN = re.compile(r"FG-IR-\d{2}-\d+", re.IGNORECASE)
VERSION_PATTERN = re.compile(r"\d+(?:\.\d+){1,3}")


class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.tables: list[list[list[str]]] = []
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = []

    def handle_data(self, data: str) -> None:
        value = " ".join(data.split())
        if value:
            self.text.append(value)
            if self._cell is not None:
                self._cell.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self._cell is not None and self._row is not None:
            self._row.append(" ".join(self._cell))
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            if self._row:
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            if self._table:
                self.tables.append(self._table)
            self._table = None


def _official_psirt_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in {
        "fortiguard.fortinet.com",
        "www.fortiguard.com",
        "fortiguard.com",
    } and "/psirt/" in parsed.path.lower()


class FortiGuardAdapter:
    def __init__(self, settings: Settings, profile: ProductProfile) -> None:
        self.settings = settings
        self.profile = profile

    @staticmethod
    def _advisory_urls(nvd_run: Path) -> list[str]:
        urls: set[str] = set()
        for page in sorted(nvd_run.glob("page_*.json")):
            payload = json.loads(page.read_text(encoding="utf-8"))
            for item in payload.get("vulnerabilities", []):
                for reference in item.get("cve", {}).get("references", []):
                    url = str(reference.get("url", ""))
                    if _official_psirt_url(url):
                        urls.add(url.split("?")[0].rstrip("/"))
        return sorted(urls)

    def crawl(self, nvd_run: Path, options: CrawlOptions | None = None) -> Path:
        selected = options or CrawlOptions()
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        run_dir = selected.output_dir or self.settings.raw_product_source_dir(self.profile.product_id, "fortiguard") / run_id
        if run_dir.exists() and any(run_dir.iterdir()):
            raise FileExistsError(f"Raw run là immutable và đã có dữ liệu: {run_dir}")
        run_dir.mkdir(parents=True, exist_ok=True)
        urls = self._advisory_urls(nvd_run)
        session = NVDAdapter._create_session_for_settings(self.settings)
        pages: list[dict[str, str]] = []
        created_at = datetime.now(UTC).isoformat()

        def save_manifest(status: str, error: str | None = None) -> None:
            manifest: dict[str, Any] = {
                "source": "fortiguard",
                "status": status,
                "product_id": self.profile.product_id,
                "created_at": created_at,
                "updated_at": datetime.now(UTC).isoformat(),
                "input_nvd_run": nvd_run.name,
                "advisory_count": len(pages),
                "pages": pages,
            }
            if error:
                manifest["error"] = error
            (run_dir / MANIFEST_FILENAME).write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        save_manifest("running")
        try:
            for url in urls:
                advisory_match = ADVISORY_PATTERN.search(url)
                advisory_id = advisory_match.group(0).upper() if advisory_match else hashlib.sha256(url.encode()).hexdigest()[:16]
                response = session.get(url, timeout=self.settings.source_request_timeout)
                response.raise_for_status()
                path = run_dir / f"{advisory_id}.html"
                path.write_text(response.text, encoding="utf-8")
                pages.append({"advisory_id": advisory_id, "url": url, "file": path.name})
                save_manifest("running")
                time.sleep(self.settings.source_request_delay)
        except Exception as exc:
            save_manifest("failed", f"{type(exc).__name__}: {exc}")
            raise
        finally:
            session.close()
        save_manifest("completed")
        self.process(run_dir)
        return run_dir

    @staticmethod
    def _parse_rule(branch_cell: str, affected: str, solution: str, source_id: str) -> list[VersionRule]:
        branch_match = VERSION_PATTERN.search(branch_cell)
        branch = derive_branch(branch_match.group(0)) if branch_match else None
        evidence = f"{branch_cell} | Affected: {affected} | Solution: {solution}"
        rules: list[VersionRule] = []
        affected_lower = affected.lower()
        if "not affected" in affected_lower:
            if branch:
                rules.append(VersionRule(source_id=source_id, authority="vendor", status="not_affected", branch=branch, evidence_text=evidence, priority=1))
        elif "all version" in affected_lower:
            if branch:
                rules.append(VersionRule(source_id=source_id, authority="vendor", status="affected", branch=branch, evidence_text=evidence, priority=1))
        else:
            versions = VERSION_PATTERN.findall(affected)
            if "through" in affected_lower and len(versions) >= 2:
                rules.append(VersionRule(source_id=source_id, authority="vendor", status="affected", branch=branch, version_start_including=versions[0], version_end_including=versions[1], evidence_text=evidence, priority=1))
            elif versions:
                rules.append(VersionRule(source_id=source_id, authority="vendor", status="affected", branch=branch, exact_versions=tuple(versions), evidence_text=evidence, priority=1))

        fixed = VERSION_PATTERN.search(solution)
        if fixed:
            if "or above" in solution.lower():
                rules.append(VersionRule(source_id=source_id, authority="vendor", status="not_affected", branch=branch or derive_branch(fixed.group(0)), version_start_including=fixed.group(0), fixed_versions=(fixed.group(0),), evidence_text=evidence, priority=1))
            else:
                rules.append(VersionRule(source_id=source_id, authority="vendor", status="not_affected", branch=branch or derive_branch(fixed.group(0)), exact_versions=(fixed.group(0),), fixed_versions=(fixed.group(0),), evidence_text=evidence, priority=1))
        return rules

    def process(self, run_dir: Path) -> int:
        manifest = json.loads((run_dir / MANIFEST_FILENAME).read_text(encoding="utf-8"))
        rows: list[dict[str, Any]] = []
        retrieved_at = datetime.now(UTC).isoformat()
        for page in manifest.get("pages", []):
            path = run_dir / page["file"]
            html = path.read_text(encoding="utf-8")
            parser = _TableParser()
            parser.feed(html)
            full_text = " ".join(parser.text)
            cves = sorted({match.group(0).upper() for match in CVE_PATTERN.finditer(full_text)})
            rules: list[VersionRule] = []
            for table in parser.tables:
                for row in table:
                    if len(row) < 3 or "fortios" not in row[0].lower():
                        continue
                    rules.extend(self._parse_rule(row[0], row[1], row[2], page["advisory_id"]))
            source = SourceReference(
                source_id=page["advisory_id"], authority="vendor", source_type="fortiguard_psirt",
                url=page["url"], title=page["advisory_id"], retrieved_at=retrieved_at,
                raw_path=self.settings.source_file_reference(path),
            )
            for cve in cves:
                rows.append({"vulnerability_id": cve, "source": source.model_dump(mode="json"), "version_rules": [rule.model_dump(mode="json") for rule in rules]})
        with (run_dir / "advisories.jsonl").open("w", encoding="utf-8", newline="\n") as file:
            for row in rows:
                file.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        return len(rows)
