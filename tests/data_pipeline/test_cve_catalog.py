import json
from pathlib import Path
from typing import Any

import pytest

from config.settings import Settings
from data_pipeline.cve_catalog import load_catalog, load_catalog_manifest, refresh_catalog
from data_pipeline.nvd import NVDAdapter


class Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload


class Session:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls = 0

    def get(self, *args: Any, **kwargs: Any) -> Response:
        assert "noRejected" not in kwargs["params"]
        result = Response(self.pages[self.calls])
        self.calls += 1
        return result

    def close(self) -> None:
        return None


def test_catalog_is_uppercase_and_hashed(tmp_path: Path, monkeypatch) -> None:
    settings = Settings(reference_data_dir=tmp_path, source_page_size=2, source_request_delay=0)
    session = Session([
        {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "cve-2024-0002"}}, {"cve": {"id": "CVE-2024-0001"}}]},
        {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2024-0003", "vulnStatus": "Rejected"}}]},
    ])
    monkeypatch.setattr(NVDAdapter, "_create_session_for_settings", lambda selected: session)

    manifest = refresh_catalog(settings)

    assert load_catalog(settings.all_cve_ids_file) == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
    assert manifest["cve_count"] == 3
    assert manifest["includes_rejected"] is True
    stored = json.loads((settings.nvd_catalog_dir / "manifest.json").read_text(encoding="utf-8"))
    assert load_catalog_manifest(settings.all_cve_ids_file) == stored
    assert len(stored["sha256"]) == 64


@pytest.mark.parametrize("incomplete_page", [[], [{"cve": {"id": "cve-2024-0002"}}]])
def test_incomplete_catalog_refresh_preserves_existing_file(tmp_path: Path, monkeypatch, incomplete_page) -> None:
    settings = Settings(reference_data_dir=tmp_path, source_page_size=1, source_request_delay=0)
    settings.nvd_catalog_dir.mkdir()
    settings.all_cve_ids_file.write_text("CVE-2023-0001\n", encoding="utf-8")
    session = Session([
        {"totalResults": 2, "vulnerabilities": [{"cve": {"id": "CVE-2024-0002"}}]},
        {"totalResults": 2, "vulnerabilities": incomplete_page},
    ])
    monkeypatch.setattr(NVDAdapter, "_create_session_for_settings", lambda selected: session)

    with pytest.raises(ValueError):
        refresh_catalog(settings)

    assert load_catalog(settings.all_cve_ids_file) == {"CVE-2023-0001"}
