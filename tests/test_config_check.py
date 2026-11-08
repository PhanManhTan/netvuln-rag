import sys
from dataclasses import replace
from types import SimpleNamespace

from config import check
from config.settings import Settings


def test_crawl_check_passes_before_data_exists(tmp_path, monkeypatch, capsys) -> None:
    raw = tmp_path / "new-data" / "raw"
    settings = Settings(raw_data_dir=raw, processed_data_dir=tmp_path / "new-data" / "processed")
    monkeypatch.setattr(check, "get_settings", lambda: settings)

    assert check.main(["--stage", "crawl"]) == 0
    assert not raw.exists()
    assert "[OK] Raw output" in capsys.readouterr().out


def test_chat_check_reports_missing_prerequisites_without_exposing_keys(tmp_path, monkeypatch, capsys) -> None:
    settings = Settings(
        processed_data_dir=tmp_path / "missing",
        embedding_provider="qdrant_cloud",
        qdrant_api_key="synthetic-secret",
        qdrant_url="https://example.com",
        llm_provider="groq",
        groq_api_key="",
    )
    monkeypatch.setattr(check, "get_settings", lambda: settings)

    assert check.main([]) == 1
    output = capsys.readouterr().out
    assert "[FAIL] Corpus" in output
    assert "[FAIL] LLM: Set GROQ_API_KEY" in output
    assert "synthetic-secret" not in output


def test_local_check_reports_unavailable_cuda_device(tmp_path, monkeypatch, capsys) -> None:
    settings = Settings(
        processed_data_dir=tmp_path,
        embedding_provider="local",
        embedding_device="cuda:2",
        embedding_cache_dir=tmp_path,
        qdrant_url="http://localhost:6333",
    )
    monkeypatch.setattr(check, "find_spec", lambda name: object())
    torch = SimpleNamespace(
        device=lambda name: SimpleNamespace(type=name.split(":")[0], index=2),
        cuda=SimpleNamespace(is_available=lambda: True, device_count=lambda: 1),
    )
    monkeypatch.setitem(sys.modules, "torch", torch)
    monkeypatch.setattr(check, "get_settings", lambda: settings)
    monkeypatch.setattr(check, "processed_snapshot_paths", lambda settings: {"structured": [tmp_path], "chunks": [tmp_path]})

    assert check.main(["--stage", "index"]) == 1
    assert "EMBEDDING_DEVICE=cuda:2 is unavailable" in capsys.readouterr().out

    settings = replace(settings, embedding_device="cpu")
    assert check.main(["--stage", "index"]) == 0
    assert "device=cpu" in capsys.readouterr().out
