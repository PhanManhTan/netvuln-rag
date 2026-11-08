import pytest

from config.settings import PROJECT_ROOT, Settings


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("EMBEDDING_BATCH_SIZE", "0"),
        ("SOURCE_PAGE_SIZE", "-1"),
        ("TOP_K", "0"),
        ("SOURCE_REQUEST_DELAY", "-1"),
        ("SOURCE_MAX_RETRIES", "-1"),
        ("LLM_TIMEOUT", "nan"),
    ],
)
def test_invalid_runtime_values_fail_before_pipeline_work(monkeypatch, name, value) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=name):
        Settings()


def test_settings_repr_omits_credentials() -> None:
    credentials = {
        "source_api_key": "synthetic-source-key",
        "qdrant_api_key": "synthetic-qdrant-key",
        "gemini_api_key": "synthetic-gemini-key",
        "groq_api_key": "synthetic-groq-key",
        "openai_api_key": "synthetic-openai-key",
    }

    settings_repr = repr(Settings(**credentials))

    assert all(value not in settings_repr for value in credentials.values())


def test_local_compute_and_cache_can_be_moved_independently(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EMBEDDING_DEVICE", "cpu")
    monkeypatch.setenv("EMBEDDING_CACHE_DIR", "model-cache")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))

    settings = Settings()

    assert settings.embedding_device == "cpu"
    assert settings.embedding_cache_dir == PROJECT_ROOT / "model-cache"
    assert settings.processed_data_dir == tmp_path / "data" / "processed"
