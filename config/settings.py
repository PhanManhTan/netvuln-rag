"""Environment-based configuration shared by all project components."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _path_from_env(name: str, default: Path) -> Path:
    return Path(os.getenv(name, str(default))).expanduser().resolve()


def _csv_from_env(name: str, default: str) -> tuple[str, ...]:
    return tuple(
        item.strip().lower()
        for item in os.getenv(name, default).split(",")
        if item.strip()
    )


@dataclass(frozen=True)
class Settings:
    """Project settings; defaults keep the current FortiOS/NVD use case working."""

    data_source: str = field(
        default_factory=lambda: os.getenv("DATA_SOURCE", "nvd").strip().lower()
    )
    target_vendor: str = field(
        default_factory=lambda: os.getenv("TARGET_VENDOR", "fortinet").strip().lower()
    )
    target_product: str = field(
        default_factory=lambda: os.getenv("TARGET_PRODUCT", "fortios").strip().lower()
    )
    target_product_aliases: tuple[str, ...] = field(
        default_factory=lambda: _csv_from_env(
            "TARGET_PRODUCT_ALIASES", "fortios,fortinet os"
        )
    )
    target_cpe: str = field(
        default_factory=lambda: os.getenv(
            "TARGET_CPE", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"
        ).strip()
    )

    raw_data_dir: Path = field(
        default_factory=lambda: _path_from_env(
            "RAW_DATA_DIR", PROJECT_ROOT / "data" / "raw"
        )
    )
    processed_data_dir: Path = field(
        default_factory=lambda: _path_from_env(
            "PROCESSED_DATA_DIR", PROJECT_ROOT / "data" / "processed"
        )
    )

    source_api_url: str = field(
        default_factory=lambda: os.getenv(
            "SOURCE_API_URL",
            os.getenv(
                "NVD_API_URL",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
            ),
        )
    )
    source_api_key: str = field(
        default_factory=lambda: os.getenv(
            "SOURCE_API_KEY", os.getenv("NVD_API_KEY", "")
        )
    )
    source_page_size: int = field(
        default_factory=lambda: int(
            os.getenv("SOURCE_PAGE_SIZE", os.getenv("NVD_RESULTS_PER_PAGE", "2000"))
        )
    )
    source_request_delay: float = field(
        default_factory=lambda: float(
            os.getenv("SOURCE_REQUEST_DELAY", os.getenv("NVD_REQUEST_DELAY", "6"))
        )
    )

    qdrant_url: str = field(
        default_factory=lambda: os.getenv("QDRANT_URL", "http://localhost:6333")
    )
    qdrant_api_key: str = field(default_factory=lambda: os.getenv("QDRANT_API_KEY", ""))
    qdrant_collection: str = field(
        default_factory=lambda: os.getenv(
            "QDRANT_COLLECTION", "netvuln_vulnerabilities_v1"
        )
    )
    embedding_model: str = field(
        default_factory=lambda: os.getenv(
            "EMBEDDING_MODEL",
            "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
        )
    )
    embedding_batch_size: int = field(
        default_factory=lambda: int(os.getenv("EMBEDDING_BATCH_SIZE", "32"))
    )

    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "ollama"))
    llm_timeout: float = field(
        default_factory=lambda: float(os.getenv("LLM_TIMEOUT", "120"))
    )
    ollama_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434")
    )
    ollama_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    )
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    )

    top_k: int = field(default_factory=lambda: int(os.getenv("TOP_K", "5")))
    min_score: float = field(default_factory=lambda: float(os.getenv("MIN_SCORE", "0")))

    @property
    def raw_source_dir(self) -> Path:
        return self.raw_data_dir / self.data_source

    @property
    def processed_file(self) -> Path:
        return self.processed_data_dir / "vulnerabilities.jsonl"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv(PROJECT_ROOT / ".env")
    return Settings()
