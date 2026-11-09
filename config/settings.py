"""Environment-based configuration shared by all project components."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from math import isfinite
from pathlib import Path

from dotenv import load_dotenv


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = PACKAGE_ROOT if (PACKAGE_ROOT / "pyproject.toml").is_file() else Path.cwd().resolve()
DEFAULT_PRODUCT_CONFIG = PACKAGE_ROOT / "config" / "products.json"
MANIFEST_FILENAME = "manifest.json"


def _path_from_env(name: str, default: Path) -> Path:
    path = Path(os.getenv(name) or default).expanduser()
    return (PROJECT_ROOT / path).resolve()


def _data_path_from_env(legacy_name: str, subdir: str) -> Path:
    if os.getenv("DATA_DIR"):
        return _path_from_env("DATA_DIR", Path("data")) / subdir
    return _path_from_env(legacy_name, Path("data") / subdir)


@dataclass(frozen=True)
class Settings:
    """Runtime settings shared by product-independent components."""

    data_source: str = field(
        default_factory=lambda: os.getenv("DATA_SOURCE", "nvd").strip().lower()
    )
    default_product_id: str = field(
        default_factory=lambda: os.getenv("DEFAULT_PRODUCT_ID", "fortios")
        .strip()
        .lower()
    )
    product_config_file: Path = field(
        default_factory=lambda: _path_from_env("PRODUCT_CONFIG_FILE", DEFAULT_PRODUCT_CONFIG)
    )

    raw_data_dir: Path = field(
        default_factory=lambda: _data_path_from_env("RAW_DATA_DIR", "raw")
    )
    processed_data_dir: Path = field(
        default_factory=lambda: _data_path_from_env("PROCESSED_DATA_DIR", "processed")
    )
    curated_data_dir: Path = field(
        default_factory=lambda: _data_path_from_env("CURATED_DATA_DIR", "curated")
    )
    reference_data_dir: Path = field(
        default_factory=lambda: _data_path_from_env("REFERENCE_DATA_DIR", "reference")
    )
    artifacts_dir: Path = field(
        default_factory=lambda: _path_from_env("ARTIFACTS_DIR", Path("artifacts"))
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
        repr=False,
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
    source_request_timeout: float = field(
        default_factory=lambda: float(os.getenv("SOURCE_REQUEST_TIMEOUT", "60"))
    )
    source_max_retries: int = field(
        default_factory=lambda: int(os.getenv("SOURCE_MAX_RETRIES", "3"))
    )
    source_retry_backoff: float = field(
        default_factory=lambda: float(os.getenv("SOURCE_RETRY_BACKOFF", "2"))
    )
    source_user_agent: str = field(
        default_factory=lambda: os.getenv(
            "SOURCE_USER_AGENT", "netvuln-rag/0.1"
        ).strip()
    )

    qdrant_url: str = field(
        default_factory=lambda: os.getenv("QDRANT_URL", "http://localhost:6333")
    )
    qdrant_api_key: str = field(repr=False, default_factory=lambda: os.getenv("QDRANT_API_KEY", ""))
    qdrant_collection: str = field(
        default_factory=lambda: os.getenv(
            "QDRANT_COLLECTION", "netvuln_vulnerabilities_v1"
        )
    )
    embedding_provider: str = field(
        default_factory=lambda: os.getenv("EMBEDDING_PROVIDER", "local").strip().lower()
    )
    embedding_model: str = field(
        default_factory=lambda: os.getenv(
            "EMBEDDING_MODEL",
            "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
        )
    )
    embedding_device: str | None = field(
        default_factory=lambda: os.getenv("EMBEDDING_DEVICE", "").strip().lower() or None
    )
    embedding_cache_dir: Path | None = field(
        default_factory=lambda: _path_from_env("EMBEDDING_CACHE_DIR", Path("."))
        if os.getenv("EMBEDDING_CACHE_DIR")
        else None
    )
    embedding_batch_size: int = field(
        default_factory=lambda: int(os.getenv("EMBEDDING_BATCH_SIZE", "32"))
    )
    embedding_dimensions: int = field(
        default_factory=lambda: int(os.getenv("EMBEDDING_DIMENSIONS", "384"))
    )
    embedding_document_prefix: str = field(
        default_factory=lambda: os.getenv("EMBEDDING_DOCUMENT_PREFIX", "")
    )
    embedding_query_prefix: str = field(
        default_factory=lambda: os.getenv("EMBEDDING_QUERY_PREFIX", "")
    )

    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "ollama"))
    llm_timeout: float = field(
        default_factory=lambda: float(os.getenv("LLM_TIMEOUT", "120"))
    )
    gemini_api_key: str = field(
        repr=False,
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip()
    )
    gemini_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite").strip()
    )
    groq_api_key: str = field(
        repr=False,
        default_factory=lambda: os.getenv("GROQ_API_KEY", "").strip()
    )
    groq_model: str = field(
        default_factory=lambda: os.getenv("GROQ_MODEL", "openai/gpt-oss-120b").strip()
    )
    ollama_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434")
    )
    ollama_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    )
    openai_api_key: str = field(repr=False, default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    )

    top_k: int = field(default_factory=lambda: int(os.getenv("TOP_K", "5")))
    min_score: float = field(default_factory=lambda: float(os.getenv("MIN_SCORE", "0")))
    llm_max_output_tokens: int = field(
        default_factory=lambda: int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "2048"))
    )
    context_max_chars: int = field(
        default_factory=lambda: int(os.getenv("CONTEXT_MAX_CHARS", "6000"))
    )

    def __post_init__(self) -> None:
        if self.embedding_device == "auto":
            object.__setattr__(self, "embedding_device", None)
        for name, value in (
            ("SOURCE_PAGE_SIZE", self.source_page_size),
            ("EMBEDDING_BATCH_SIZE", self.embedding_batch_size),
            ("TOP_K", self.top_k),
            ("SOURCE_REQUEST_TIMEOUT", self.source_request_timeout),
            ("LLM_TIMEOUT", self.llm_timeout),
            ("LLM_MAX_OUTPUT_TOKENS", self.llm_max_output_tokens),
            ("CONTEXT_MAX_CHARS", self.context_max_chars),
        ):
            if not isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        for name, value in (
            ("SOURCE_REQUEST_DELAY", self.source_request_delay),
            ("SOURCE_MAX_RETRIES", self.source_max_retries),
            ("SOURCE_RETRY_BACKOFF", self.source_retry_backoff),
        ):
            if not isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and nonnegative")
        if self.embedding_provider not in {"local", "qdrant_cloud"}:
            raise ValueError("EMBEDDING_PROVIDER must be local or qdrant_cloud")
        if self.embedding_provider == "qdrant_cloud" and self.embedding_dimensions < 1:
            raise ValueError("EMBEDDING_DIMENSIONS must be positive for Qdrant Cloud Inference")

    def raw_product_source_dir(self, product_id: str, source: str | None = None) -> Path:
        return self.raw_data_dir / product_id / (source or self.data_source)

    def source_file_reference(self, path: Path) -> str | None:
        resolved = path.resolve()
        for namespace, directory in (("raw", self.raw_data_dir), ("curated", self.curated_data_dir)):
            root = directory.resolve()
            if resolved.is_relative_to(root):
                return (Path(namespace) / resolved.relative_to(root)).as_posix()
        return None

    @property
    def structured_data_dir(self) -> Path:
        return self.processed_data_dir / "structured"

    @property
    def chunks_data_dir(self) -> Path:
        return self.processed_data_dir / "chunks"

    def structured_file(self, product_id: str) -> Path:
        return self.structured_data_dir / product_id / "vulnerabilities.jsonl"

    def chunks_file(self, product_id: str) -> Path:
        return self.chunks_data_dir / product_id / "chunks.jsonl"

    @property
    def processed_manifest(self) -> Path:
        return self.processed_data_dir / MANIFEST_FILENAME

    @property
    def normalized_manifest(self) -> Path:
        return self.processed_data_dir / "normalized-manifest.json"

    @property
    def nvd_catalog_dir(self) -> Path:
        return self.reference_data_dir / "nvd"

    @property
    def all_cve_ids_file(self) -> Path:
        return self.nvd_catalog_dir / "all_cve_ids.txt"

    @property
    def evaluation_dir(self) -> Path:
        return self.artifacts_dir / "evaluation"

    @property
    def evaluation_questions_file(self) -> Path:
        return self.evaluation_dir / "questions.jsonl"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv(PROJECT_ROOT / ".env")
    return Settings()
