"""Check the configuration and local prerequisites for a pipeline stage."""

from __future__ import annotations

import argparse
import os
from importlib.util import find_spec
from pathlib import Path
from urllib.parse import urlsplit

from config.products import get_product_catalog
from config.settings import Settings, get_settings
from data_pipeline.process import load_processed_manifest, processed_snapshot_paths
from data_pipeline.registry import get_source_adapter
from evaluation.dataset import load_questions, validate_question_runs
from rag.generation.client import LLMClient


def _http_url(value: str, setting: str) -> None:
    try:
        url = urlsplit(value)
        valid = (
            url.scheme in {"http", "https"}
            and url.hostname
            and not any(character.isspace() for character in value)
            and (url.port is None or url.port > 0)
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(f"Set {setting} to a valid HTTP or HTTPS URL")


def _output_directory(path: Path) -> str:
    existing = next((directory for directory in (path, *path.parents) if directory.exists()), None)
    if existing is None or not existing.is_dir() or not os.access(existing, os.W_OK):
        raise ValueError(f"No writable directory for {path} (checked {existing})")
    return str(path)


def _products(settings: Settings) -> str:
    catalog = get_product_catalog(settings.product_config_file)
    catalog.by_id(settings.default_product_id)
    return f"{', '.join(profile.product_id for profile in catalog.products)} ({settings.product_config_file})"


def _crawl_source(settings: Settings) -> str:
    catalog = get_product_catalog(settings.product_config_file)
    get_source_adapter(settings, catalog.by_id(settings.default_product_id))
    _http_url(settings.source_api_url, "SOURCE_API_URL")
    return settings.data_source


def _corpus(settings: Settings) -> str:
    paths = processed_snapshot_paths(settings)
    if not paths["structured"] or not paths["chunks"]:
        raise ValueError(f"No processed records or chunks in {settings.processed_data_dir}. Run data_pipeline.prepare.")
    return f"{len(paths['structured'])} record file(s), {len(paths['chunks'])} chunk file(s) in {settings.processed_data_dir}"


def _qdrant(settings: Settings) -> str:
    _http_url(settings.qdrant_url, "QDRANT_URL")
    if not settings.qdrant_collection.strip():
        raise ValueError("Set QDRANT_COLLECTION")
    if settings.embedding_provider == "qdrant_cloud" and not settings.qdrant_api_key.strip():
        raise ValueError("Set QDRANT_API_KEY for Qdrant Cloud Inference")
    return settings.qdrant_collection


def _embeddings(settings: Settings) -> str:
    if not settings.embedding_model.strip():
        raise ValueError("Set EMBEDDING_MODEL")
    if settings.embedding_provider == "qdrant_cloud":
        return f"qdrant_cloud, {settings.embedding_model}, {settings.embedding_dimensions} dimensions"

    if find_spec("sentence_transformers") is None:
        raise ValueError("Install requirements.txt to use local embeddings")
    device_name = settings.embedding_device or "auto"
    if settings.embedding_device:
        import torch

        device = torch.device(settings.embedding_device)
        if device.type != "cpu":
            backend = getattr(torch, device.type, None)
            available = getattr(backend, "is_available", lambda: False)
            device_count = getattr(backend, "device_count", None)
            if not available() or (
                device.index is not None and device_count and device.index >= device_count()
            ):
                raise ValueError(f"EMBEDDING_DEVICE={settings.embedding_device} is unavailable")

    cache = _output_directory(settings.embedding_cache_dir) if settings.embedding_cache_dir else "default"
    return f"local, {settings.embedding_model}, device={device_name}, cache={cache}"


def _llm(settings: Settings, provider: str) -> str:
    if provider not in LLMClient.supported_providers:
        raise ValueError(f"Set LLM_PROVIDER to one of {', '.join(LLMClient.supported_providers)}")
    model = LLMClient(settings).model_name(provider)
    if not model.strip():
        raise ValueError(f"Set {provider.upper()}_MODEL")
    if provider == "ollama":
        _http_url(settings.ollama_url, "OLLAMA_URL")
    elif not getattr(settings, f"{provider}_api_key").strip():
        raise ValueError(f"Set {provider.upper()}_API_KEY")
    return f"{provider}, {model}"


def _dataset(settings: Settings, dataset: Path) -> str:
    questions = load_questions(dataset)
    if not questions:
        raise ValueError(f"No questions in {dataset}")
    manifest = load_processed_manifest(settings)
    catalog = get_product_catalog(settings.product_config_file)
    product_ids = {profile.product_id for profile in catalog.products}
    active_manifest = {
        "products": [item for item in manifest["products"] if item["product_id"] in product_ids]
    }
    validate_question_runs(questions, active_manifest, settings.data_source)
    return f"{len(questions)} question(s) in {dataset}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("crawl", "index", "chat", "evaluate"), default="chat")
    parser.add_argument("--dataset", type=Path, help="Question file for the evaluate stage")
    parser.add_argument("--output-dir", type=Path, help="Output directory override for evaluation")
    parser.add_argument("--provider", choices=LLMClient.supported_providers, help="LLM provider override")
    args = parser.parse_args(argv)
    try:
        settings = get_settings()
    except (OSError, ValueError) as exc:
        print(f"[FAIL] Settings: {exc}")
        return 1

    provider = args.provider or settings.llm_provider.strip().lower()
    checks = [("Product catalog", lambda: _products(settings))]
    if args.stage == "crawl":
        checks.extend([
            ("Source", lambda: _crawl_source(settings)),
            ("Raw output", lambda: _output_directory(settings.raw_data_dir)),
            ("Processed output", lambda: _output_directory(settings.processed_data_dir)),
        ])
    else:
        checks.extend([
            ("Corpus", lambda: _corpus(settings)),
            ("Qdrant", lambda: _qdrant(settings)),
            ("Embeddings", lambda: _embeddings(settings)),
        ])
    if args.stage in {"chat", "evaluate"}:
        checks.append(("LLM", lambda: _llm(settings, provider)))
    if args.stage == "evaluate":
        dataset = (args.dataset or settings.evaluation_questions_file).resolve()
        checks.extend([
            ("Questions", lambda: _dataset(settings, dataset)),
            ("Evaluation output", lambda: _output_directory((args.output_dir or settings.evaluation_dir).resolve())),
        ])

    failed = False
    for label, check in checks:
        try:
            detail = check()
        except (OSError, ValueError, LookupError, TypeError, ImportError, RuntimeError) as exc:
            print(f"[FAIL] {label}: {exc}")
            failed = True
        else:
            print(f"[OK] {label}: {detail}")
    print("Offline checks only. Service connectivity and model downloads are checked when you run the stage.")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
