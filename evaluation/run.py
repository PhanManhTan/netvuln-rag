"""Run the same questions with LLM-only and RAG, then compare metrics."""

from __future__ import annotations

import argparse
import json
import math
import time
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from config.products import get_product_catalog
from config.settings import get_settings
from data_pipeline.cve_catalog import load_catalog, load_catalog_manifest
from data_pipeline.process import load_processed_manifest, resolve_processed_artifact
from evaluation.client import BenchmarkClient
from evaluation.dataset import load_questions, validate_question_runs
from evaluation.metrics import compare_summaries, extract_cves, infer_status, summarize
from rag.generation.chatbot import RAGChatbot, SOURCE_LIST_SEPARATOR, load_prompts
from rag.generation.client import LLMClient
from rag.retrieval.retriever import Retriever


BASELINE_SYSTEM_PROMPT = load_prompts()["baseline_system_prompt"]


def _answer_status(answer: str, question_type: str) -> str:
    status = infer_status(answer)
    if status == "answered" and question_type in {"version_inventory", "vulnerability_detail", "semantic"}:
        if extract_cves(answer):
            return "affected"
    return status


def run_baseline(
    item: dict[str, Any], llm: LLMClient, provider: str
) -> dict[str, Any]:
    started = time.perf_counter()
    error = None
    try:
        answer = llm.generate(BASELINE_SYSTEM_PROMPT, item["question"], provider)
    except Exception as exc:
        answer = ""
        error = str(exc) or type(exc).__name__
    return {
        **item,
        "mode": "llm_only",
        "answer": answer,
        "predicted_status": "error" if error else _answer_status(answer, item["question_type"]),
        "citations": [],
        "latency_seconds": time.perf_counter() - started,
        "error": error,
    }


def run_rag(
    item: dict[str, Any], chatbot: RAGChatbot, provider: str, top_k: int
) -> dict[str, Any]:
    started = time.perf_counter()
    error = None
    evidence_cves = []
    try:
        response = chatbot.ask(item["question"], provider=provider, top_k=top_k)
        answer = response["answer"]
        citations = response["citations"]
        evidence_cves = response.get("retrieved_evidence_cves")
        if evidence_cves is None:
            evidence_cves = [citation["vulnerability_id"] for citation in citations]
        predicted_status = response["status"]
        if predicted_status == "answered":
            if citations:
                answer = answer.rsplit(SOURCE_LIST_SEPARATOR, 1)[0]
            predicted_status = _answer_status(answer, item["question_type"])
        elif predicted_status == "error":
            error = answer or "RAG returned an error."
    except Exception as exc:
        answer = ""
        predicted_status = "error"
        citations = []
        error = str(exc) or type(exc).__name__
    return {
        **item,
        "mode": "rag",
        "answer": answer,
        "predicted_status": predicted_status,
        "citations": citations,
        "retrieved_evidence_cves": sorted(set(evidence_cves)),
        "latency_seconds": time.perf_counter() - started,
        "error": error,
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        for row in rows:
            file.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Compare LLM-only with RAG")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=settings.evaluation_questions_file,
    )
    parser.add_argument(
        "--all-cve-ids",
        type=Path,
        help="Optional global NVD catalog; uses the default snapshot if present",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=settings.evaluation_dir,
    )
    parser.add_argument(
        "--provider",
        choices=LLMClient.supported_providers,
        type=lambda value: value.strip().lower(),
        default=settings.llm_provider.strip().lower(),
    )
    parser.add_argument("--top-k", type=int, default=settings.top_k)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--request-interval", type=float, default=None,
        help="Minimum seconds between LLM attempts (default: 6 for Groq, 0 for other providers)",
    )
    parser.add_argument("--max-retries", type=int, default=2, help="Retries per transient LLM HTTP error")
    args = parser.parse_args()
    if args.provider not in LLMClient.supported_providers:
        parser.error(f"Unsupported LLM provider: {args.provider}")
    if args.top_k < 1 or (args.limit is not None and args.limit < 1):
        parser.error("--top-k and --limit must be positive")
    interval = args.request_interval
    if interval is None:
        interval = 6.0 if args.provider == "groq" else 0.0
    if not math.isfinite(interval) or interval < 0 or args.max_retries < 0:
        parser.error("--request-interval and --max-retries must be nonnegative and finite")
    provider_keys = {
        "gemini": ("GEMINI_API_KEY", settings.gemini_api_key),
        "groq": ("GROQ_API_KEY", settings.groq_api_key),
        "openai": ("OPENAI_API_KEY", settings.openai_api_key),
    }
    key = provider_keys.get(args.provider)
    if key and not key[1].strip():
        parser.error(f"Set {key[0]} before running the benchmark")

    dataset_path = args.dataset.resolve()
    evaluation_dir = settings.evaluation_dir.resolve()
    dataset_reference = (
        dataset_path.relative_to(evaluation_dir).as_posix()
        if dataset_path.is_relative_to(evaluation_dir) else dataset_path.name
    )
    questions = load_questions(dataset_path)
    if args.limit is not None:
        questions = questions[:args.limit]
    if not questions:
        parser.error("Evaluation dataset has no questions")

    catalog = get_product_catalog(settings.product_config_file)
    enabled_products = {profile.product_id for profile in catalog.products}
    try:
        processed_manifest = load_processed_manifest(settings)
        products = [row for row in processed_manifest["products"] if row["product_id"] in enabled_products]
        validate_question_runs(questions, {"products": products}, settings.data_source)
        snapshot_paths = {
            kind: [resolve_processed_artifact(settings, row, kind) for row in products]
            for kind in ("structured", "chunks")
        }
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    catalog_path = args.all_cve_ids
    if catalog_path is None and settings.all_cve_ids_file.is_file():
        catalog_path = settings.all_cve_ids_file
    known_cves = load_catalog(catalog_path) if catalog_path is not None else None
    catalog_manifest = load_catalog_manifest(catalog_path) if catalog_path is not None else None
    llm = BenchmarkClient(settings, interval, args.max_retries)
    chatbot = RAGChatbot(settings=settings, llm=llm, retriever=Retriever(settings, snapshot_paths=snapshot_paths))
    started_at = datetime.now(UTC)
    run_dir = args.output_dir / started_at.strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir.mkdir(parents=True, exist_ok=False)
    metadata = {
        "created_at": started_at.isoformat(),
        "provider": args.provider,
        "model": llm.model_name(args.provider),
        "top_k": args.top_k,
        "dataset": dataset_reference,
        "target_questions": len(questions),
        "request_interval_seconds": interval,
        "max_retries": args.max_retries,
        "embedding_provider": settings.embedding_provider,
        "embedding_model": settings.embedding_model,
        "embedding_dimensions": settings.embedding_dimensions,
        "embedding_query_prefix": settings.embedding_query_prefix,
        "qdrant_collection": settings.qdrant_collection,
        "min_score": settings.min_score,
        "default_product_id": settings.default_product_id,
        "corpus_products": sorted(row["product_id"] for row in products),
        "nvd_catalog": catalog_manifest,
        "processed_manifest": processed_manifest,
    }
    write_json(run_dir / "run.json", metadata)
    write_jsonl(run_dir / "questions.jsonl", questions)
    if catalog_manifest is not None:
        write_json(run_dir / "nvd_catalog_manifest.json", catalog_manifest)
    write_json(run_dir / "processed_manifest.json", processed_manifest)
    print(f"Evaluation artifacts: {run_dir}", flush=True)
    return run_benchmark(questions, known_cves, llm, chatbot, run_dir, metadata)


def run_benchmark(
    questions: list[dict[str, Any]],
    known_cves: set[str] | None,
    llm: BenchmarkClient,
    chatbot: RAGChatbot,
    run_dir: Path,
    metadata: dict[str, Any],
) -> int:
    paths = {mode: run_dir / f"{mode}_results.jsonl" for mode in ("llm_only", "rag")}
    for path in paths.values():
        path.touch()
    results: dict[str, list[dict[str, Any]]] = {mode: [] for mode in paths}
    runners = (
        ("llm_only", partial(run_baseline, llm=llm, provider=metadata["provider"])),
        ("rag", partial(run_rag, chatbot=chatbot, provider=metadata["provider"], top_k=metadata["top_k"])),
    )
    interrupted = False
    started = time.monotonic()
    try:
        for index, item in enumerate(questions, 1):
            for mode, runner in runners:
                if llm.stop_reason:
                    break
                print(f"[{index}/{len(questions)}] {item['id']} - {mode}", flush=True)
                waited_before = llm.wait_seconds
                row = runner(item)
                row["latency_seconds"] = max(
                    0.0, row["latency_seconds"] - (llm.wait_seconds - waited_before)
                )
                with paths[mode].open("a", encoding="utf-8", newline="\n") as file:
                    file.write(json.dumps(row, ensure_ascii=False) + "\n")
                results[mode].append(row)
            if llm.stop_reason:
                break
    except KeyboardInterrupt:
        interrupted = True
    finally:
        pairs = list(zip(results["llm_only"], results["rag"]))
        scored = [(b0, b2) for b0, b2 in pairs if b0["error"] is None and b2["error"] is None]
        failures = {
            mode: sum(row["error"] is not None for row in rows)
            for mode, rows in results.items()
        }
        baseline_summary = summarize((b0 for b0, _ in scored), known_cves) if scored else None
        rag_summary = summarize((b2 for _, b2 in scored), known_cves) if scored else None
        completed = len(scored) == len(questions)
        report = {
            **metadata,
            "paired_questions": len(pairs),
            "scored_questions": len(scored),
            "failed_responses": failures,
            "completed": completed,
            "stop_reason": "Interrupted" if interrupted else llm.stop_reason,
            "llm_wait_seconds": llm.wait_seconds,
            "wall_seconds": time.monotonic() - started,
            "baseline": baseline_summary,
            "rag": rag_summary,
            "rag_minus_baseline": compare_summaries(baseline_summary, rag_summary) if scored else None,
        }
        write_json(run_dir / "summary.json", report)
        print(f"Scored {len(scored)}/{len(questions)} pairs. Summary: {run_dir / 'summary.json'}", flush=True)
    if interrupted:
        return 130
    return 0 if completed else 1


if __name__ == "__main__":
    raise SystemExit(main())

