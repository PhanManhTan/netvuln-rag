"""Run the same questions with LLM-only and RAG, then compare metrics."""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config.settings import PROJECT_ROOT, get_settings
from generation.chatbot import RAGChatbot, load_prompts
from generation.client import LLMClient
from tests.evaluation.metrics import compare_summaries, infer_status, summarize


BASELINE_SYSTEM_PROMPT = load_prompts()["baseline_system_prompt"]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            required = {"id", "question", "expected_cves", "expected_status"}
            missing = required - row.keys()
            if missing:
                raise ValueError(f"{path}:{line_number} thiếu field: {sorted(missing)}")
            rows.append(row)
    return rows


def load_known_cves(path: Path) -> set[str]:
    if not path.exists():
        raise FileNotFoundError(
            f"Không tìm thấy {path}. Hãy chạy crawl và process data trước evaluation."
        )
    known_cves: set[str] = set()
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            row = json.loads(line)
            identifier = row.get("vulnerability_id") or row.get("cve_id")
            if identifier:
                known_cves.add(str(identifier).upper())
    return known_cves


def _rag_predicted_status(response: dict[str, Any]) -> str:
    if response["status"] == "error":
        return "error"
    if response["status"] == "insufficient_evidence":
        return "insufficient_evidence"
    if response["matches"]:
        status = response["matches"][0]["status"]
        return status.value if hasattr(status, "value") else str(status)
    return infer_status(response["answer"])


def run_baseline(
    item: dict[str, Any], llm: LLMClient, provider: str
) -> dict[str, Any]:
    started = time.perf_counter()
    error = None
    try:
        answer = llm.generate(BASELINE_SYSTEM_PROMPT, item["question"], provider)
    except Exception as exc:
        answer = ""
        error = str(exc)
    return {
        **item,
        "mode": "llm_only",
        "answer": answer,
        "predicted_status": "error" if error else infer_status(answer),
        "citations": [],
        "latency_seconds": time.perf_counter() - started,
        "error": error,
    }


def run_rag(
    item: dict[str, Any], chatbot: RAGChatbot, provider: str, top_k: int
) -> dict[str, Any]:
    started = time.perf_counter()
    error = None
    try:
        response = chatbot.ask(item["question"], provider=provider, top_k=top_k)
        answer = response["answer"]
        predicted_status = _rag_predicted_status(response)
        citations = response["citations"]
    except Exception as exc:
        answer = ""
        predicted_status = "error"
        citations = []
        error = str(exc)
    return {
        **item,
        "mode": "rag",
        "answer": answer,
        "predicted_status": predicted_status,
        "citations": citations,
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
        default=PROJECT_ROOT / "tests" / "evaluation" / "questions.jsonl",
    )
    parser.add_argument(
        "--known-cves",
        type=Path,
        default=settings.processed_file,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "artifacts" / "evaluation",
    )
    parser.add_argument(
        "--provider",
        default=settings.llm_provider,
    )
    parser.add_argument("--top-k", type=int, default=settings.top_k)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    questions = load_jsonl(args.dataset)
    if args.limit is not None:
        questions = questions[: max(0, args.limit)]
    if not questions:
        raise ValueError("Evaluation dataset không có câu hỏi.")

    known_cves = load_known_cves(args.known_cves)
    llm = LLMClient(settings)
    chatbot = RAGChatbot(settings=settings, llm=llm)
    baseline_results: list[dict[str, Any]] = []
    rag_results: list[dict[str, Any]] = []

    for index, item in enumerate(questions, 1):
        print(f"[{index}/{len(questions)}] {item['id']} - LLM only")
        baseline_results.append(run_baseline(item, llm, args.provider))
        print(f"[{index}/{len(questions)}] {item['id']} - RAG")
        rag_results.append(run_rag(item, chatbot, args.provider, args.top_k))

    baseline_summary = summarize(baseline_results, known_cves)
    rag_summary = summarize(rag_results, known_cves)
    report = {
        "created_at": datetime.now(UTC).isoformat(),
        "provider": args.provider,
        "model": llm.model_name(args.provider),
        "top_k": args.top_k,
        "dataset": str(args.dataset),
        "baseline": baseline_summary,
        "rag": rag_summary,
        "rag_minus_baseline": compare_summaries(baseline_summary, rag_summary),
    }

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output_dir / run_id
    write_jsonl(run_dir / "llm_only_results.jsonl", baseline_results)
    write_jsonl(run_dir / "rag_results.jsonl", rag_results)
    write_json(run_dir / "summary.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Evaluation artifacts: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

