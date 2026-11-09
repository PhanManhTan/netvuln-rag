"""Run the complete NetVuln RAG pipeline end-to-end on Cloud or local:
1. Crawl NVD API for all products and versions
2. Process and build text chunks
3. Index vectors into Qdrant collection
4. Build review/gold evaluation dataset (~120 questions)
5. Run benchmark comparing B0 (LLM only), B1 (LLM + Document), and B2 (RAG)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time


def run_step(step_name: str, command: list[str]) -> None:
    print(f"\n{'='*70}\n[STEP] {step_name}\nCommand: {' '.join(command)}\n{'='*70}", flush=True)
    started = time.perf_counter()
    result = subprocess.run(command, check=False)
    elapsed = time.perf_counter() - started
    if result.returncode != 0:
        print(f"\n[ERROR] Step '{step_name}' failed with exit code {result.returncode} ({elapsed:.1f}s)", flush=True)
        sys.exit(result.returncode)
    print(f"[SUCCESS] Step '{step_name}' finished in {elapsed:.1f}s", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run complete NetVuln RAG pipeline end-to-end")
    parser.add_argument("--provider", help="LLM provider (groq, gemini, ollama, openai)")
    parser.add_argument("--eval-limit", type=int, help="Limit number of questions to evaluate (for quick test)")
    parser.add_argument("--skip-crawl", action="store_true", help="Skip crawling if raw data is already fetched")
    parser.add_argument("--request-interval", type=float, help="Seconds between LLM calls (e.g. 1.0 or 0.0)")
    parser.add_argument("--context-max-chars", type=int, help="Max characters for context evidence (default from .env or 6000)")
    parser.add_argument("--max-retries", type=int, help="Retries on transient HTTP 429/5xx errors (default: 2)")
    args = parser.parse_args()

    python_bin = sys.executable

    # 1. Crawl + Process + Index Qdrant
    prep_cmd = [python_bin, "-m", "data_pipeline.prepare", "--all-products", "--recreate-index"]
    if args.skip_crawl:
        prep_cmd.append("--skip-crawl")
    run_step("1. Crawl NVD & Process & Index to Qdrant", prep_cmd)

    # 2. Build 120 Evaluation Questions
    build_cmd = [
        python_bin, "-m", "evaluation.build",
        "--from-processed",
        "--checks-per-version", "5",
        "--details-per-product", "4",
        "--semantic-per-product", "4",
    ]
    run_step("2. Build Ground-Truth Dataset (~120 questions)", build_cmd)

    # 3. Run Benchmark (B0, B1, B2)
    eval_cmd = [python_bin, "-m", "evaluation.run", "--with-documents"]
    if args.provider:
        eval_cmd.extend(["--provider", args.provider])
    if args.eval_limit:
        eval_cmd.extend(["--limit", str(args.eval_limit)])
    if args.request_interval is not None:
        eval_cmd.extend(["--request-interval", str(args.request_interval)])
    if args.context_max_chars is not None:
        eval_cmd.extend(["--context-max-chars", str(args.context_max_chars)])
    if args.max_retries is not None:
        eval_cmd.extend(["--max-retries", str(args.max_retries)])

    run_step("3. Run Benchmark (B0: LLM, B1: Doc, B2: RAG)", eval_cmd)

    print(f"\n{'='*70}\n[ALL DONE] Full pipeline completed successfully!\nCheck artifacts/evaluation/ for summary.json\n{'='*70}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

