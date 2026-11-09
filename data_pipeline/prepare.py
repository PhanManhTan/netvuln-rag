"""Run the data pipeline and optionally benchmark the resulting corpus."""

from __future__ import annotations

import argparse
import subprocess
import sys

from config.products import get_product_catalog
from config.settings import get_settings
from data_pipeline.crawl import crawl_product
from data_pipeline.index import build_index, check_new_collection
from data_pipeline.process import process_data


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("phải lớn hơn 0")
    return parsed


def main() -> int:
    settings = get_settings()
    catalog = get_product_catalog(settings.product_config_file)
    parser = argparse.ArgumentParser(description="Prepare all RAG data")
    products = parser.add_mutually_exclusive_group()
    products.add_argument("--product", choices=[item.product_id for item in catalog.products])
    products.add_argument("--all-products", action="store_true")
    parser.add_argument("--limit", type=_positive_int, help="Maximum records per NVD query")
    parser.add_argument("--run", default="latest", help="Run ID or latest (with --skip-crawl)")
    parser.add_argument("--skip-crawl", action="store_true")
    index = parser.add_mutually_exclusive_group()
    index.add_argument("--skip-index", action="store_true")
    index.add_argument("--recreate-index", action="store_true", help="Replace the existing Qdrant collection")
    parser.add_argument("--evaluate", action="store_true", help="Build questions and compare raw, BM25, and RAG after indexing")
    parser.add_argument("--eval-limit", type=_positive_int, help="Maximum questions to benchmark with --evaluate")
    args = parser.parse_args()
    if args.run != "latest" and not args.skip_crawl:
        parser.error("--run chỉ dùng được với --skip-crawl")
    if args.eval_limit is not None and not args.evaluate:
        parser.error("--eval-limit requires --evaluate")
    if args.evaluate and args.skip_index:
        parser.error("--evaluate requires indexing in this run")
    if args.evaluate and args.limit is not None and not args.skip_crawl:
        parser.error("--evaluate requires a complete crawl. Use --eval-limit to shorten the benchmark.")
    if not args.skip_index and not args.recreate_index:
        check_new_collection(settings)

    profiles = catalog.products if args.all_products else (catalog.by_id(args.product or settings.default_product_id),)
    nvd_runs = {}
    if not args.skip_crawl:
        for profile in profiles:
            print(f"[crawl] {profile.product_id}")
            runs = crawl_product(profile, limit=args.limit, settings=settings)
            nvd_runs[profile.product_id] = runs[settings.data_source].name
    else:
        print("[crawl] skipped")

    print("[process] validating structured records and building chunks")
    results = process_data([profile.product_id for profile in profiles], args.run, settings, nvd_runs=nvd_runs)
    for result in results:
        print(f"  {result['product_id']}: {result['record_count']} records / {result['chunk_count']} chunks")

    if not args.skip_index:
        print("[index] writing the configured collection")
        count = build_index(
            settings.chunks_data_dir, settings, recreate=args.recreate_index,
            require_new_collection=not args.recreate_index,
        )
        print(f"Indexed {count} chunks into {settings.qdrant_collection}")
    else:
        print("[index] skipped")

    if not args.evaluate:
        return 0

    print("[evaluation] building questions from the published snapshot", flush=True)
    build = subprocess.run([sys.executable, "-m", "evaluation.build", "--from-processed"], check=False)
    if build.returncode:
        return build.returncode
    command = [sys.executable, "-m", "evaluation.run", "--modes", "llm_raw", "llm_bm25", "rag"]
    if args.eval_limit is not None:
        command.extend(["--limit", str(args.eval_limit)])
    print("[evaluation] comparing raw, BM25, and RAG", flush=True)
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
