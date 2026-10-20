"""Run the configured crawl -> process -> index workflow."""

from __future__ import annotations

import argparse

from rag_system.config import get_settings
from rag_system.indexer import build_index
from rag_system.ingestion.adapters import get_source_adapter


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Prepare all RAG data")
    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Reuse existing raw source data",
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete and rebuild the vector collection",
    )
    args = parser.parse_args()
    adapter = get_source_adapter(settings)

    if not args.skip_crawl:
        print(f"[1/3] Crawling source: {settings.data_source}")
        adapter.crawl()
    else:
        print("[1/3] Skipping data crawl")

    print("[2/3] Normalizing vulnerability records")
    record_count = adapter.process(settings.raw_source_dir, settings.processed_file)
    print(f"Processed {record_count} records")

    print("[3/3] Building vector index")
    chunk_count = build_index(
        settings.processed_file,
        settings,
        recreate=args.recreate,
    )
    print(f"Indexed {chunk_count} chunks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
