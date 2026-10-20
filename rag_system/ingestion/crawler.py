"""Generic command for collecting raw data through the configured adapter."""

from __future__ import annotations

import argparse
from pathlib import Path

from rag_system.config import get_settings
from rag_system.ingestion.adapters import get_source_adapter


def crawl_data(output_dir: Path | None = None) -> Path:
    settings = get_settings()
    return get_source_adapter(settings).crawl(output_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect raw vulnerability data")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = crawl_data(args.output)
    print(f"Raw data saved to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
