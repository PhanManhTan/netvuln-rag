"""Generic command for normalizing data through the configured adapter."""

from __future__ import annotations

import argparse
from pathlib import Path

from config.settings import Settings, get_settings
from ingestion.registry import get_source_adapter


def process_data(
    input_path: Path | None = None,
    output_path: Path | None = None,
    settings: Settings | None = None,
) -> int:
    selected = settings or get_settings()
    source = input_path or selected.raw_source_dir
    output = output_path or selected.processed_file
    return get_source_adapter(selected).process(source, output)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Normalize vulnerability data")
    parser.add_argument("--input", type=Path, default=settings.raw_source_dir)
    parser.add_argument("--output", type=Path, default=settings.processed_file)
    args = parser.parse_args()
    count = process_data(args.input, args.output, settings)
    print(f"Normalized {count} records to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
