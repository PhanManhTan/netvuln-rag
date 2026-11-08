"""Generic command for collecting raw data through the configured adapter."""

from __future__ import annotations

import argparse
from pathlib import Path

from config.products import ProductProfile, get_product_catalog
from config.settings import Settings, get_settings
from data_pipeline.contracts import CrawlOptions
from data_pipeline.fortiguard import FortiGuardAdapter
from data_pipeline.registry import get_source_adapter


def crawl_data(
    profile: ProductProfile,
    output_dir: Path | None = None,
    limit: int | None = None,
    settings: Settings | None = None,
) -> Path:
    selected = settings or get_settings()
    options = CrawlOptions(output_dir=output_dir, limit=limit)
    return get_source_adapter(selected, profile).crawl(options)


def crawl_product(
    profile: ProductProfile,
    output_dir: Path | None = None,
    limit: int | None = None,
    settings: Settings | None = None,
) -> dict[str, Path]:
    """Collect every configured source for one product."""

    selected = settings or get_settings()
    nvd_run = crawl_data(profile, output_dir, limit, selected)
    runs = {selected.data_source: nvd_run}
    if profile.vendor_source == "fortiguard":
        runs["fortiguard"] = FortiGuardAdapter(selected, profile).crawl(
            nvd_run, CrawlOptions(limit=limit)
        )
    return runs


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("phải là số nguyên lớn hơn 0")
    return parsed


def main() -> int:
    settings = get_settings()
    catalog = get_product_catalog(settings.product_config_file)
    parser = argparse.ArgumentParser(description="Collect raw vulnerability data")
    parser.add_argument("--output", type=Path)
    products = parser.add_mutually_exclusive_group()
    products.add_argument("--product", choices=[item.product_id for item in catalog.products])
    products.add_argument("--all-products", action="store_true")
    parser.add_argument(
        "--limit",
        type=_positive_int,
        help="Maximum records per NVD query (per configured version, otherwise per product)",
    )
    args = parser.parse_args()
    selected = catalog.products if args.all_products else (
        catalog.by_id(args.product or settings.default_product_id),
    )
    if args.output and len(selected) > 1:
        parser.error("--output chỉ dùng được khi crawl một --product")
    for profile in selected:
        runs = crawl_product(profile, args.output, args.limit, settings)
        for source, output in runs.items():
            print(f"{profile.product_id}/{source}: raw data saved to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
