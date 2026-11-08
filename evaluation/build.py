"""Build review-draft evaluation questions from a raw NVD version snapshot."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from itertools import cycle, islice
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from config.products import ProductProfile, get_product_catalog
from config.settings import Settings, get_settings
from data_pipeline.cve_catalog import load_catalog
from data_pipeline.nvd import NVDAdapter, cve_description, cve_url, cve_weaknesses
from data_pipeline.process import load_processed_manifest, resolve_processed_artifact, select_run
from data_pipeline.schemas import VersionRule, VulnerabilityRecord
from data_pipeline.versioning import MatchStatus, VersionMatcher
from evaluation.dataset import EvaluationQuestion, load_famous_review_list


def _load_records(path: Path) -> list[VulnerabilityRecord]:
    with path.open("r", encoding="utf-8") as file:
        return [VulnerabilityRecord.model_validate_json(line) for line in file if line.strip()]


def _sample(rule: VersionRule) -> str | None:
    if rule.exact_versions:
        return rule.exact_versions[0]
    if rule.version_start_including:
        return rule.version_start_including
    if rule.version_end_including:
        return rule.version_end_including
    if rule.branch:
        return f"{rule.branch}.0"
    return None


def _urls(record: VulnerabilityRecord, source_ids: tuple[str, ...]) -> list[str]:
    selected = set(source_ids)
    return sorted({source.url for source in record.sources if source.source_id in selected})


def _row(
    identifier: str,
    product_id: str,
    question_type: str,
    question: str,
    cves: list[str],
    status: str,
    urls: list[str],
    famous: bool,
    conflict: bool,
    notes: str,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "product_id": product_id,
        "question_type": question_type,
        "question": question,
        "expected_cves": cves,
        "expected_status": status,
        "expected_source_urls": urls,
        "famous": famous,
        "has_conflict": conflict,
        "notes": notes,
    }


def build_product_questions(
    product_id: str,
    records: list[VulnerabilityRecord],
    famous_reasons: dict[str, str],
) -> list[dict[str, Any]]:
    matcher = VersionMatcher()
    display_name = records[0].display_name if records else product_id
    candidates: list[tuple[VulnerabilityRecord, str, Any]] = []
    for record in records:
        for rule in record.applicability:
            version = _sample(rule)
            if version:
                decision = matcher.evaluate_record(record, version)
                if decision.status != MatchStatus.UNKNOWN:
                    candidates.append((record, version, decision))
    candidates = list({(record.vulnerability_id, version): (record, version, decision) for record, version, decision in candidates}.values())
    if len(candidates) < 4:
        raise ValueError(f"{product_id} cần ít nhất 4 record có version evidence để sinh benchmark")
    candidates.sort(key=lambda item: (item[0].vulnerability_id not in famous_reasons, not item[2].query_has_conflict, item[0].vulnerability_id))

    rows: list[dict[str, Any]] = []
    checks = list(islice(cycle(candidates), 14))
    for index, (record, version, decision) in enumerate(checks, 1):
        reason = famous_reasons.get(record.vulnerability_id, "")
        rows.append(_row(
            f"{product_id}-check-{index:02d}", product_id, "cve_version_check",
            f"{display_name} phiên bản {version} có bị {record.vulnerability_id} ảnh hưởng không?",
            [record.vulnerability_id], decision.status.value, _urls(record, decision.source_ids),
            bool(reason), decision.query_has_conflict, f"Generated from validated rule. {reason}".strip(),
        ))

    versions = list(dict.fromkeys(version for _, version, _ in candidates))
    if not versions:
        raise ValueError(f"{product_id} không có version để tạo inventory questions")
    for index, version in enumerate(islice(cycle(versions), 14), 1):
        decisions = [(record, matcher.evaluate_record(record, version)) for record in records]
        affected = [(record, decision) for record, decision in decisions if decision.status == MatchStatus.AFFECTED]
        expected = sorted(record.vulnerability_id for record, _ in affected)
        urls = sorted({url for record, decision in affected for url in _urls(record, decision.source_ids)})
        conflict = any(decision.query_has_conflict for _, decision in affected)
        famous = any(cve in famous_reasons for cve in expected)
        rows.append(_row(
            f"{product_id}-inventory-{index:02d}", product_id, "version_inventory",
            f"{display_name} phiên bản {version} có những lỗ hổng nào đã công bố?",
            expected, "affected" if expected else "insufficient_evidence", urls, famous, conflict,
            "Generated by evaluating all structured records at this exact version; requires human gold review.",
        ))

    selected_records = list(islice(cycle([item[0] for item in candidates]), 8))
    for index, record in enumerate(selected_records[:4], 1):
        reason = famous_reasons.get(record.vulnerability_id, "")
        rows.append(_row(
            f"{product_id}-detail-{index:02d}", product_id, "vulnerability_detail",
            f"Hãy mô tả {record.vulnerability_id} trên {display_name} và nêu nguồn.",
            [record.vulnerability_id], "affected", sorted({source.url for source in record.sources}),
            bool(reason), record.has_source_conflict, f"Detail question from structured record. {reason}".strip(),
        ))
    for index, record in enumerate(selected_records[4:8], 1):
        reason = famous_reasons.get(record.vulnerability_id, "")
        weakness = record.weaknesses[0] if record.weaknesses else "mô tả kỹ thuật"
        rows.append(_row(
            f"{product_id}-semantic-{index:02d}", product_id, "semantic",
            f"Lỗ hổng nào của {display_name} liên quan đến {weakness}?",
            [record.vulnerability_id], "affected", sorted({source.url for source in record.sources}),
            bool(reason), record.has_source_conflict, f"Semantic candidate derived from source metadata. {reason}".strip(),
        ))
    return rows


def _inject_negative_cases(
    rows: list[dict[str, Any]],
    product_id: str,
    records: list[VulnerabilityRecord],
    other_records: list[VulnerabilityRecord],
    all_cve_ids: set[str],
) -> None:
    """Reserve three check slots for unknown, nonexistent, and wrong-product cases."""

    display_name = records[0].display_name
    matcher = VersionMatcher()
    unknown_record = next(
        (record for record in records if matcher.evaluate_record(record, "999.999.999").status == MatchStatus.UNKNOWN),
        None,
    )
    wrong_product = next(
        (record for record in other_records if all(item.vulnerability_id != record.vulnerability_id for item in records)),
        None,
    )
    if unknown_record is None or wrong_product is None:
        raise ValueError(f"Không đủ corpus để tạo negative cases cho {product_id}")
    serial = 99999
    while f"CVE-2099-{serial}" in all_cve_ids:
        serial += 1
    nonexistent = f"CVE-2099-{serial}"
    replacements = [
        _row(
            f"{product_id}-check-12", product_id, "cve_version_check",
            f"{display_name} phiên bản 999.999.999 có bị {unknown_record.vulnerability_id} ảnh hưởng không?",
            [], "insufficient_evidence", [], False, False,
            "Existing CVE with a version outside all parseable source coverage.",
        ),
        _row(
            f"{product_id}-check-13", product_id, "cve_version_check",
            f"{display_name} phiên bản 7.0.0 có bị {nonexistent} ảnh hưởng không?",
            [], "insufficient_evidence", [], False, False,
            "Identifier verified absent from the refreshed all-NVD catalog at generation time.",
        ),
        _row(
            f"{product_id}-check-14", product_id, "cve_version_check",
            f"{display_name} phiên bản 7.0.0 có bị {wrong_product.vulnerability_id} ảnh hưởng không?",
            [], "insufficient_evidence", [], False, False,
            f"Real CVE from the other product ({wrong_product.product_id}), absent from this product corpus.",
        ),
    ]
    by_id = {row["id"]: index for index, row in enumerate(rows)}
    for replacement in replacements:
        rows[by_id[replacement["id"]]] = replacement


def _build_content_questions(
    profile: ProductProfile,
    records: dict[str, dict[str, Any]],
    famous: dict[str, str],
    details_per_product: int | None,
    semantic_per_product: int | None,
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    weakness_groups: defaultdict[str, list[str]] = defaultdict(list)
    for cve, record in sorted(records.items()):
        description = cve_description(record)
        if description:
            detail = _row(
                f"{profile.product_id}-detail-{cve.lower()}", profile.product_id, "vulnerability_detail",
                f"NVD mô tả {cve} trên {profile.display_name} như thế nào? Hãy nêu nguồn.",
                [cve], "affected", [cve_url(cve)], cve in famous, False,
                "Review the summary against the reference answer from the original CVE record.",
            )
            detail["reference_answer"] = description
            details.append(detail)
        for weakness in cve_weaknesses(record):
            if re.fullmatch(r"CWE-[0-9]+", weakness):
                weakness_groups[weakness].append(cve)

    semantic = [
        _row(
            f"{profile.product_id}-semantic-{weakness.lower()}", profile.product_id, "semantic",
            f"Trong dữ liệu NVD đã thu thập cho {profile.display_name}, những CVE nào thuộc nhóm điểm yếu {weakness}?",
            cves, "affected", [cve_url(cve) for cve in cves],
            any(cve in famous for cve in cves), False,
            "Gold includes every CVE with this CWE in the product snapshot. Review before benchmarking.",
        )
        for weakness, cves in sorted(weakness_groups.items())
    ]
    return details[:details_per_product] + semantic[:semantic_per_product]


def build_raw_questions(
    adapter: NVDAdapter,
    run_dir: Path,
    famous: dict[str, str],
    checks_per_version: int | None = None,
    *,
    details_per_product: int | None = None,
    semantic_per_product: int | None = None,
) -> list[dict[str, Any]]:
    profile = adapter.profile
    snapshots = []
    raw_records: dict[str, dict[str, Any]] = {}
    for target, records in adapter.read_version_queries(run_dir, require_complete=True):
        snapshots.append((target, sorted(records)))
        for cve, (_, raw) in records.items():
            raw_records.setdefault(cve, raw)
    rows: list[dict[str, Any]] = []
    for index, (target, cves) in enumerate(snapshots):
        identifier = f"{profile.product_id}-{target.version}"
        subject = f"{profile.display_name} phiên bản {target.version}"
        notes = f"NVD isVulnerable query for {target.cpe}. Review against original CVE records."
        urls = [cve_url(cve) for cve in cves]
        rows.append(_row(
            f"{identifier}-inventory", profile.product_id, "version_inventory",
            f"{subject} có những CVE nào được NVD ghi nhận?",
            cves, "affected" if cves else "insufficient_evidence", urls,
            any(cve in famous for cve in cves), False, notes,
        ))
        for cve, url in zip(cves[:checks_per_version], urls[:checks_per_version], strict=True):
            rows.append(_row(
                f"{identifier}-{cve.lower()}", profile.product_id, "cve_version_check",
                f"{subject} có bị {cve} ảnh hưởng theo NVD không?",
                [cve], "affected", [url], cve in famous, False, notes,
            ))
        known = set(cves)
        neighbors = snapshots[max(0, index - 1):index] + snapshots[index + 1:index + 2]
        for neighbor, neighbor_cves in neighbors:
            missing = next((cve for cve in neighbor_cves if cve not in known), None)
            if missing:
                rows.append(_row(
                    f"{identifier}-{missing.lower()}", profile.product_id, "cve_version_check",
                    f"{subject} có bị {missing} ảnh hưởng theo NVD không?",
                    [], "insufficient_evidence", [], missing in famous, False,
                    f"{notes} CVE present for {neighbor.version}; absent from this complete query.",
                ))
                break
    rows.extend(_build_content_questions(profile, raw_records, famous, details_per_product, semantic_per_product))
    return [{**row, "raw_run_id": run_dir.name} for row in rows]


def _build_legacy_questions(
    profiles: tuple[ProductProfile, ...], settings: Settings, famous: dict[str, str]
) -> list[dict[str, Any]]:
    all_cve_ids = load_catalog(settings.all_cve_ids_file)
    processed_manifest = load_processed_manifest(settings)
    manifests = {item["product_id"]: item for item in processed_manifest["products"]}
    for profile in profiles:
        if profile.product_id not in manifests:
            raise ValueError(f"Product {profile.product_id} is missing from the processed corpus")
    records_by_product = {
        profile.product_id: _load_records(resolve_processed_artifact(settings, manifests[profile.product_id], "structured"))
        for profile in profiles
    }
    rows: list[dict[str, Any]] = []
    for profile in profiles:
        product_id = profile.product_id
        if profile.vendor_source == "mikrotik_curated":
            curated = manifests.get(product_id, {}).get("curated") or {}
            if not curated.get("milestone_met"):
                raise ValueError(f"{product_id} chưa đạt curation milestone")
        product_rows = build_product_questions(product_id, records_by_product[product_id], famous)
        other_records = [
            record for other_id, records in records_by_product.items()
            if other_id != product_id for record in records
        ]
        if other_records:
            _inject_negative_cases(product_rows, product_id, records_by_product[product_id], other_records, all_cve_ids)
        run_id = manifests[product_id]["input_runs"].get(settings.data_source)
        for row in product_rows:
            row["raw_run_id"] = run_id
        rows.extend(product_rows)
    conflict_cves = {
        record.vulnerability_id
        for records in records_by_product.values()
        for record in records
        if record.has_source_conflict
    }
    represented_conflicts = {
        cve for row in rows if row["has_conflict"] for cve in row["expected_cves"]
    }
    missing_conflicts = conflict_cves - represented_conflicts
    if missing_conflicts:
        raise ValueError(f"Benchmark chưa bao phủ toàn bộ conflict CVE: {sorted(missing_conflicts)}")
    print(f"Conflict coverage: {len(represented_conflicts)}/{len(conflict_cves)} real corpus CVEs")
    return rows


def main() -> int:
    settings = get_settings()
    catalog = get_product_catalog(settings.product_config_file)
    parser = argparse.ArgumentParser(description="Build evaluation draft from completed NVD crawls")
    parser.add_argument("--product", choices=[item.product_id for item in catalog.products])
    parser.add_argument("--run", default="latest", help="NVD run ID (with --product), or latest per product")
    parser.add_argument("--checks-per-version", type=int, help="Cap positive CVE/version checks per version")
    parser.add_argument("--details-per-product", type=int, help="Cap CVE detail questions per product")
    parser.add_argument("--semantic-per-product", type=int, help="Cap CWE lookup questions per product")
    parser.add_argument("--output", type=Path, default=settings.evaluation_questions_file)
    parser.add_argument("--famous-list", type=Path, default=Path(__file__).with_name("famous_cves.json"))
    args = parser.parse_args()
    if args.run != "latest" and not args.product:
        parser.error("--run cần --product khi chọn một run ID")
    if args.checks_per_version is not None and args.checks_per_version < 1:
        parser.error("--checks-per-version phải lớn hơn 0")
    for option, count in (
        ("--details-per-product", args.details_per_product),
        ("--semantic-per-product", args.semantic_per_product),
    ):
        if count is not None and count < 0:
            parser.error(f"{option} phải lớn hơn hoặc bằng 0")

    profiles = (catalog.by_id(args.product),) if args.product else catalog.products
    famous = load_famous_review_list(args.famous_list)
    rows: list[dict[str, Any]] = []
    versioned = [profile for profile in profiles if profile.versions]
    if versioned:
        if len(versioned) != len(profiles):
            parser.error("Hãy dùng --product nếu catalog trộn crawl theo product và theo version")
        for profile in versioned:
            run_dir = select_run(settings.raw_product_source_dir(profile.product_id, "nvd"), args.run)
            rows.extend(build_raw_questions(
                NVDAdapter(settings, profile), run_dir, famous, args.checks_per_version,
                details_per_product=args.details_per_product, semantic_per_product=args.semantic_per_product,
            ))
    else:
        counts = (args.checks_per_version, args.details_per_product, args.semantic_per_product)
        if args.run != "latest" or any(count is not None for count in counts):
            parser.error("--run và các giới hạn số câu yêu cầu profile có versions")
        rows = _build_legacy_questions(profiles, settings, famous)

    questions = [EvaluationQuestion.model_validate(row) for row in rows]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with NamedTemporaryFile(dir=args.output.parent, mode="w", encoding="utf-8", newline="\n", delete=False) as file:
            temporary_path = Path(file.name)
            for question in questions:
                file.write(question.model_dump_json(exclude_none=True) + "\n")
        temporary_path.replace(args.output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    print(f"Wrote {len(rows)} review-draft questions to {args.output}")
    for question_type, count in sorted(Counter(question.question_type for question in questions).items()):
        print(f"  {question_type}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
