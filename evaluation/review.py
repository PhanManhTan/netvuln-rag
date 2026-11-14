"""Offline review packets, reviewed dataset exports, and non-destructive rescoring."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from data_pipeline.schemas import CVE_PATTERN
from evaluation.dataset import EvaluationQuestion, dataset_quality_report, load_questions
from evaluation.metrics import SCORER_VERSION, compare_summaries, extract_cves, infer_status, summarize
from evaluation.performance import summarize_performance, write_metrics_csv


SCHEMA_VERSION = "1.0"
MODE_KEYS = {"llm_only": "baseline", "llm_document": "document", "llm_raw": "raw", "llm_bm25": "bm25", "rag": "rag"}
VERDICTS = {"affected", "not_affected", "insufficient_evidence", "answered"}
RATINGS = ("factual_correctness", "faithfulness", "citation_support")
GOLD_REVIEW_FIELDS = {"review_status", "reviewed_by", "reviewed_at", "label_basis", "label_evidence", "expected_cves", "expected_status", "expected_source_urls", "reference_answer", "reference_claims", "notes", "question"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_hash(row: dict[str, Any]) -> str:
    body = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _read_rows(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"Rows must be JSON objects: {path}")
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError(f"Duplicate question IDs: {path}")
    return rows


def _write_new_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write("\n")


def _run_files(run_dir: Path) -> dict[str, str]:
    metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    modes = metadata.get("modes")
    if not isinstance(modes, list) or not modes or any(not isinstance(mode, str) for mode in modes) or len(modes) != len(set(modes)):
        raise ValueError("Run metadata requires distinct benchmark modes")
    files = [run_dir / "run.json", run_dir / "questions.jsonl"]
    for mode in modes:
        if mode not in MODE_KEYS:
            raise ValueError(f"Unsupported run mode: {mode}")
        files.append(run_dir / f"{mode}_results.jsonl")
    for name in ("processed_manifest.json", "nvd_catalog_manifest.json"):
        if (run_dir / name).exists():
            files.append(run_dir / name)
    return {path.name: _sha256(path) for path in files}


def _answer_packet_row(row: dict[str, Any], mode: str) -> dict[str, Any]:
    return {
        "id": row["id"], "mode": mode, "record_sha256": _record_hash(row),
        "answer": row.get("answer", ""), "predicted_status": row.get("predicted_status"),
        "expected_cves": row.get("expected_cves", []), "expected_status": row.get("expected_status"),
        "reference_answer": row.get("reference_answer"), "reference_claims": row.get("reference_claims", []),
        "citations": row.get("citations", []), "expected_source_urls": row.get("expected_source_urls", []),
        "raw_run_id": row.get("raw_run_id"),
    }


def review_quality_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Add review-worklist diagnostics without requiring a particular distribution."""
    text_counts = Counter(" ".join(row["question"].casefold().split()) for row in rows)
    gaps: dict[str, list[str]] = {}
    for row in rows:
        missing = []
        if not row.get("raw_run_id"):
            missing.append("raw_run_id")
        if not row.get("label_evidence"):
            missing.append("label_evidence")
        if row.get("expected_cves") and not row.get("expected_source_urls"):
            missing.append("expected_source_urls")
        if row.get("question_type") == "vulnerability_detail" and not (row.get("reference_answer") or row.get("reference_claims")):
            missing.append("reference_answer_or_claims")
        if missing:
            gaps[row["id"]] = missing
    return {
        **dataset_quality_report(rows),
        "conflict_questions": sum(bool(row.get("has_conflict")) for row in rows),
        "duplicate_question_texts": sorted(text for text, count in text_counts.items() if count > 1),
        "provenance_gaps": gaps,
    }


def export_packet(dataset: Path, output: Path, run_dir: Path | None = None) -> dict[str, Any]:
    """Create a draft packet. Only nested review objects are editable annotations."""
    rows = _read_rows(dataset)
    validated = load_questions(dataset)
    question_ids = {row["id"] for row in rows}
    quality = review_quality_report(validated)
    packet: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "dataset_sha256": _sha256(dataset),
        "source_files": _run_files(run_dir) if run_dir else {},
        "quality": quality,
        "questions": [{"id": row["id"], "question_sha256": _record_hash(row), "question": row, "review": None} for row in rows],
        "answers": [],
    }
    if run_dir:
        if _sha256(run_dir / "questions.jsonl") != packet["dataset_sha256"]:
            raise ValueError("The dataset must match the run's saved questions.jsonl exactly")
        metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        for mode in metadata["modes"]:
            for row in _read_rows(run_dir / f"{mode}_results.jsonl"):
                if row["id"] not in question_ids:
                    raise ValueError(f"Result has unknown question ID: {row['id']}")
                packet["answers"].append({**_answer_packet_row(row, mode), "review": None})
    _write_new_json(output, packet)
    return packet


def _load_packet(packet_path: Path, dataset: Path) -> dict[str, Any]:
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    if packet.get("schema_version") != SCHEMA_VERSION or packet.get("dataset_sha256") != _sha256(dataset):
        raise ValueError("Review packet does not match the source dataset")
    originals = {row["id"]: row for row in _read_rows(dataset)}
    seen: set[str] = set()
    for item in packet["questions"]:
        identifier = item["id"]
        if identifier in seen or identifier not in originals or item["question_sha256"] != _record_hash(originals[identifier]):
            raise ValueError(f"Question pin mismatch or duplicate: {identifier}")
        if item.get("question") != originals[identifier]:
            raise ValueError(f"Question display changed; edit only the review object: {identifier}")
        seen.add(identifier)
    if seen != set(originals):
        raise ValueError("Review packet is missing source questions")
    return packet


def freeze_dataset(dataset: Path, packet_path: Path, output: Path) -> dict[str, Any]:
    """Write only explicitly approved questions; never mark draft labels approved."""
    packet = _load_packet(packet_path, dataset)
    approved = []
    omitted = []
    for item in packet["questions"]:
        row = _approved_gold(item)
        if row is None:
            omitted.append(item["id"])
            continue
        approved.append(row)
    if not approved:
        raise ValueError("No approved questions; review source evidence before freezing a dataset")
    # Validate before creating any output, including the sidecar path.
    sidecar = output.with_suffix(output.suffix + ".review.json")
    if output.exists() or sidecar.exists():
        raise FileExistsError("Reviewed dataset output and sidecar must be new files")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as file:
        for row in approved:
            file.write(json.dumps(row, ensure_ascii=False) + "\n")
    report = {"source_dataset_sha256": packet["dataset_sha256"], "review_packet_sha256": _sha256(packet_path), "dataset_sha256": _sha256(output), "approved_questions": len(approved), "omitted_question_ids": omitted, "quality": dataset_quality_report(approved)}
    _write_new_json(sidecar, report)
    return report


def _approved_gold(item: dict[str, Any]) -> dict[str, Any] | None:
    review = item.get("review")
    if review is not None and not isinstance(review, dict):
        raise ValueError("Question review must be a JSON object or null")
    if not review or review.get("review_status") != "approved":
        return None
    if set(review) - GOLD_REVIEW_FIELDS:
        raise ValueError(f"Unsupported gold review fields: {sorted(set(review) - GOLD_REVIEW_FIELDS)}")
    return EvaluationQuestion.model_validate({**item["question"], **review}).model_dump(mode="json")


def _review_provenance(review: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(review.get("reviewed_by"), str) or not review["reviewed_by"].strip():
        raise ValueError("Answer review requires reviewed_by")
    try:
        stamp = datetime.fromisoformat(review["reviewed_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ValueError("Answer review requires an ISO reviewed_at timestamp") from exc
    if stamp.tzinfo is None:
        raise ValueError("Answer review reviewed_at must include a timezone")
    if not isinstance(review.get("notes"), str) or not review["notes"].strip():
        raise ValueError("Answer review requires notes explaining the evidence")
    urls = review.get("evidence_sources")
    if not isinstance(urls, list) or not urls or any(not isinstance(url, str) or urlparse(url).scheme not in {"http", "https"} or not urlparse(url).netloc for url in urls):
        raise ValueError("Answer review requires HTTP(S) evidence_sources")
    return {key: review[key] for key in ("reviewed_by", "reviewed_at", "notes", "evidence_sources")}


def _apply_answer_review(row: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(review, dict):
        raise ValueError("Answer review must be a JSON object or null")
    allowed = {"reviewed_by", "reviewed_at", "notes", "evidence_sources", "predicted_status", "asserted_cves", *RATINGS}
    if set(review) - allowed:
        raise ValueError(f"Unsupported answer review fields: {sorted(set(review) - allowed)}")
    provenance = _review_provenance(review)
    for field in RATINGS:
        if review.get(field) is not None and type(review[field]) is not bool:
            raise ValueError(f"{field} must be true, false, or null")
    updated = dict(row)
    updated["manual_review"] = {**provenance, **{field: review.get(field) for field in RATINGS}}
    correction_fields = {field: review[field] for field in ("predicted_status", "asserted_cves") if field in review}
    if "predicted_status" in correction_fields and correction_fields["predicted_status"] not in VERDICTS:
        raise ValueError("Invalid reviewed verdict")
    if "asserted_cves" in correction_fields:
        cves = correction_fields["asserted_cves"]
        if not isinstance(cves, list) or any(not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve) or cve.upper() != cve for cve in cves):
            raise ValueError("Reviewed asserted_cves must be a list of canonical CVE IDs")
        # A parser correction cannot invent identifiers absent from the saved answer.
        if set(cves) - extract_cves(str(row.get("answer", ""))):
            raise ValueError("Reviewed assertions must occur in the saved answer")
    if correction_fields:
        if row.get("error") is not None or row.get("output_error") or row.get("predicted_status") == "error":
            raise ValueError("A review cannot turn a failed request into a successful answer")
        updated.update(correction_fields)
        if "predicted_status" in correction_fields:
            updated["verdict"] = correction_fields["predicted_status"]
        updated["status_source"] = "manual_review"
        updated["review_correction"] = {**provenance, "original_prediction": {key: row.get(key) for key in ("predicted_status", "verdict", "asserted_cves", "status_source")}}
    return updated


def rescore_run(run_dir: Path, output_dir: Path, packet_path: Path | None = None, all_cve_ids: Path | None = None) -> dict[str, Any]:
    """Score saved outputs with optional human annotations. Makes no model calls."""
    metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    load_questions(run_dir / "questions.jsonl")
    question_rows = _read_rows(run_dir / "questions.jsonl")
    question_ids = [row["id"] for row in question_rows]
    source_files = _run_files(run_dir)
    packet = _load_packet(packet_path, run_dir / "questions.jsonl") if packet_path else None
    if packet and packet.get("source_files") != source_files:
        raise ValueError("Run files changed since review packet export")
    reviews = {}
    gold_reviews: dict[str, dict[str, Any]] = {}
    if packet:
        for item in packet["questions"]:
            gold = _approved_gold(item)
            if gold:
                if gold["question"] != item["question"]["question"]:
                    raise ValueError("Changed question text requires freezing a new dataset and a new generation run")
                gold_reviews[item["id"]] = gold
        for item in packet["answers"]:
            key = (item["mode"], item["id"])
            if key in reviews:
                raise ValueError(f"Duplicate answer review: {key}")
            reviews[key] = item
    results: dict[str, list[dict[str, Any]]] = {}
    matched_reviews: set[tuple[str, str]] = set()
    for mode in metadata["modes"]:
        results[mode] = []
        for original in _read_rows(run_dir / f"{mode}_results.jsonl"):
            if original["id"] not in question_ids:
                raise ValueError(f"Result has unknown question ID: {original['id']}")
            row = dict(original)
            key = (mode, row["id"])
            annotation = reviews.get(key)
            if annotation:
                pinned_fields = {field: value for field, value in annotation.items() if field != "review"}
                if pinned_fields != _answer_packet_row(original, mode):
                    raise ValueError(f"Answer pin mismatch: {key}")
                matched_reviews.add(key)
            if row["id"] in gold_reviews:
                gold = gold_reviews[row["id"]]
                row["original_label"] = {field: row.get(field) for field in gold}
                row.update(gold)
            # Old runs stored heuristic verdicts. Re-evaluate their text explicitly,
            # preserving the original value; structured or human verdicts stay pinned.
            if row.get("error") is None and row.get("predicted_status") != "error" and row.get("status_source") != "manual_review" and not row.get("verdict"):
                status = infer_status(str(row.get("answer", "")))
                if status == "answered" and row.get("predicted_status") == "insufficient_evidence":
                    status = "insufficient_evidence"
                if status == "answered" and row.get("question_type") != "cve_version_check" and extract_cves(str(row.get("answer", ""))):
                    status = "affected"
                row["original_prediction"] = {"predicted_status": row.get("predicted_status")}
                row["predicted_status"] = status
                row["status_source"] = "legacy_inference"
            if annotation and annotation.get("review"):
                row = _apply_answer_review(row, annotation["review"])
            results[mode].append(row)
    if matched_reviews != set(reviews):
        raise ValueError("Review packet contains answers absent from this run")
    known_cves = None
    catalog_manifest = None
    if all_cve_ids:
        from data_pipeline.cve_catalog import load_catalog, load_catalog_manifest

        known_cves = load_catalog(all_cve_ids)
        catalog_manifest = load_catalog_manifest(all_cve_ids)
    indexed = {mode: {row["id"]: row for row in rows} for mode, rows in results.items()}
    paired = [identifier for identifier in question_ids if all(identifier in rows for rows in indexed.values())]
    scored = [identifier for identifier in paired if all(rows[identifier].get("error") is None and rows[identifier].get("predicted_status") != "error" for rows in indexed.values())]
    summaries = {MODE_KEYS[mode]: summarize((rows[identifier] for identifier in scored), known_cves) if scored else None for mode, rows in indexed.items()}
    effective_questions = [gold_reviews.get(row["id"], row) for row in question_rows]
    report = {
        **metadata, "scorer_version": SCORER_VERSION, "rescored_at": datetime.now(UTC).isoformat(), "source_run": str(run_dir.resolve()),
        "source_file_sha256": source_files, "review_packet_sha256": _sha256(packet_path) if packet_path else None,
        "catalog_sha256": _sha256(all_cve_ids) if all_cve_ids else None,
        "nvd_catalog": catalog_manifest, "source_nvd_catalog": metadata.get("nvd_catalog"),
        "catalog_status": "supplied_for_rescore" if all_cve_ids else "not_supplied_for_rescore",
        "label_quality": dataset_quality_report(effective_questions),
        "automatic_score_scope": "CVE sets, verdicts and expected URL overlap; factual content and source support require separate review",
        "rescore_llm_calls": 0, "target_questions": len(question_rows), "paired_questions": len(paired),
        "gold_reviewed_question_ids": sorted(gold_reviews),
        "scored_questions": len(scored), "completed": len(scored) == len(question_rows),
        "failed_responses": {mode: sum(row.get("error") is not None or row.get("predicted_status") == "error" for row in rows) for mode, rows in results.items()},
        "attempted_questions": {mode: len(rows) for mode, rows in results.items()}, **summaries,
        "llm_usage": {mode: summarize_performance(rows) for mode, rows in results.items()},
    }
    for left, right in combinations(summaries, 2):
        report[f"{right}_minus_{left}"] = compare_summaries(summaries[left], summaries[right]) if scored else None
    # All validation runs before creating a fresh directory. No source file is edited.
    output_dir.mkdir(parents=True, exist_ok=False)
    for name in source_files:
        if not name.endswith("_results.jsonl"):
            target_name = "source_nvd_catalog_manifest.json" if name == "nvd_catalog_manifest.json" else name
            (output_dir / target_name).write_bytes((run_dir / name).read_bytes())
    if catalog_manifest:
        _write_new_json(output_dir / "nvd_catalog_manifest.json", catalog_manifest)
    if gold_reviews:
        with (output_dir / "reviewed_questions.jsonl").open("x", encoding="utf-8") as file:
            for row in effective_questions:
                file.write(json.dumps(row, ensure_ascii=False) + "\n")
    for mode, rows in results.items():
        with (output_dir / f"{mode}_results.jsonl").open("x", encoding="utf-8") as file:
            for row in rows:
                file.write(json.dumps(row, ensure_ascii=False) + "\n")
    _write_new_json(output_dir / "summary.json", report)
    write_metrics_csv(output_dir / "metrics.csv", report, MODE_KEYS)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    quality = commands.add_parser("quality", help="Report dataset balance and provenance gaps")
    quality.add_argument("--dataset", required=True, type=Path)
    packet = commands.add_parser("packet", help="Export unreviewed questions and saved answers")
    packet.add_argument("--dataset", required=True, type=Path)
    packet.add_argument("--run-dir", type=Path)
    packet.add_argument("--output", required=True, type=Path)
    freeze = commands.add_parser("freeze", help="Export only explicitly approved gold questions")
    freeze.add_argument("--dataset", required=True, type=Path)
    freeze.add_argument("--reviews", required=True, type=Path)
    freeze.add_argument("--output", required=True, type=Path)
    rescore = commands.add_parser("rescore", help="Rescore saved outputs into a new directory")
    rescore.add_argument("--run-dir", required=True, type=Path)
    rescore.add_argument("--output-dir", required=True, type=Path)
    rescore.add_argument("--reviews", type=Path)
    rescore.add_argument("--all-cve-ids", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "quality":
            result = review_quality_report(load_questions(args.dataset))
        elif args.command == "packet":
            packet_result = export_packet(args.dataset, args.output, args.run_dir)
            result = {"output": str(args.output), "questions": len(packet_result["questions"]), "answers": len(packet_result["answers"]), "quality": packet_result["quality"]}
        elif args.command == "freeze":
            result = freeze_dataset(args.dataset, args.reviews, args.output)
        else:
            result = rescore_run(args.run_dir, args.output_dir, args.reviews, args.all_cve_ids)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(2, f"Review failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
