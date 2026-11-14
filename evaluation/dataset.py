"""Schema for evaluation questions and optional legacy distribution checks."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from data_pipeline.schemas import CVE_PATTERN


class LabelEvidence(BaseModel):
    """A reviewable source excerpt supporting a draft or approved label."""

    model_config = ConfigDict(frozen=True)

    source_url: str
    excerpt: str = Field(min_length=1)

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Label evidence source_url must be an HTTP(S) URL")
        return value

    @field_validator("excerpt")
    @classmethod
    def validate_excerpt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Label evidence excerpt must not be blank")
        return value.strip()


class EvaluationQuestion(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    product_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    question_type: Literal["version_inventory", "cve_version_check", "vulnerability_detail", "semantic"]
    question: str
    expected_cves: tuple[str, ...]
    expected_status: Literal["affected", "not_affected", "insufficient_evidence"]
    expected_source_urls: tuple[str, ...]
    famous: bool
    has_conflict: bool
    notes: str
    raw_run_id: str | None = None
    reference_answer: str | None = None
    review_status: Literal["draft", "approved", "rejected"] = "draft"
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    label_basis: str = "unreviewed"
    label_evidence: tuple[LabelEvidence, ...] = ()
    reference_claims: tuple[str, ...] = ()

    @field_validator("expected_cves")
    @classmethod
    def normalize_cves(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(value.upper() for value in values))
        if any(not CVE_PATTERN.fullmatch(value) for value in normalized):
            raise ValueError("Expected CVE IDs must use CVE-YYYY-NNNN format")
        return normalized

    @model_validator(mode="after")
    def validate_review(self) -> "EvaluationQuestion":
        if self.review_status != "approved":
            return self
        if not self.reviewed_by or not self.reviewed_by.strip():
            raise ValueError("Approved question requires reviewed_by")
        try:
            reviewed_at = datetime.fromisoformat((self.reviewed_at or "").replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Approved question requires an ISO8601 reviewed_at") from exc
        if reviewed_at.tzinfo is None or reviewed_at.utcoffset() is None:
            raise ValueError("Approved question reviewed_at requires a timezone")
        if not self.label_basis.strip() or self.label_basis.strip() == "unreviewed" or not self.label_evidence:
            raise ValueError("Approved question requires label_basis and supporting label_evidence")
        if self.expected_status == "not_affected" and self.label_basis in {
            "absence_from_complete_nvd_query", "outside_source_coverage", "wrong_product_absence", "catalog_absence",
        }:
            raise ValueError("not_affected requires positive source evidence; absence does not establish safety")
        return self


def load_questions(
    path: Path, enforce_distribution: bool = False, *, require_reviewed: bool = False,
) -> list[dict[str, Any]]:
    rows: list[EvaluationQuestion] = []
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                rows.append(EvaluationQuestion.model_validate_json(line))
            except Exception as exc:
                raise ValueError(f"Evaluation row lỗi tại {path}:{line_number}: {exc}") from exc
    if len({row.id for row in rows}) != len(rows):
        raise ValueError("Evaluation dataset có id trùng")
    if require_reviewed:
        unreviewed = [row.id for row in rows if row.review_status != "approved"]
        if unreviewed:
            raise ValueError(f"Evaluation requires approved questions; unreviewed/rejected IDs: {unreviewed[:10]}")
    if enforce_distribution:
        _validate_distribution(rows)
    return [row.model_dump(mode="json") for row in rows]


def dataset_quality_report(questions: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe coverage without inventing a universal score or approving labels."""
    counts = {
        field: dict(sorted(Counter(str(row.get(field, "draft" if field == "review_status" else "unknown")) for row in questions).items()))
        for field in ("product_id", "question_type", "expected_status", "review_status", "label_basis")
    }
    warnings: list[str] = []
    if not questions:
        warnings.append("Dataset is empty.")
    if counts["review_status"].get("approved", 0) != len(questions):
        warnings.append("Dataset contains unreviewed or rejected labels; scores measure draft snapshot agreement.")
    for status in ("affected", "not_affected", "insufficient_evidence"):
        if not counts["expected_status"].get(status):
            warnings.append(f"No {status} questions; that verdict is not evaluated.")
    if questions and not any(row.get("has_conflict") for row in questions):
        warnings.append("No source-conflict questions; conflict handling is not evaluated.")
    total = len(questions)
    if total and max(counts["question_type"].values(), default=0) / total > 0.6:
        warnings.append("One question type accounts for more than 60% of the dataset; inspect per-type scores.")
    return {"questions": total, **counts, "reviewed_ready": bool(total and counts["review_status"].get("approved", 0) == total), "warnings": warnings}


def validate_question_runs(
    questions: list[dict[str, Any]], manifest: dict[str, Any], source: str
) -> None:
    """Require question products and pinned raw runs to be present in the corpus."""
    processed_runs = {
        item["product_id"]: item["input_runs"].get(source)
        for item in manifest["products"]
    }
    for question in questions:
        product_id = question["product_id"]
        if product_id not in processed_runs:
            raise ValueError(f"Product {product_id} is missing from the processed corpus")
        run_id = question.get("raw_run_id")
        if run_id and run_id != processed_runs[product_id]:
            raise ValueError(
                f"Question {question['id']} requires {product_id} {source} run {run_id}, "
                f"but the processed corpus uses {processed_runs[product_id]!r}"
            )


def _validate_distribution(rows: list[EvaluationQuestion]) -> None:
    if len(rows) != 72:
        raise ValueError(f"Evaluation dataset phải có đúng 72 câu, hiện có {len(rows)}")
    product_counts = Counter(row.product_id for row in rows)
    if product_counts != {"routeros": 36, "fortios": 36}:
        raise ValueError(f"Phân bố product không đúng: {dict(product_counts)}")
    expected_types = {"version_inventory": 14, "cve_version_check": 14, "vulnerability_detail": 4, "semantic": 4}
    for product_id in ("routeros", "fortios"):
        counts = Counter(row.question_type for row in rows if row.product_id == product_id)
        if counts != expected_types:
            raise ValueError(f"Phân bố question_type của {product_id} không đúng: {dict(counts)}")
    if sum(row.famous for row in rows) < 12:
        raise ValueError("Evaluation dataset cần ít nhất 12 câu famous=true")


def load_famous_review_list(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = {str(item["vulnerability_id"]).upper(): str(item["reason"]).strip() for item in payload}
    if any(not reason for reason in result.values()):
        raise ValueError("Mỗi famous CVE phải có reason")
    return result
