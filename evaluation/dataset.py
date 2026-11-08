"""Schema for evaluation questions and optional legacy distribution checks."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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

    @field_validator("expected_cves")
    @classmethod
    def normalize_cves(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(value.upper() for value in values))


def load_questions(path: Path, enforce_distribution: bool = False) -> list[dict[str, Any]]:
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
    if enforce_distribution:
        _validate_distribution(rows)
    return [row.model_dump(mode="json") for row in rows]


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
