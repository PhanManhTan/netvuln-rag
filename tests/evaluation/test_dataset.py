import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from config.products import ProductProfile, VersionTarget
from data_pipeline.schemas import SourceReference, VersionRule, VulnerabilityRecord
from evaluation.build import _build_content_questions, _inject_negative_cases, build_product_questions, build_raw_questions
from evaluation.dataset import EvaluationQuestion, dataset_quality_report, load_questions


def records(product_id: str, base: int) -> list[VulnerabilityRecord]:
    result = []
    for offset in range(4):
        cve = f"CVE-2024-{base + offset:04d}"
        source = SourceReference(
            source_id=f"nvd:{cve}", authority="nvd", source_type="nvd",
            url=f"https://nvd.nist.gov/vuln/detail/{cve}",
        )
        rule = VersionRule(
            source_id=source.source_id, authority="nvd", status="affected",
            branch="7.2", exact_versions=(f"7.2.{offset}",),
        )
        result.append(VulnerabilityRecord(
            record_id=f"{product_id}:{cve}", vulnerability_id=cve, product_id=product_id,
            vendor="vendor", product=product_id, display_name=product_id,
            weaknesses=(f"CWE-{100 + offset}",), sources=(source,),
            applicability=(rule,), effective_rules=(rule,),
        ))
    return result


def test_generator_produces_required_72_row_distribution(tmp_path) -> None:
    routeros = records("routeros", 1000)
    fortios = records("fortios", 2000)
    famous = {record.vulnerability_id: "review reason" for record in (*routeros, *fortios)}
    all_ids = set(famous)
    rows = []
    for product_id, selected, other in (
        ("routeros", routeros, fortios),
        ("fortios", fortios, routeros),
    ):
        product_rows = build_product_questions(product_id, selected, famous)
        _inject_negative_cases(product_rows, product_id, selected, other, all_ids)
        rows.extend(product_rows)
    path = tmp_path / "questions.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert len(load_questions(path, enforce_distribution=True)) == 72


def draft_question() -> dict:
    return {
        "id": "sample", "product_id": "fortios", "question_type": "cve_version_check",
        "question": "FortiOS 7.2.7 có bị CVE-2024-0001 ảnh hưởng không?",
        "expected_cves": ["CVE-2024-0001"], "expected_status": "affected",
        "expected_source_urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
        "famous": False, "has_conflict": False, "notes": "Draft from snapshot.",
    }


def test_reviewed_gate_rejects_draft_and_accepts_evidence_backed_approval(tmp_path) -> None:
    row = draft_question()
    path = tmp_path / "questions.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert load_questions(path)[0]["review_status"] == "draft"
    with pytest.raises(ValueError, match="approved"):
        load_questions(path, require_reviewed=True)

    row.update(review_status="approved", reviewed_by="test-reviewer", reviewed_at="2026-11-09T18:00:00Z", label_basis="manual_source_review", label_evidence=[{
        "source_url": row["expected_source_urls"][0], "excerpt": "Source explicitly covers the queried version.",
    }])
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert load_questions(path, require_reviewed=True)[0]["review_status"] == "approved"


@pytest.mark.parametrize("overrides", [
    {}, {"reviewed_by": "reviewer"},
    {"reviewed_by": "reviewer", "reviewed_at": "2026-11-09T18:00:00"},
    {"reviewed_by": "reviewer", "reviewed_at": "2026-11-09T18:00:00Z", "label_basis": "manual_source_review"},
])
def test_approved_label_requires_reviewer_timestamp_and_evidence(overrides) -> None:
    row = {**draft_question(), "review_status": "approved", **overrides}
    with pytest.raises(ValidationError):
        EvaluationQuestion.model_validate(row)


def test_absence_evidence_cannot_be_approved_as_not_affected() -> None:
    row = {
        **draft_question(), "expected_status": "not_affected", "review_status": "approved",
        "reviewed_by": "reviewer", "reviewed_at": "2026-11-09T18:00:00Z",
        "label_basis": "absence_from_complete_nvd_query",
        "label_evidence": [{"source_url": "https://nvd.nist.gov/", "excerpt": "Absent from query."}],
    }
    with pytest.raises(ValidationError, match="positive source evidence"):
        EvaluationQuestion.model_validate(row)


def test_quality_report_exposes_missing_classes_and_review_status() -> None:
    report = dataset_quality_report([draft_question()])
    assert report["review_status"] == {"draft": 1}
    assert report["expected_status"] == {"affected": 1}
    assert not report["reviewed_ready"]
    assert any("No not_affected" in warning for warning in report["warnings"])


def test_raw_candidate_selection_is_reproducible_and_not_oldest_prefix(tmp_path) -> None:
    targets = tuple(VersionTarget(version=f"7.2.{index}", cpe=f"cpe:2.3:o:fortinet:fortios:7.2.{index}:*:*:*:*:*:*:*") for index in range(3))
    product = ProductProfile(product_id="fortios", vendor="fortinet", product="fortios", display_name="FortiOS", cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", versions=targets)
    raw = {
        f"CVE-2024-{index:04d}": (tmp_path / "page_0001.json", {"id": f"CVE-2024-{index:04d}", "descriptions": [{"lang": "en", "value": f"Description {index}."}]})
        for index in range(1, 31)
    }
    adapter = SimpleNamespace(profile=product, read_version_queries=lambda *args, **kwargs: [(target, raw) for target in targets])
    rows = build_raw_questions(adapter, tmp_path / "saved-run", {}, checks_per_version=4, details_per_product=3)
    assert rows == build_raw_questions(adapter, tmp_path / "saved-run", {}, checks_per_version=4, details_per_product=3)
    checks = [row for row in rows if row["question_type"] == "cve_version_check"]
    assert len(checks) == 12
    assert {row["expected_cves"][0] for row in checks[:4]} != set(sorted(raw)[:4])
    assert len({row["question"].split("CVE-")[0] for row in checks}) > 1
    assert all(row["review_status"] == "draft" for row in rows)
    assert all(row["expected_status"] != "not_affected" for row in rows)
    assert all(row["label_basis"] == "nvd_exact_cpe_query" for row in checks)


def test_semantic_candidates_include_natural_weakness_alias_with_full_gold_group() -> None:
    product = ProductProfile(product_id="fortios", vendor="fortinet", product="fortios", display_name="FortiOS", cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*")
    raw = {f"CVE-2024-{index:04d}": {"weaknesses": [{"description": [{"value": "CWE-287"}]}]} for index in (1, 2)}
    rows = _build_content_questions(product, raw, {}, 0, 2)
    lexical, natural = rows
    assert "CWE-287" in lexical["question"]
    assert "CWE-" not in natural["question"] and "CVE-" not in natural["question"]
    assert "improper authentication" in natural["question"]
    assert natural["expected_cves"] == lexical["expected_cves"] == sorted(raw)
    assert natural["review_status"] == "draft"
    assert natural["label_basis"] == "nvd_weakness_membership"
    assert all("CWE-287" in evidence["excerpt"] for evidence in natural["label_evidence"])
