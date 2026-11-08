import json

from data_pipeline.schemas import SourceReference, VersionRule, VulnerabilityRecord
from evaluation.build import _inject_negative_cases, build_product_questions
from evaluation.dataset import load_questions


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
