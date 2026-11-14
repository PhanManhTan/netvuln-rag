import hashlib
import json

import pytest

from evaluation.dataset import load_questions
from evaluation.review import export_packet, freeze_dataset, rescore_run


def _json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _fixture(tmp_path):
    run = tmp_path / "source"
    run.mkdir()
    question = {
        "id": "openssh-check", "product_id": "openssh", "question_type": "cve_version_check",
        "question": "OpenSSH 9.6p1 có bị CVE-2008-3844 ảnh hưởng không?",
        "expected_cves": ["CVE-2008-3844"], "expected_status": "affected",
        "expected_source_urls": ["https://nvd.nist.gov/vuln/detail/CVE-2008-3844"],
        "famous": False, "has_conflict": False, "notes": "Review conditional package scope.",
        "reference_answer": "Only unofficial modified RHEL packages.", "raw_run_id": "fixture-raw",
    }
    (run / "questions.jsonl").write_text(json.dumps(question) + "\n", encoding="utf-8")
    _json(run / "run.json", {"modes": ["llm_only", "rag"], "target_questions": 1, "model": "fixture-model"})
    _json(run / "processed_manifest.json", {"snapshot_id": "fixture", "products": []})
    for mode in ("llm_only", "rag"):
        answer = {
            **question, "mode": mode, "answer": "Có. CVE-2008-3844 ảnh hưởng OpenSSH 9.6p1. Khuyến nghị nâng cấp bản không bị ảnh hưởng.",
            "predicted_status": "not_affected", "citations": [{"url": question["expected_source_urls"][0]}],
            "retrieved_evidence_cves": ["CVE-2008-3844"], "error": None,
        }
        (run / f"{mode}_results.jsonl").write_text(json.dumps(answer) + "\n", encoding="utf-8")
    return run


def _hashes(run):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in run.iterdir()}


def _answer_review():
    return {
        "reviewed_by": "test reviewer", "reviewed_at": "2026-11-09T12:00:00Z",
        "notes": "Conclusion is positive; source restricts scope to modified packages.",
        "evidence_sources": ["https://nvd.nist.gov/vuln/detail/CVE-2008-3844"],
        "predicted_status": "affected", "asserted_cves": ["CVE-2008-3844"],
        "factual_correctness": False, "faithfulness": False, "citation_support": False,
    }


def test_export_packet_is_deterministic_and_never_approves_labels(tmp_path):
    run = _fixture(tmp_path)
    first = tmp_path / "packet.json"
    second = tmp_path / "packet-copy.json"
    packet = export_packet(run / "questions.jsonl", first, run)
    export_packet(run / "questions.jsonl", second, run)
    assert first.read_bytes() == second.read_bytes()
    assert len(packet["answers"]) == 2
    assert all(item["review"] is None for item in packet["questions"] + packet["answers"])
    assert packet["questions"][0]["question"]["reference_answer"]
    with pytest.raises(FileExistsError):
        export_packet(run / "questions.jsonl", first, run)


def test_freeze_requires_approved_source_backed_review(tmp_path):
    run = _fixture(tmp_path)
    packet_path = tmp_path / "packet.json"
    packet = export_packet(run / "questions.jsonl", packet_path, run)
    output = tmp_path / "reviewed.jsonl"
    with pytest.raises(ValueError, match="No approved"):
        freeze_dataset(run / "questions.jsonl", packet_path, output)
    assert not output.exists()
    packet["questions"][0]["review"] = {
        "review_status": "approved", "reviewed_by": "test reviewer", "reviewed_at": "2026-11-09T12:00:00Z",
        "label_basis": "Independent source review",
        "label_evidence": [{"source_url": "https://nvd.nist.gov/vuln/detail/CVE-2008-3844", "excerpt": "Only unofficial modified RHEL packages."}],
        "question": "Theo snapshot NVD, OpenSSH 9.6p1 có CVE-2008-3844 không?",
    }
    _json(packet_path, packet)
    report = freeze_dataset(run / "questions.jsonl", packet_path, output)
    assert report["approved_questions"] == 1
    assert load_questions(output, require_reviewed=True)[0]["review_status"] == "approved"
    with pytest.raises(FileExistsError):
        freeze_dataset(run / "questions.jsonl", packet_path, output)


def test_freeze_rejects_tampered_question_display_and_changed_dataset(tmp_path):
    run = _fixture(tmp_path)
    packet_path = tmp_path / "packet.json"
    packet = export_packet(run / "questions.jsonl", packet_path, run)
    packet["questions"][0]["question"]["expected_status"] = "not_affected"
    _json(packet_path, packet)
    with pytest.raises(ValueError, match="display changed"):
        freeze_dataset(run / "questions.jsonl", packet_path, tmp_path / "no.jsonl")
    (run / "questions.jsonl").write_text((run / "questions.jsonl").read_text() + "\n")
    with pytest.raises(ValueError, match="source dataset"):
        freeze_dataset(run / "questions.jsonl", packet_path, tmp_path / "no.jsonl")


def test_rescore_applies_pinned_review_and_preserves_originals(tmp_path):
    run = _fixture(tmp_path)
    before = _hashes(run)
    packet_path = tmp_path / "packet.json"
    packet = export_packet(run / "questions.jsonl", packet_path, run)
    packet["answers"][1]["review"] = _answer_review()
    _json(packet_path, packet)
    output = tmp_path / "rescored"
    report = rescore_run(run, output, packet_path)
    result = json.loads((output / "rag_results.jsonl").read_text())
    assert result["predicted_status"] == "affected"
    assert result["verdict"] == "affected"
    assert result["status_source"] == "manual_review"
    assert result["original_prediction"]["predicted_status"] == "not_affected"
    assert result["manual_review"]["factual_correctness"] is False
    assert report["rescore_llm_calls"] == 0
    assert report["completed"] is True
    assert report["rag"]["manual_factual_correctness_questions"] == 1
    assert _hashes(run) == before
    with pytest.raises(FileExistsError):
        rescore_run(run, output, packet_path)


@pytest.mark.parametrize("tamper", ["answer", "manifest", "pin", "expected_cves", "citations", "reference_answer"])
def test_rescore_rejects_changed_source_or_answer_pin(tmp_path, tamper):
    run = _fixture(tmp_path)
    packet_path = tmp_path / "packet.json"
    packet = export_packet(run / "questions.jsonl", packet_path, run)
    if tamper == "answer":
        packet["answers"][0]["answer"] = "Changed review display"
    elif tamper == "pin":
        packet["answers"][0]["record_sha256"] = "0" * 64
    elif tamper == "manifest":
        _json(run / "processed_manifest.json", {"snapshot_id": "different"})
    else:
        packet["answers"][0][tamper] = "tampered display"
    _json(packet_path, packet)
    output = tmp_path / "bad"
    with pytest.raises(ValueError, match="changed|pin mismatch"):
        rescore_run(run, output, packet_path)
    assert not output.exists()


@pytest.mark.parametrize("field,value", [("reviewed_by", ""), ("reviewed_at", "2026-11-09T12:00:00"), ("evidence_sources", []), ("factual_correctness", 1), ("asserted_cves", ["CVE-2099-9999"])])
def test_rescore_rejects_invalid_review_or_invented_assertions(tmp_path, field, value):
    run = _fixture(tmp_path)
    packet_path = tmp_path / "packet.json"
    packet = export_packet(run / "questions.jsonl", packet_path, run)
    review = _answer_review()
    review[field] = value
    packet["answers"][0]["review"] = review
    _json(packet_path, packet)
    with pytest.raises(ValueError):
        rescore_run(run, tmp_path / "bad", packet_path)
    assert not (tmp_path / "bad").exists()


def test_rescore_pairs_by_question_id_and_reports_incomplete_run(tmp_path):
    run = _fixture(tmp_path)
    (run / "rag_results.jsonl").write_text("")
    report = rescore_run(run, tmp_path / "rescored")
    assert report["completed"] is False
    assert report["paired_questions"] == 0
    assert report["scored_questions"] == 0
    assert report["attempted_questions"] == {"llm_only": 1, "rag": 0}
    assert report["baseline"] is None


def test_rescore_recomputes_efficiency_from_original_calls_without_changing_source(tmp_path):
    run = _fixture(tmp_path)
    path = run / "rag_results.jsonl"
    row = json.loads(path.read_text())
    row["llm_requests"] = [{"succeeded": True, "total_tokens": 200, "latency_seconds": 2}]
    path.write_text(json.dumps(row) + "\n")
    before = _hashes(run)
    output = tmp_path / "rescored"
    report = rescore_run(run, output)
    assert report["rescore_llm_calls"] == 0
    assert report["llm_usage"]["rag"]["total_tokens"] == 200
    assert report["llm_usage"]["rag"]["average_total_tokens_per_question"] == 200
    assert report["llm_usage"]["llm_only"]["total_tokens"] is None
    assert (output / "metrics.csv").exists()
    assert _hashes(run) == before


def test_rescore_applies_approved_gold_corrections_without_regeneration(tmp_path):
    run = _fixture(tmp_path)
    packet_path = tmp_path / "packet.json"
    packet = export_packet(run / "questions.jsonl", packet_path, run)
    packet["questions"][0]["review"] = {
        "review_status": "approved", "reviewed_by": "test reviewer", "reviewed_at": "2026-11-09T12:00:00Z",
        "label_basis": "Checked source limits; membership does not establish environment",
        "label_evidence": [{"source_url": "https://nvd.nist.gov/vuln/detail/CVE-2008-3844", "excerpt": "Only unofficial modified RHEL packages."}],
        "expected_status": "insufficient_evidence", "expected_cves": [],
    }
    _json(packet_path, packet)
    output = tmp_path / "rescored"
    report = rescore_run(run, output, packet_path)
    result = json.loads((output / "rag_results.jsonl").read_text())
    assert result["expected_status"] == "insufficient_evidence"
    assert result["expected_cves"] == []
    assert result["original_label"]["expected_status"] == "affected"
    assert report["gold_reviewed_question_ids"] == ["openssh-check"]
    assert report["label_quality"]["reviewed_ready"] is True
    assert (output / "reviewed_questions.jsonl").exists()
    # Changing the question would require a different generation, not rescoring.
    packet["questions"][0]["review"]["question"] = "A different question"
    _json(packet_path, packet)
    with pytest.raises(ValueError, match="new generation run"):
        rescore_run(run, tmp_path / "different", packet_path)


def test_rescore_cannot_correct_output_failure_or_reuse_old_catalog_metadata(tmp_path):
    run = _fixture(tmp_path)
    metadata = json.loads((run / "run.json").read_text())
    metadata["nvd_catalog"] = {"sha256": "old-catalog", "cve_count": 999}
    _json(run / "run.json", metadata)
    result_file = run / "rag_results.jsonl"
    result = json.loads(result_file.read_text())
    result["output_error"] = "Malformed JSON"
    result_file.write_text(json.dumps(result) + "\n")
    packet_path = tmp_path / "packet.json"
    packet = export_packet(run / "questions.jsonl", packet_path, run)
    packet["answers"][1]["review"] = _answer_review()
    _json(packet_path, packet)
    with pytest.raises(ValueError, match="failed request"):
        rescore_run(run, tmp_path / "bad", packet_path)
    report = rescore_run(run, tmp_path / "without-catalog")
    assert report["nvd_catalog"] is None
    assert report["source_nvd_catalog"] == metadata["nvd_catalog"]
    assert report["catalog_status"] == "not_supplied_for_rescore"
