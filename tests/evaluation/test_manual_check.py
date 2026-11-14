import hashlib
import json
from types import SimpleNamespace

import pytest

from evaluation import manual_check


@pytest.fixture
def saved_run(tmp_path):
    questions = [
        {"id": f"q{i}", "question": f"Question {i}", "expected_status": "affected", "expected_cves": [f"CVE-2024-100{i}"], "expected_source_urls": [], "reference_answer": f"Reference {i}"}
        for i in (1, 2, 3)
    ]
    (tmp_path / "run.json").write_text(json.dumps({"modes": ["llm_only", "rag"], "model": "test-model"}))
    (tmp_path / "questions.jsonl").write_text("".join(json.dumps(q) + "\n" for q in questions))
    for mode in ("llm_only", "rag"):
        rows = [{**q, "answer": f"{mode} answer {q['id']}", "predicted_status": "affected", "error": None, "citations": []} for q in questions[:2]]
        if mode == "rag":
            rows[1]["error"] = "Retrieval unavailable"
            rows.reverse()
        (tmp_path / f"{mode}_results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    return tmp_path


def test_viewer_pairs_by_id_and_displays_missing_and_failed_answers(saved_run, capsys):
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in saved_run.iterdir()}
    run = manual_check.load_run(saved_run)
    manual_check.show_question(run, 0)
    first = capsys.readouterr().out
    assert "Question 1/3" in first and "FULL ANSWERS AND SOURCES" in first
    assert "Reference 1" in first and "llm_only answer q1" in first and "rag answer q1" in first
    assert "rag answer q2" not in first
    manual_check.show_question(run, 1)
    assert "B2 error: Retrieval unavailable" in capsys.readouterr().out
    manual_check.show_question(run, 2)
    assert "NOT RUN" in capsys.readouterr().out
    assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in saved_run.iterdir()} == before


def test_select_search_and_navigation_are_read_only(saved_run, monkeypatch, capsys):
    commands = iter(["a", "u", "0", "2", "a", "p", "n", "q1", "/CVE-2024-1002", "/no-such-text", "n", "/", "r", "l 2", "q"])
    monkeypatch.setattr("builtins.input", lambda _: next(commands))
    assert manual_check.browse(manual_check.load_run(saved_run)) == 0
    output = capsys.readouterr().out
    assert "Select a question first." in output
    assert "Select a number from 1 to 3" in output
    assert "Question 2/3" in output and "Question 1/3" in output
    assert "0 questions | Page 1/1" in output
    assert "No matching questions" in output
    assert output.count("LLM EFFICIENCY — main system metrics (whole saved run)") == 2
    assert not list(saved_run.glob("*.html"))


def test_cli_selects_run_and_exits_cleanly_on_eof(saved_run, monkeypatch, capsys):
    monkeypatch.setattr("config.settings.get_settings", lambda: SimpleNamespace(evaluation_dir=saved_run.parent))
    monkeypatch.setattr("sys.argv", ["manual_check"])
    commands = iter(["invalid", "", "1"])

    def enter(_):
        try:
            return next(commands)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr("builtins.input", enter)
    assert manual_check.main() == 0
    output = capsys.readouterr().out
    assert "Saved evaluation runs" in output and "test-model" in output
    assert "CVE COMPARISON" in output and "B2" in output
    assert "Reference 1" in output and "llm_only answer q1" in output and "rag answer q1" in output


def test_viewer_prefers_reviewed_labels_and_can_read_logs_without_metadata(saved_run):
    rows = manual_check.read_rows(saved_run / "questions.jsonl")
    rows[0]["expected_status"] = "not_affected"
    (saved_run / "reviewed_questions.jsonl").write_text("".join(json.dumps(q) + "\n" for q in rows))
    (saved_run / "run.json").unlink()
    run = manual_check.load_run(saved_run)
    assert run.questions[0]["expected_status"] == "not_affected"
    assert run.modes == ["llm_only", "rag"]


def test_viewer_reports_broken_saved_files(saved_run):
    path = saved_run / "rag_results.jsonl"
    path.write_text("{not-json}\n")
    with pytest.raises(ValueError, match="Invalid JSON"):
        manual_check.load_run(saved_run)
    path.write_text('{"id":"duplicate"}\n{"id":"duplicate"}\n')
    with pytest.raises(ValueError, match="Missing or duplicate question ID"):
        manual_check.load_run(saved_run)


def test_cve_matrix_has_one_row_per_cve_and_marks_missing_and_extra(saved_run):
    run = manual_check.load_run(saved_run)
    first, second, extra = "CVE-2024-1001", "CVE-2024-1002", "CVE-2024-9999"
    run.questions[0]["expected_cves"] = [first, second]
    run.modes = ["llm_only", "llm_document", "rag"]
    run.answers = {
        "llm_only": {"q1": {"predicted_status": "not_affected", "asserted_cves": [first], "error": None}},
        "llm_document": {"q1": {"predicted_status": "affected", "asserted_cves": [first, extra], "error": None}},
        "rag": {"q1": {"predicted_status": "affected", "asserted_cves": [second, first, first], "error": None}},
    }
    expected, outputs = manual_check.comparison_data(run, 0)
    assert manual_check.cve_rows(expected, outputs) == [
        [first, "YES", "YES", "YES", "YES"],
        [second, "YES", "! MISSING", "! MISSING", "YES"],
        [extra, "-", "-", "+ EXTRA", "-"],
    ]


def test_cve_matrix_keeps_missing_responses_and_errors_distinct(saved_run):
    run = manual_check.load_run(saved_run)
    run.answers["llm_only"].pop("q2")
    expected, outputs = manual_check.comparison_data(run, 1)
    assert manual_check.cve_rows(expected, outputs) == [["CVE-2024-1002", "YES", "NOT RUN", "ERROR"]]
    criteria = dict((row[0], row[1:]) for row in manual_check.evaluation_rows(run.questions[1], outputs))
    assert criteria["CVE exact match"] == ["NOT RUN", "ERROR"]
    assert criteria["LLM judge"] == ["NOT RUN", "NOT RUN"]


def test_legacy_mentions_are_normalized_and_explicit_abstention_is_preserved(saved_run, capsys):
    run = manual_check.load_run(saved_run)
    run.answers["llm_only"]["q1"].update(answer="Cannot confirm CVE‑2024‑1001.", predicted_status="insufficient_evidence", asserted_cves=[])
    run.answers["rag"]["q1"].update(answer="CVE‑2024‑1001 affects this version.")
    expected, outputs = manual_check.comparison_data(run, 0)
    assert manual_check.cve_rows(expected, outputs) == [["CVE-2024-1001", "YES", "! MISSING", "YES"]]
    manual_check.show_question(run, 0)
    output = capsys.readouterr().out
    assert "Legacy outputs:" in output and "Legacy heuristic" in output
    assert "! DIFF" in output and "OK" in output


def test_table_preserves_unicode_alignment_at_common_terminal_widths(capsys):
    for width in (60, 80, 120, 160):
        manual_check.print_table(["CVE", "System", "B0", "B1", "B2"], [["CVE-2024-6387", "YES", "! MISSING", "漢字 and e\u0301", "+ EXTRA"]], width, first_width=17)
        lines = capsys.readouterr().out.splitlines()
        assert {manual_check.display_width(line) for line in lines} == {width}
        assert sum("CVE-2024-6387" in line for line in lines) == 1


def test_per_question_criteria_score_cves_evidence_and_url_overlap(saved_run):
    run = manual_check.load_run(saved_run)
    run.questions[0].update(expected_cves=["CVE-2024-1001", "CVE-2024-1002"], expected_source_urls=["https://example.org/correct"])
    run.answers["rag"]["q1"].update(
        asserted_cves=["CVE-2024-1001", "CVE-2024-9999"],
        retrieved_evidence_cves=["CVE-2024-1001"],
        citations=[{"url": "https://example.org/correct"}, {"url": "https://example.org/other"}],
    )
    _, outputs = manual_check.comparison_data(run, 0)
    criteria = {row[0]: row[1:] for row in manual_check.evaluation_rows(run.questions[0], outputs)}
    assert criteria["CVE exact match"][1] == "FAIL"
    assert criteria["Verdict match"][1] == "PASS"
    assert criteria["CVE + verdict"][1] == "FAIL"
    assert criteria["CVE precision"][1] == criteria["CVE recall"][1] == "50.0% (1/2)"
    assert criteria["CVE F1"][1] == "50.0%"
    assert criteria["Evidence CVE recall"] == ["N/A", "50.0% (1/2)"]
    assert criteria["Citation URL precision"][1] == "50.0% (1/2)"
    assert criteria["Expected URL hit"][1] == "PASS"
    assert criteria["Factual correctness"] == ["NOT REVIEWED", "NOT REVIEWED"]
    assert criteria["LLM judge"] == ["NOT RUN", "NOT RUN"]


def test_per_question_human_ratings_require_provenance_and_keep_unknowns(saved_run, capsys):
    run = manual_check.load_run(saved_run)
    run.answers["llm_only"]["q1"]["manual_review"] = {"factual_correctness": True}
    run.answers["rag"]["q1"]["manual_review"] = {
        "reviewed_by": "Test reviewer", "reviewed_at": "2026-11-09T12:00:00Z",
        "evidence_sources": ["https://example.org/advisory"], "notes": "The answer omits a configuration condition.",
        "factual_correctness": False, "faithfulness": None, "citation_support": True,
    }
    _, outputs = manual_check.comparison_data(run, 0)
    criteria = {row[0]: row[1:] for row in manual_check.evaluation_rows(run.questions[0], outputs)}
    assert criteria["Factual correctness"] == ["NOT REVIEWED", "FAIL (human)"]
    assert criteria["Faithfulness"] == ["NOT REVIEWED", "NOT REVIEWED"]
    assert criteria["Citation support"] == ["NOT REVIEWED", "PASS (human)"]
    manual_check.show_evaluation(run.questions[0], outputs, 100)
    assert "Test reviewer" in capsys.readouterr().out


def test_empty_set_abstention_and_legacy_repetition_do_not_create_false_scores(saved_run):
    run = manual_check.load_run(saved_run)
    run.answers["llm_only"]["q1"].update(answer="Cannot confirm CVE-2024-1001.", predicted_status="insufficient_evidence")
    expected, outputs = manual_check.comparison_data(run, 0)
    assert manual_check.cve_rows(expected, outputs)[0][2] == "! MISSING"
    run.questions[0].update(expected_cves=[], expected_status="insufficient_evidence")
    run.answers["llm_only"]["q1"]["asserted_cves"] = []
    _, outputs = manual_check.comparison_data(run, 0)
    criteria = {row[0]: row[1:] for row in manual_check.evaluation_rows(run.questions[0], outputs)}
    assert criteria["CVE exact match"][0] == criteria["Verdict match"][0] == criteria["CVE + verdict"][0] == "PASS"
    assert criteria["Correct abstention"][0] == "PASS"
    assert criteria["CVE precision"][0] == criteria["CVE recall"][0] == criteria["CVE F1"][0] == "N/A"


def test_usage_remains_visible_for_failed_answers_and_missing_responses(saved_run, capsys):
    run = manual_check.load_run(saved_run)
    run.answers["llm_only"].pop("q2")
    run.answers["rag"]["q2"].update(llm_requests=[
        {"succeeded": False, "latency_seconds": 1},
        {"succeeded": True, "latency_seconds": 2, "input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
    ])
    _, outputs = manual_check.comparison_data(run, 1)
    metrics = {row[0]: row[1:] for row in manual_check.usage_rows(outputs)}
    assert metrics["Total tokens"] == ["NOT RUN", "120 (1/2 calls)"]
    assert metrics["LLM attempts"] == ["NOT RUN", "2"]
    assert metrics["Failed LLM attempts"] == ["NOT RUN", "1"]
    manual_check.show_question(run, 1, 160)
    output = capsys.readouterr().out
    assert "LLM EFFICIENCY" in output and "120 (1/2 calls)" in output
    assert "B2 error: Retrieval unavailable" in output


def test_run_usage_uses_each_modes_full_log_even_when_responses_are_unpaired(saved_run):
    run = manual_check.load_run(saved_run)
    run.answers["llm_only"]["q1"]["llm_requests"] = []
    run.answers["llm_only"]["q2"]["llm_requests"] = [{"succeeded": True, "total_tokens": 100, "latency_seconds": 1}]
    run.answers["rag"].pop("q2")
    outputs = [{"mode": mode, "rows": list(run.answers[mode].values())} for mode in run.modes]
    metrics = {row[0]: row[1:] for row in manual_check.usage_rows(outputs, overview=True)}
    assert metrics["Saved responses"] == ["2", "1"]
    assert metrics["Responses with logs"] == ["2", "0"]
    assert metrics["Total tokens"] == ["100", "NOT RECORDED"]
    assert metrics["Mean tokens/question"] == ["50.00", "NOT RECORDED"]
