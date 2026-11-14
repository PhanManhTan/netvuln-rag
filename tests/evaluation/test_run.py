import csv
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from config.settings import Settings
from data_pipeline.schemas import TextChunk
from evaluation import client, run
from evaluation.metrics import summarize
from rag.generation.client import LLMClient
from rag.retrieval.models import ParsedQuery, QueryIntent, SearchBundle, SearchResult


CVE = "CVE-2023-51384"


@pytest.fixture
def run_cli(monkeypatch, tmp_path):
    processed_dir = tmp_path / "processed"
    processed_dir.mkdir()
    (processed_dir / "structured.jsonl").touch()
    (processed_dir / "chunks.jsonl").touch()
    settings = Settings(
        artifacts_dir=tmp_path, raw_data_dir=tmp_path / "raw", processed_data_dir=processed_dir,
        default_product_id="openssh", groq_api_key="test-key",
    )
    questions = [
        {
            "id": f"openssh-{version}",
            "product_id": "openssh",
            "question_type": "cve_version_check",
            "question": f"Is {version} affected by {CVE}?",
            "expected_cves": [CVE],
            "expected_status": "affected",
            "expected_source_urls": [],
            "famous": False,
            "has_conflict": False,
            "notes": "",
            "raw_run_id": "test-snapshot",
        }
        for version in ("9.5p1", "9.6p1")
    ]
    manifest = {"products": [{
        "product_id": "openssh",
        "input_runs": {settings.data_source: "test-snapshot"},
        "structured_path": "structured.jsonl",
        "chunks_path": "chunks.jsonl",
    }]}
    monkeypatch.setattr(run, "get_settings", lambda: settings)
    monkeypatch.setattr(run, "load_processed_manifest", lambda _: manifest)
    response = Mock()
    response.json.return_value = {
        "choices": [{"message": {"content": f"Affected by {CVE}."}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27},
    }
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(return_value=response))
    monkeypatch.setattr(
        sys, "argv",
        ["evaluation.run", "--provider", "groq", "--request-interval", "0", "--output-dir", str(tmp_path / "runs")],
    )
    run.write_jsonl(settings.evaluation_questions_file, questions)
    return tmp_path / "runs"


def test_cli_persists_errors_but_scores_only_successful_pairs(monkeypatch, run_cli):
    class FakeChatbot:
        def __init__(self, settings, llm, retriever):
            self.llm = llm

        def ask(self, question, provider, top_k, **kwargs):
            if "9.6p1" in question:
                raise RuntimeError("Index unavailable")
            return {
                "answer": self.llm.generate("", question, provider),
                "status": "answered",
                "citations": [],
                "retrieved_evidence_cves": [CVE],
            }

    monkeypatch.setattr(run, "RAGChatbot", FakeChatbot)
    assert run.main() == 1

    run_dir, = run_cli.iterdir()
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["target_questions"] == summary["paired_questions"] == 2
    assert summary["scored_questions"] == summary["baseline"]["questions"] == summary["rag"]["questions"] == 1
    assert summary["rag"]["cve_and_status_accuracy"] == summary["rag"]["version_status_accuracy"] == 1.0
    assert summary["failed_responses"] == {"llm_only": 0, "rag": 1}
    assert summary["completed"] is False
    answers = [json.loads(line) for line in (run_dir / "rag_results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert answers[0]["retrieved_evidence_cves"] == [CVE]
    assert answers[0]["llm_requests"][0]["total_tokens"] == 27
    assert answers[1]["error"] == "Index unavailable"
    assert answers[1]["llm_requests"] == []
    assert summary["llm_usage"]["llm_only"]["total_tokens"] == 54
    assert summary["llm_usage"]["rag"]["total_tokens"] == 27
    assert summary["llm_usage"]["rag"]["average_total_tokens_per_question"] == 13.5
    assert summary["llm_usage"]["rag"]["questions_with_llm_call"] == 1
    with (run_dir / "metrics.csv").open(encoding="utf-8-sig", newline="") as file:
        metrics = list(csv.DictReader(file))
    assert {row["metric_group"] for row in metrics} == {"answer_quality", "llm_efficiency"}
    totals = {row["mode"]: row["value"] for row in metrics if row["metric"] == "total_tokens"}
    assert totals == {"llm_only": "54", "rag": "27"}
    assert summary["llm_usage"]["rag"]["saved_questions"] == 2  # Quality scores only one pair.


def test_cli_compares_fixed_documents_and_counts_provider_tokens(monkeypatch, run_cli):
    other_cve = "CVE-2023-11111"
    chunks_path = run_cli.parent / "processed" / "chunks.jsonl"
    chunks = [
        TextChunk(
            chunk_id=marker, record_id=f"{product}:{cve}", vulnerability_id=cve,
            product_id=product, vendor=product, product=product, section="overview",
            text=body, source_id=marker, source_url=f"https://example.com/{marker}", content_hash=marker,
        )
        for marker, product, cve, body in (
            ("other", "openvpn", other_cve, "Other product evidence."),
            ("fixed", "openssh", other_cve, "Fixed product evidence."),
            ("overflow", "openssh", CVE, "x" * run.DOCUMENT_CONTEXT_MAX_CHARS),
        )
    ]
    chunks_path.write_text("\n".join(chunk.model_dump_json() for chunk in chunks), encoding="utf-8")
    search_calls = []

    def search(self, question, top_k):
        search_calls.append(question)
        results = [
            SearchResult("retrieved", 1.0, CVE, "overview", "Retrieved evidence.", "https://example.com/retrieved"),
            SearchResult("overflow", 1.0, other_cve, "overview", chunks[-1].text, "https://example.com/overflow"),
        ]
        return SearchBundle(ParsedQuery(question, QueryIntent.VULNERABILITY_CHECK), results, [])

    prompts = {"fixed": [], "retrieved": [], "baseline": []}

    def post(url, *, json, **kwargs):
        prompt = json["messages"][-1]["content"]
        answer = f"Affected by {CVE}."
        assert "Other product evidence." not in prompt and "x" * 100 not in prompt
        if "Fixed product evidence." in prompt:
            prompts["fixed"].append(prompt.split("Bằng chứng:\n", 1)[1])
            answer = "Không đủ bằng chứng."
            input_tokens = 70
        elif "Retrieved evidence." in prompt:
            prompts["retrieved"].append(prompt)
            answer += " [S1]"
            input_tokens = 40
        else:
            prompts["baseline"].append(prompt)
            input_tokens = 20
        response = Mock()
        response.json.return_value = {
            "choices": [{"message": {"content": answer}}],
            "usage": {
                "prompt_tokens": input_tokens, "completion_tokens": 7,
                "completion_tokens_details": {"reasoning_tokens": 3},
            },
        }
        return response

    monkeypatch.setattr(run.Retriever, "search", search)
    monkeypatch.setattr("rag.generation.client.requests.post", post)
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--with-documents"])

    assert run.main() == 0
    assert len(search_calls) == len(prompts["fixed"]) == len(prompts["retrieved"]) == len(prompts["baseline"]) == 2
    assert prompts["fixed"][0] == prompts["fixed"][1]
    run_dir, = run_cli.iterdir()
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["context_max_chars"] == run.DOCUMENT_CONTEXT_MAX_CHARS
    assert summary["scored_questions"] == 2
    assert summary["document"]["cve_and_status_accuracy"] == 0.0
    assert summary["rag_minus_document"]["cve_and_status_accuracy"] == 1.0
    assert summary["baseline"]["evidence_cve_recall"] is None
    assert summary["document"]["evidence_cve_recall"] == 0.0
    assert summary["rag"]["evidence_cve_recall"] == 1.0
    usage = summary["llm_usage"]
    assert usage["llm_only"]["input_tokens"] == 40
    assert usage["llm_document"]["input_tokens"] == 140
    assert usage["llm_document"]["output_tokens"] == 14
    assert usage["llm_document"]["reasoning_tokens"] == 6
    assert usage["llm_document"]["total_tokens"] == 154
    assert usage["rag"]["input_tokens"] == 80
    row = json.loads((run_dir / "llm_document_results.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert row["document_evidence_cves"] == [other_cve]
    assert row["llm_requests"][0]["input_tokens"] == 70


@pytest.mark.parametrize("completed", [True, False])
def test_streaming_cli_persists_ttft_usage_and_final_validation(monkeypatch, run_cli, capsys, completed):
    text = json.dumps({"verdict": "affected", "answer": f"Affected by {CVE}.", "asserted_cves": [CVE]})
    events = [
        {"choices": [{"delta": {"content": text[:20]}}]},
        {"choices": [{"delta": {"content": text[20:]}}]},
    ]
    if completed:
        events.extend([
            {"choices": [], "x_groq": {"usage": {"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27}}},
            "[DONE]",
        ])
    response = Mock()
    response.iter_lines.return_value = iter(
        line for event in events
        for line in ["data: " + (event if isinstance(event, str) else json.dumps(event)), ""]
    )
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(return_value=response))
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--modes", "llm_only", "--stream", "--limit", "1"])
    assert run.main() == (0 if completed else 1)
    run_dir, = run_cli.iterdir()
    summary = json.loads((run_dir / "summary.json").read_text())
    row = json.loads((run_dir / "llm_only_results.jsonl").read_text())
    usage = summary["llm_usage"]["llm_only"]
    assert summary["stream"] is True
    assert usage["ttft_reported_attempts"] == 1
    assert usage["average_ttft_seconds"] >= 0
    assert usage["failed_attempts"] == (0 if completed else 1)
    if completed:
        assert row["raw_answer"] == text
        assert row["asserted_cves"] == [CVE]
        assert usage["total_tokens"] == 27
        assert summary["baseline"]["cve_and_status_accuracy"] == 1
    else:
        assert "before completion" in row["error"]
        assert summary["baseline"] is None
        assert usage["total_tokens"] is None
    output = capsys.readouterr().out
    assert text in output and "LLM draft (streaming" in output and "Final result [" in output
    response.close.assert_called_once()


def test_cli_runs_raw_baseline_from_pinned_pages_without_processed_data(monkeypatch, run_cli):
    settings = run.get_settings()
    profile = run.get_product_catalog(settings.product_config_file).by_id("openssh")
    run_dir = settings.raw_product_source_dir("openssh", "nvd") / "test-snapshot"
    raw = {"id": CVE, "configurations": [{"nodes": [{"operator": "AND"}]}]}
    queries = []
    for index, target in enumerate(profile.versions, 1):
        page = f"page_{index:04d}.json"
        run.write_json(run_dir / page, {"totalResults": 1, "vulnerabilities": [{"cve": raw}]})
        queries.append({"version": target.version, "cpe": target.cpe, "pages": [page], "total_results": 1, "downloaded": 1})
    run.write_json(run_dir / "manifest.json", {"product_id": "openssh", "status": "completed", "version_queries": queries})
    load_manifest = Mock(side_effect=AssertionError("Raw mode must use the raw run directly"))
    monkeypatch.setattr(run, "load_processed_manifest", load_manifest)
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--modes", "llm_raw"])

    assert run.main() == 0
    load_manifest.assert_not_called()
    prompts = [call.kwargs["json"]["messages"][-1]["content"] for call in requests.post.call_args_list]
    evidence = [prompt.split("Bằng chứng:\n", 1)[1] for prompt in prompts]
    assert len(evidence) == 2 and evidence[0] == evidence[1]
    assert evidence[0].count(json.dumps(raw, separators=(",", ":"))) == 1
    output_dir, = run_cli.iterdir()
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["raw_runs"] == {"openssh": "test-snapshot"}
    assert summary["raw"]["evidence_cve_recall"] == 1.0
    assert summary["llm_usage"]["llm_raw"]["total_tokens"] == 54


def test_cli_runs_bm25_with_only_processed_chunks(monkeypatch, run_cli):
    settings = run.get_settings()
    chunk = TextChunk(
        chunk_id="openssh-test", record_id=f"openssh:{CVE}", vulnerability_id=CVE,
        product_id="openssh", vendor="openbsd", product="openssh", section="overview",
        text=f"OpenSSH {CVE} is affected. BM25 evidence.", source_id="test",
        source_url="https://example.com/advisory", content_hash="test",
    )
    (settings.processed_data_dir / "chunks.jsonl").write_text(chunk.model_dump_json(), encoding="utf-8")
    resolve_artifact = run.resolve_processed_artifact

    def resolve_chunks_only(settings, row, kind):
        assert kind == "chunks"
        return resolve_artifact(settings, row, kind)

    monkeypatch.setattr(run, "resolve_processed_artifact", resolve_chunks_only)
    monkeypatch.setattr(run.Retriever, "_dense_search", Mock(side_effect=AssertionError("BM25 must not use Qdrant")))
    monkeypatch.setattr(run.Retriever, "_structured_decisions", Mock(side_effect=AssertionError("BM25 must not check versions")))
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--modes", "llm_bm25"])

    assert run.main() == 0
    output_dir, = run_cli.iterdir()
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["modes"] == ["llm_bm25"]
    assert summary["bm25"]["cve_and_status_accuracy"] == 1.0
    assert summary["bm25"]["evidence_cve_recall"] == 1.0


@pytest.mark.parametrize(("provider", "payload", "tokens"), [
    ("gemini", {
        "candidates": [{"content": {"parts": [{"text": "answer"}]}}],
        "usageMetadata": {
            "promptTokenCount": 20, "candidatesTokenCount": 4, "thoughtsTokenCount": 3, "totalTokenCount": 27,
        },
    }, {"input_tokens": 20, "output_tokens": 7, "reasoning_tokens": 3, "total_tokens": 27}),
    ("openai", {
        "output_text": "answer",
        "usage": {"input_tokens": 20, "output_tokens": 7, "input_tokens_details": {"cached_tokens": 5}},
    }, {"input_tokens": 20, "output_tokens": 7, "cached_input_tokens": 5, "total_tokens": 27}),
    ("ollama", {
        "message": {"content": "answer"}, "prompt_eval_count": 20, "eval_count": 7,
    }, {"input_tokens": 20, "output_tokens": 7, "total_tokens": 27}),
])
def test_generation_records_provider_token_usage(monkeypatch, provider, payload, tokens):
    response = Mock()
    response.json.return_value = payload
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(return_value=response))
    llm = client.BenchmarkClient(Settings(gemini_api_key="test", openai_api_key="test"), 0, 0)

    assert llm.generate("", "Question", provider) == "answer"
    attempt, = llm.attempts
    assert {key: attempt[key] for key in attempt if key in client.TOKEN_FIELDS} == tokens


def test_cli_persists_baseline_before_rag_runs_and_keeps_it_after_interrupt(monkeypatch, run_cli):
    class InterruptedChatbot:
        def __init__(self, settings, llm, retriever):
            pass

        def ask(self, question, provider, top_k, **kwargs):
            baseline_path, = run_cli.glob("*/llm_only_results.jsonl")
            assert json.loads(baseline_path.read_text(encoding="utf-8"))["answer"] == f"Affected by {CVE}."
            raise KeyboardInterrupt

    monkeypatch.setattr(run, "RAGChatbot", InterruptedChatbot)
    assert run.main() == 130

    run_dir, = run_cli.iterdir()
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["stop_reason"] == "Interrupted"
    assert summary["paired_questions"] == 0
    assert summary["baseline"] is None
    assert (run_dir / "llm_only_results.jsonl").read_text(encoding="utf-8")
    assert (run_dir / "rag_results.jsonl").read_text(encoding="utf-8") == ""


def test_interrupted_question_keeps_attempted_llm_usage_in_logs_and_main_metrics(monkeypatch, run_cli):
    class InterruptedChatbot:
        def __init__(self, settings, llm, retriever):
            self.llm = llm

        def ask(self, question, provider, top_k, **kwargs):
            self.llm.generate("", question, provider)
            raise KeyboardInterrupt

    monkeypatch.setattr(run, "RAGChatbot", InterruptedChatbot)
    assert run.main() == 130
    run_dir, = run_cli.iterdir()
    summary = json.loads((run_dir / "summary.json").read_text())
    row = json.loads((run_dir / "rag_results.jsonl").read_text())
    assert row["error"] == "Interrupted"
    assert row["llm_requests"][0]["total_tokens"] == 27
    assert summary["llm_usage"]["rag"]["total_tokens"] == 27
    assert summary["llm_usage"]["rag"]["attempts"] == 1
    assert summary["failed_responses"]["rag"] == 1
    assert summary["scored_questions"] == 0


def test_cli_stops_after_provider_denies_access(monkeypatch, run_cli):
    attempts = []

    def generate(_, system_prompt, question, provider):
        attempts.append(question)
        response = requests.Response()
        response.status_code = 403
        raise requests.HTTPError("Access denied", response=response)

    monkeypatch.setattr(LLMClient, "generate", generate)
    assert run.main() == 1

    assert len(attempts) == 1
    run_dir, = run_cli.iterdir()
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["failed_responses"] == {"llm_only": 1, "rag": 0}
    assert summary["stop_reason"] == "LLM endpoint returned HTTP 403."


def test_benchmark_client_honors_retry_after_and_next_request_interval(monkeypatch):
    elapsed = 0.0
    request_times = []

    def sleep(seconds):
        nonlocal elapsed
        elapsed += seconds

    def generate(*args):
        request_times.append(elapsed)
        if len(request_times) == 1:
            response = requests.Response()
            response.status_code = 429
            response.headers["Retry-After"] = "11"
            raise requests.HTTPError(response=response)
        return "answer"

    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: elapsed, sleep=sleep))
    monkeypatch.setattr(LLMClient, "generate", generate)
    llm = client.BenchmarkClient(Settings(), request_interval=6, max_retries=2)

    assert llm.generate("", "B0") == llm.generate("", "B2") == "answer"
    assert request_times == [0, 11, 17]
    assert llm.wait_seconds == 17
    usage = client.summarize_usage(llm.attempts)
    assert usage["attempts"] == 3
    assert usage["failed_attempts"] == 1
    assert usage["input_tokens"] is None
    assert usage["reported_attempts"]["input_tokens"] == 0


def test_baseline_parses_same_structured_verdict_as_evidence_modes() -> None:
    answer = {
        "verdict": "affected",
        "answer": f"{CVE} bị ảnh hưởng. Khuyến nghị: nâng cấp lên bản không bị ảnh hưởng.",
        "asserted_cves": [CVE],
    }
    llm = Mock()
    llm.generate.return_value = json.dumps(answer)
    row = run.run_baseline({"question": "Question", "question_type": "cve_version_check"}, llm, "groq")
    assert row["predicted_status"] == "affected"
    assert row["asserted_cves"] == [CVE]
    assert row["answer"] == answer["answer"]
    assert row["raw_answer"] == llm.generate.return_value
    assert row["status_source"] == "structured_verdict"
    assert "asserted_cves" in llm.generate.call_args.args[0]


def test_evidence_runner_preserves_structured_verdict_and_filter_trace() -> None:
    response = {
        "status": "answered", "verdict": "affected", "asserted_cves": [CVE],
        "answer": f"{CVE} affected. Recommendation: use a version not affected.",
        "citations": [], "raw_answer": "raw-json", "answer_format": "structured",
    }
    row = run._run_with_evidence({"question_type": "cve_version_check"}, "rag", lambda: response)
    assert row["predicted_status"] == "affected"
    assert row["raw_answer"] == "raw-json"
    response.update({
        "status": "insufficient_evidence", "verdict": "insufficient_evidence", "asserted_cves": [],
        "model_verdict": "affected", "model_asserted_cves": [CVE],
        "rejected_cves": [CVE], "rejected_source_ids": ["S99"],
        "output_error": "unsupported_identifier_or_citation",
    })
    filtered = run._run_with_evidence({"question_type": "cve_version_check"}, "rag", lambda: response)
    assert filtered["model_verdict"] == "affected"
    assert filtered["model_asserted_cves"] == filtered["rejected_cves"] == [CVE]
    assert filtered["rejected_source_ids"] == ["S99"]
    assert filtered["predicted_status"] == "insufficient_evidence"


def test_malformed_baseline_envelope_is_an_error_not_a_legacy_success() -> None:
    llm = Mock()
    llm.generate.return_value = '{"verdict": "affected", "answer": "broken"'
    row = run.run_baseline({"question": "Question", "question_type": "cve_version_check"}, llm, "groq")
    assert row["predicted_status"] == "error"
    assert row["error"] == row["output_error"] == "invalid_structured_answer"
    assert row["raw_answer"] == llm.generate.return_value


def test_cli_can_require_reviewed_labels_before_making_requests(monkeypatch, run_cli):
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--require-reviewed"])
    with pytest.raises(SystemExit) as exc:
        run.main()
    assert exc.value.code == 2
    requests.post.assert_not_called()


@pytest.mark.parametrize(("raw_answer", "output_error", "accuracy", "filtered"), [
    (json.dumps({
        "verdict": "affected", "answer": f"{CVE} bị ảnh hưởng. Khuyến nghị: nâng cấp lên bản không bị ảnh hưởng [S1].",
        "asserted_cves": [CVE],
    }), None, 1, 0),
    ('{"verdict":"affected",', "invalid_structured_answer", 0, 0),
    (json.dumps({
        "verdict": "affected", "answer": "CVE-2099-99999 bị ảnh hưởng [S1].",
        "asserted_cves": ["CVE-2099-99999"],
    }), "unsupported_identifier_or_citation", 0, 1),
])
def test_real_chatbot_envelope_to_evaluation_scoring(raw_answer, output_error, accuracy, filtered) -> None:
    llm = Mock()
    llm.generate.return_value = raw_answer
    chatbot = run.RAGChatbot(Settings(), retriever=Mock(), llm=llm)
    item = {
        "question": f"Does {CVE} affect OpenSSH?", "question_type": "cve_version_check",
        "expected_cves": [CVE], "expected_status": "affected",
        "expected_source_urls": ["https://example.test/advisory"],
    }
    evidence = lambda _: ("Evidence", [{
        "source_id": "S1", "vulnerability_id": CVE, "url": "https://example.test/advisory",
    }])
    row = run.run_context_baseline(item, chatbot, "groq", "llm_bm25", evidence)
    assert row["raw_answer"] == raw_answer
    assert row.get("output_error") == output_error
    summary = summarize([row], {CVE})
    assert summary["cve_and_status_accuracy"] == accuracy
    assert summary["filtered_responses"] == filtered
    assert summary["output_format_errors"] == (output_error == "invalid_structured_answer")
