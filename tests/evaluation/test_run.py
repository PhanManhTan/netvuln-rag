import json
import sys
from types import SimpleNamespace

import pytest
import requests

from config.settings import Settings
from evaluation import client, run
from rag.generation.client import LLMClient


CVE = "CVE-2023-51384"


@pytest.fixture
def run_cli(monkeypatch, tmp_path):
    processed_dir = tmp_path / "processed"
    processed_dir.mkdir()
    (processed_dir / "structured.jsonl").touch()
    (processed_dir / "chunks.jsonl").touch()
    settings = Settings(artifacts_dir=tmp_path, processed_data_dir=processed_dir, groq_api_key="test-key")
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
    monkeypatch.setattr(LLMClient, "generate", lambda *args: f"Affected by {CVE}.")
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

        def ask(self, question, provider, top_k):
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
    assert answers[1]["error"] == "Index unavailable"


def test_cli_persists_baseline_before_rag_runs_and_keeps_it_after_interrupt(monkeypatch, run_cli):
    class InterruptedChatbot:
        def __init__(self, settings, llm, retriever):
            pass

        def ask(self, question, provider, top_k):
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
