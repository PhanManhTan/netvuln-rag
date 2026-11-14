import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from config.settings import Settings
from evaluation import client
from rag.generation.client import LLMClient


def response_stream(events, *, ndjson=False):
    response = Mock()
    lines = []
    for event in events:
        data = event if isinstance(event, str) else json.dumps(event, ensure_ascii=False)
        lines.extend([data] if ndjson else [f"data: {data}", ""])
    response.iter_lines.return_value = iter(lines)
    return response


@pytest.mark.parametrize(("provider", "events", "tokens"), [
    ("groq", [
        {"choices": [{"delta": {"role": "assistant", "reasoning": "internal"}}]},
        {"choices": [{"delta": {"content": "Xin "}}]},
        {"choices": [{"delta": {"content": "chào."}}]},
        {"choices": [], "x_groq": {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}},
        "[DONE]",
    ], 15),
    ("gemini", [
        {"candidates": [{"content": {"parts": [{"text": "internal", "thought": True}]}}]},
        {"candidates": [{"content": {"parts": [{"text": "Xin "}]}}]},
        {"candidates": [{"content": {"parts": [{"text": "chào."}]}, "finishReason": "STOP"}],
         "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15}},
    ], 15),
    ("ollama", [
        {"message": {"thinking": "internal"}, "done": False},
        {"message": {"content": "Xin "}, "done": False},
        {"message": {"content": "chào."}, "done": False},
        {"message": {"content": ""}, "done": True, "prompt_eval_count": 10, "eval_count": 5},
    ], 15),
    ("openai", [
        {"type": "response.created", "response": {"usage": None}},
        {"type": "response.reasoning_summary_text.delta", "delta": "internal"},
        {"type": "response.output_text.delta", "delta": "Xin "},
        {"type": "response.output_text.delta", "delta": "chào."},
        {"type": "response.completed", "response": {"usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}}},
    ], 15),
])
def test_stream_collects_text_and_final_usage_for_each_provider(monkeypatch, provider, events, tokens):
    response = response_stream(events, ndjson=provider == "ollama")
    post = Mock(return_value=response)
    monkeypatch.setattr("rag.generation.client.requests.post", post)
    llm = client.BenchmarkClient(Settings(groq_api_key="test", gemini_api_key="test", openai_api_key="test"), 0, 0)
    chunks = []
    llm.on_chunk = chunks.append

    assert llm.generate("Use the evidence.", "Question", provider) == "Xin chào."
    assert chunks == ["Xin ", "chào."]
    attempt, = llm.attempts
    assert attempt["succeeded"] is True
    assert attempt["total_tokens"] == tokens
    assert 0 <= attempt["ttft_seconds"] <= attempt["latency_seconds"]
    assert post.call_args.kwargs["stream"] is True
    if provider == "gemini":
        assert ":streamGenerateContent?alt=sse" in post.call_args.args[0]
        assert "stream" not in post.call_args.kwargs["json"]
    else:
        assert post.call_args.kwargs["json"]["stream"] is True
    response.json.assert_not_called()
    response.close.assert_called_once()


def test_text_is_emitted_before_next_event_and_ttft_ignores_metadata_and_reasoning(monkeypatch):
    elapsed = [0.0]
    chunks = []
    response = Mock()

    def lines(**kwargs):
        elapsed[0] = 0.1
        yield 'data: {"choices":[{"delta":{"role":"assistant","reasoning":"internal"}}]}'
        yield ""
        assert chunks == []
        elapsed[0] = 0.4
        yield 'data: {"choices":[{"delta":{"content":"Xin "}}]}'
        yield ""
        assert chunks == ["Xin "]  # The next server event has not arrived yet.
        elapsed[0] = 0.8
        yield 'data: {"choices":[{"delta":{"content":"chào."}}]}'
        yield ""
        assert chunks == ["Xin ", "chào."]
        elapsed[0] = 1.2
        yield "data: [DONE]"
        yield ""

    response.iter_lines.side_effect = lines
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(return_value=response))
    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: elapsed[0]))
    llm = client.BenchmarkClient(Settings(groq_api_key="test"), 0, 0)
    llm.on_chunk = chunks.append
    assert llm.generate("", "Question", "groq") == "Xin chào."
    assert llm.attempts[0]["ttft_seconds"] == 0.4
    assert llm.attempts[0]["latency_seconds"] == 1.2


@pytest.mark.parametrize(("provider", "events", "message"), [
    ("groq", [{"choices": [{"delta": {"content": "partial"}}]}], "before completion"),
    ("groq", [{"x_groq": {"error": "Capacity exceeded"}}], "Capacity exceeded"),
    ("openai", [{"type": "response.incomplete", "response": {"incomplete_details": {"reason": "max_output_tokens"}}}], "max_output_tokens"),
    ("openai", [{"type": "response.failed", "response": {"error": {"message": "Upstream failure"}}}], "Upstream failure"),
    ("gemini", [{"promptFeedback": {"blockReason": "SAFETY"}}], "SAFETY"),
    ("ollama", [{"message": {"content": "partial"}, "done": False}], "before completion"),
])
def test_stream_failures_do_not_return_partial_text_as_a_completed_answer(monkeypatch, provider, events, message):
    response = response_stream(events, ndjson=provider == "ollama")
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(return_value=response))
    llm = client.BenchmarkClient(Settings(groq_api_key="test", gemini_api_key="test", openai_api_key="test"), 0, 0)
    llm.on_chunk = lambda text: None
    with pytest.raises(RuntimeError, match=message):
        llm.generate("", "Question", provider)
    assert llm.attempts[0]["succeeded"] is False
    response.close.assert_called_once()


def test_sse_multiline_events_comments_and_utf8_bytes(monkeypatch):
    response = Mock()
    response.iter_lines.return_value = iter([
        b": keepalive", b"event: message", b"data: {\"choices\":",
        'data: [{"delta":{"content":"Tiếng Việt"}}]}'.encode(),
        b"", b"data: [DONE]", b"",
    ])
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(return_value=response))
    chunks = []
    llm = LLMClient(Settings(groq_api_key="test"), on_chunk=chunks.append)
    assert llm.generate("", "Question", "groq") == "Tiếng Việt"
    assert chunks == ["Tiếng Việt"]


def test_stream_http_failure_still_retries_and_closes_both_connections(monkeypatch):
    limited = Mock()
    status = requests.Response()
    status.status_code = 429
    limited.raise_for_status.side_effect = requests.HTTPError(response=status)
    succeeded = response_stream([{"choices": [{"delta": {"content": "Answer"}}]}, "[DONE]"])
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(side_effect=[limited, succeeded]))
    elapsed = [0.0]
    monkeypatch.setattr(client, "time", SimpleNamespace(
        monotonic=lambda: elapsed[0], sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
    ))
    llm = client.BenchmarkClient(Settings(groq_api_key="test"), 0, 1)
    llm.on_chunk = lambda text: None
    assert llm.generate("", "Question", "groq") == "Answer"
    assert len(llm.attempts) == 2
    assert "ttft_seconds" not in llm.attempts[0]
    assert "ttft_seconds" in llm.attempts[1]
    limited.close.assert_called_once()
    succeeded.close.assert_called_once()
