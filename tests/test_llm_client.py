from unittest.mock import Mock

import pytest

from config.settings import Settings
from rag.generation.client import LLMClient


def test_gemini_uses_configured_model_and_extracts_answer(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    response = Mock()
    response.json.return_value = {
        "candidates": [{
            "content": {
                "parts": [
                    {"text": "Internal draft", "thought": True},
                    {"text": "First "},
                    {"text": "answer."},
                ],
            },
        }],
    }
    post = Mock(return_value=response)
    monkeypatch.setattr("rag.generation.client.requests.post", post)
    client = LLMClient(Settings(llm_timeout=20))

    assert client.model_name() == "gemini-3.8-flash"
    assert client.generate("Use the evidence.", "What is affected?") == "First answer."
    response.raise_for_status.assert_called_once()
    post.assert_called_once_with(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent",
        headers={"x-goog-api-key": "test-key"},
        json={
            "contents": [{"role": "user", "parts": [{"text": "What is affected?"}]}],
            "systemInstruction": {"parts": [{"text": "Use the evidence."}]},
        },
        timeout=20,
        allow_redirects=False,
    )


def test_gemini_requires_api_key_before_request(monkeypatch) -> None:
    post = Mock()
    monkeypatch.setattr("rag.generation.client.requests.post", post)
    client = LLMClient(Settings(llm_provider="gemini", gemini_api_key=""))

    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        client.generate("Use the evidence.", "What is affected?")
    post.assert_not_called()


def test_gemini_reports_blocked_response(monkeypatch) -> None:
    response = Mock()
    response.json.return_value = {"promptFeedback": {"blockReason": "SAFETY"}}
    monkeypatch.setattr("rag.generation.client.requests.post", Mock(return_value=response))
    client = LLMClient(Settings(gemini_api_key="test-key"))

    with pytest.raises(RuntimeError, match="SAFETY"):
        client.generate("", "What is affected?", provider="gemini")


def test_groq_uses_configured_api_model(monkeypatch) -> None:
    response = Mock()
    response.json.return_value = {"choices": [{"message": {"content": "An answer."}}]}
    post = Mock(return_value=response)
    monkeypatch.setattr("rag.generation.client.requests.post", post)
    client = LLMClient(Settings(groq_api_key="test-key", groq_model="openai/gpt-oss-120b"))

    assert client.generate("Use the evidence.", "What is affected?", provider="groq") == "An answer."
    assert client.model_name("groq") == "openai/gpt-oss-120b"
    assert post.call_args.args[0] == "https://api.groq.com/openai/v1/chat/completions"
    assert post.call_args.kwargs["json"]["reasoning_effort"] == "low"
