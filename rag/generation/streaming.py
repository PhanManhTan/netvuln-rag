"""Read SSE/NDJSON generation events without buffering the entire response."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import requests


def _decode(data: str) -> dict[str, Any] | None:
    if data == "[DONE]":
        return None
    event = json.loads(data)
    if not isinstance(event, dict):
        raise RuntimeError("LLM stream returned an invalid event.")
    return event


def _events(response: requests.Response, *, ndjson: bool) -> Iterator[dict[str, Any] | None]:
    data: list[str] = []
    # SSE is UTF-8; small reads prevent requests from delaying short deltas.
    response.encoding = "utf-8"
    for line in response.iter_lines(chunk_size=1, decode_unicode=True):
        if isinstance(line, bytes):
            line = line.decode("utf-8")
        if ndjson:
            if line.strip():
                yield _decode(line)
        elif not line:
            if data:
                yield _decode("\n".join(data))
                data = []
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    if data:
        yield _decode("\n".join(data))


def consume_stream(
    provider: str,
    response: requests.Response,
    record_response: Callable[[str, dict[str, Any]], None],
    emit_text: Callable[[str], None],
) -> dict[str, Any]:
    parts: list[str] = []
    result: dict[str, Any] = {}
    completed = False
    for event in _events(response, ndjson=provider == "ollama"):
        if event is None:
            if provider == "groq":
                completed = True
            break
        payload = (event.get("response") or {}) if provider == "openai" else event
        record_response(provider, payload)
        error = event.get("error") or (event.get("x_groq") or {}).get("error")
        if event.get("type") in {"response.failed", "response.incomplete", "error"}:
            error = error or payload.get("error") or payload.get("incomplete_details") or event.get("message") or event["type"]
        if error:
            message = (error.get("message") or error.get("reason") or "LLM stream failed") if isinstance(error, dict) else str(error)
            raise RuntimeError(message)

        text = ""
        if provider == "groq":
            result.update(event)
            choice = next(iter(event.get("choices") or []), {})
            text = (choice.get("delta") or {}).get("content") or ""
        elif provider == "gemini":
            result.update(event)
            if (event.get("promptFeedback") or {}).get("blockReason"):
                raise RuntimeError(f"Gemini: {event['promptFeedback']['blockReason']}")
            candidate = next(iter(event.get("candidates") or []), {})
            text = "".join(p.get("text", "") for p in (candidate.get("content") or {}).get("parts", []) if not p.get("thought"))
            completed = completed or bool(candidate.get("finishReason"))
        elif provider == "ollama":
            result.update(event)
            text = (event.get("message") or {}).get("content") or ""
            completed = event.get("done") is True
        elif event.get("type") == "response.output_text.delta":
            text = event.get("delta") or ""
        elif event.get("type") == "response.completed":
            result = payload
            completed = True
        if text:
            parts.append(text)
            emit_text(text)
        if completed and provider in {"ollama", "openai"}:
            break

    if not completed:
        raise RuntimeError("LLM stream ended before completion.")
    text = "".join(parts)
    if provider == "groq":
        result["choices"] = [{"message": {"content": text}}]
    elif provider == "gemini":
        candidate = next(iter(result.get("candidates") or []), {})
        result["candidates"] = [{**candidate, "content": {"parts": [{"text": text}]}}]
    elif provider == "ollama":
        result["message"] = {"content": text}
    else:
        result["output_text"] = text
    return result
