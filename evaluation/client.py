"""Rate pacing and transient HTTP retries for the benchmark client."""

from __future__ import annotations

import math
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import requests

from config.settings import Settings
from evaluation.performance import TOKEN_FIELDS, summarize_usage
from rag.generation.client import LLMClient


RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_RETRY_DELAY = 60


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _count(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _read_usage(provider: str, payload: dict[str, Any]) -> dict[str, int]:
    usage = _object(payload.get("usage"))
    if provider == "groq" and not usage:
        usage = _object(_object(payload.get("x_groq")).get("usage"))
    if provider == "gemini":
        usage = _object(payload.get("usageMetadata"))
        input_tokens = _count(usage.get("promptTokenCount"))
        total_tokens = _count(usage.get("totalTokenCount"))
        reasoning_tokens = _count(usage.get("thoughtsTokenCount"))
        candidates = _count(usage.get("candidatesTokenCount"))
        if input_tokens is not None and total_tokens is not None and total_tokens >= input_tokens:
            output_tokens = total_tokens - input_tokens
        else:
            output_tokens = candidates + (reasoning_tokens or 0) if candidates is not None else None
        cached_tokens = _count(usage.get("cachedContentTokenCount"))
    elif provider == "ollama":
        input_tokens = _count(payload.get("prompt_eval_count"))
        output_tokens = _count(payload.get("eval_count"))
        cached_tokens = _count(payload.get("prompt_eval_cached_count"))
        total_tokens = reasoning_tokens = None
    else:
        input_key, output_key = (
            ("prompt_tokens", "completion_tokens") if provider == "groq" else ("input_tokens", "output_tokens")
        )
        input_tokens = _count(usage.get(input_key))
        output_tokens = _count(usage.get(output_key))
        total_tokens = _count(usage.get("total_tokens"))
        reasoning_tokens = _count(_object(usage.get(f"{output_key}_details")).get("reasoning_tokens"))
        cached_tokens = _count(_object(usage.get(f"{input_key}_details")).get("cached_tokens"))
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    counts = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "reasoning_tokens": reasoning_tokens,
        "cached_input_tokens": cached_tokens,
    }
    return {field: value for field, value in counts.items() if value is not None}


def _retry_after(value: str) -> float:
    try:
        delay = float(value)
    except ValueError:
        try:
            retry_time = parsedate_to_datetime(value)
        except ValueError:
            return 0
        if retry_time.tzinfo is None:
            retry_time = retry_time.replace(tzinfo=UTC)
        delay = (retry_time - datetime.now(UTC)).total_seconds()
    return max(0, delay) if math.isfinite(delay) else 0


class BenchmarkClient(LLMClient):
    """Apply one pacing schedule to requests from both benchmark modes."""

    def __init__(self, settings: Settings, request_interval: float, max_retries: int) -> None:
        super().__init__(settings)
        self.request_interval = request_interval
        self.max_retries = max_retries
        self.wait_seconds = 0.0
        self.stop_reason: str | None = None
        self.attempts: list[dict[str, Any]] = []
        self._next_request = 0.0

    def _record_response(self, provider: str, payload: dict[str, Any]) -> None:
        self.attempts[-1].update(_read_usage(provider, payload))

    def _record_chunk(self, text: str) -> None:
        self.attempts[-1].setdefault("ttft_seconds", time.monotonic() - self._request_started)
        super()._record_chunk(text)

    def generate(self, system_prompt: str, user_prompt: str, provider: str | None = None) -> str:
        retries = 0
        while True:
            started_wait = time.monotonic()
            remaining = self._next_request - started_wait
            if remaining > 0:
                time.sleep(remaining)
                self.wait_seconds += time.monotonic() - started_wait
            request_started = time.monotonic()
            self._request_started = request_started
            self._next_request = request_started + self.request_interval
            attempt: dict[str, Any] = {"succeeded": False}
            self.attempts.append(attempt)

            try:
                answer = super().generate(system_prompt, user_prompt, provider)
                attempt["succeeded"] = True
                return answer
            except requests.HTTPError as exc:
                if exc.response is None:
                    raise
                status = exc.response.status_code
                if status in {401, 403, 404}:
                    self.stop_reason = f"LLM endpoint returned HTTP {status}."
                if status not in RETRYABLE_STATUS:
                    raise

                delay = max(6 * (retries + 1), _retry_after(exc.response.headers.get("Retry-After", "")))
                if retries >= self.max_retries or delay > MAX_RETRY_DELAY:
                    if status == 429:
                        self.stop_reason = "LLM rate limit exceeded the benchmark retry policy."
                    raise

                retries += 1
                now = time.monotonic()
                self._next_request = max(self._next_request, now + delay)
                wait = self._next_request - now
                print(f"LLM HTTP {status}, retry {retries}/{self.max_retries} scheduled after {wait:g}s", flush=True)
            finally:
                attempt["latency_seconds"] = time.monotonic() - request_started
