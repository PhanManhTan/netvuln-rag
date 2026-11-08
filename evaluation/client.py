"""Rate pacing and transient HTTP retries for the benchmark client."""

from __future__ import annotations

import math
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import requests

from config.settings import Settings
from rag.generation.client import LLMClient


RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_RETRY_DELAY = 60


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
        self._next_request = 0.0

    def generate(self, system_prompt: str, user_prompt: str, provider: str | None = None) -> str:
        retries = 0
        while True:
            started_wait = time.monotonic()
            remaining = self._next_request - started_wait
            if remaining > 0:
                time.sleep(remaining)
                self.wait_seconds += time.monotonic() - started_wait
            self._next_request = time.monotonic() + self.request_interval

            try:
                return super().generate(system_prompt, user_prompt, provider)
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
