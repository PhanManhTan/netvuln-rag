"""Provider-neutral text generation client."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import requests

from config.settings import Settings, get_settings
from rag.generation.streaming import consume_stream


class LLMClient:
    """Dispatch text generation to the configured provider."""

    supported_providers = ("gemini", "groq", "ollama", "openai")

    def __init__(self, settings: Settings | None = None, *, on_chunk: Callable[[str], None] | None = None) -> None:
        self.settings = settings or get_settings()
        self.on_chunk = on_chunk

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        provider: str | None = None,
    ) -> str:
        selected = (provider or self.settings.llm_provider).strip().lower()
        generators = {
            "gemini": self._generate_gemini,
            "groq": self._generate_groq,
            "ollama": self._generate_ollama,
            "openai": self._generate_openai,
        }
        try:
            generate = generators[selected]
        except KeyError as exc:
            supported = ", ".join(self.supported_providers)
            raise ValueError(
                f"LLM provider {selected!r} chưa được hỗ trợ. Có: {supported}"
            ) from exc
        return generate(system_prompt, user_prompt)

    def model_name(self, provider: str | None = None) -> str:
        """Return the configured model without leaking provider logic to callers."""
        selected = (provider or self.settings.llm_provider).strip().lower()
        models = {
            "gemini": self.settings.gemini_model,
            "groq": self.settings.groq_model,
            "ollama": self.settings.ollama_model,
            "openai": self.settings.openai_model,
        }
        return models.get(selected, selected)

    def _record_response(self, provider: str, payload: dict[str, Any]) -> None:
        """Allow benchmark callers to observe usage from a successful HTTP response."""

    def _record_chunk(self, text: str) -> None:
        if self.on_chunk is not None:
            self.on_chunk(text)

    def _request_json(self, provider: str, url: str, **kwargs: Any) -> dict[str, Any]:
        streaming = self.on_chunk is not None
        if streaming:
            kwargs["stream"] = True
            if provider == "gemini":
                url = url.replace(":generateContent", ":streamGenerateContent?alt=sse")
            else:
                kwargs["json"]["stream"] = True
        response = requests.post(url, **kwargs)
        try:
            response.raise_for_status()
            if streaming:
                return consume_stream(provider, response, self._record_response, self._record_chunk)
            return response.json()
        finally:
            response.close()

    def _generate_gemini(self, system_prompt: str, user_prompt: str) -> str:
        if not self.settings.gemini_api_key:
            raise ValueError("GEMINI_API_KEY chưa được cấu hình.")
        model = self.settings.gemini_model.removeprefix("models/")
        if not model:
            raise ValueError("GEMINI_MODEL chưa được cấu hình.")

        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}
        result = self._request_json(
            "gemini",
            f"https://generativelanguage.googleapis.com/v1beta/models/{quote(model, safe='')}:generateContent",
            headers={"x-goog-api-key": self.settings.gemini_api_key},
            json=payload,
            timeout=self.settings.llm_timeout,
            allow_redirects=False,
        )
        self._record_response("gemini", result)
        candidate = next(iter(result.get("candidates") or []), {})
        parts = (candidate.get("content") or {}).get("parts", [])
        text = "".join(part.get("text", "") for part in parts if not part.get("thought")).strip()
        if not text:
            reason = result.get("promptFeedback", {}).get("blockReason") or candidate.get("finishReason")
            detail = f" ({reason})" if reason else ""
            raise RuntimeError(f"Gemini trả về nội dung rỗng{detail}.")
        return text

    def _generate_groq(self, system_prompt: str, user_prompt: str) -> str:
        if not self.settings.groq_api_key:
            raise ValueError("GROQ_API_KEY chưa được cấu hình.")
        model = self.settings.groq_model
        if not model:
            raise ValueError("GROQ_MODEL chưa được cấu hình.")
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_completion_tokens": self.settings.llm_max_output_tokens,
        }
        if model in {"openai/gpt-oss-20b", "openai/gpt-oss-120b"}:
            payload["reasoning_effort"] = "low"
            payload["reasoning_format"] = "hidden"
        result = self._request_json(
            "groq",
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.settings.groq_api_key}"},
            json=payload,
            timeout=self.settings.llm_timeout,
            allow_redirects=False,
        )
        self._record_response("groq", result)
        choice = next(iter(result.get("choices") or []), {})
        text = (choice.get("message", {}).get("content") or "").strip()
        if not text:
            raise RuntimeError("Groq trả về nội dung rỗng.")
        return text

    def _generate_ollama(self, system_prompt: str, user_prompt: str) -> str:
        result = self._request_json(
            "ollama",
            f"{self.settings.ollama_url.rstrip('/')}/api/chat",
            json={
                "model": self.settings.ollama_model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "options": {"temperature": 0.1},
            },
            timeout=self.settings.llm_timeout,
        )
        self._record_response("ollama", result)
        content = result.get("message", {}).get("content", "").strip()
        if not content:
            raise RuntimeError("Ollama trả về nội dung rỗng.")
        return content

    def _generate_openai(self, system_prompt: str, user_prompt: str) -> str:
        if not self.settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY chưa được cấu hình.")
        result = self._request_json(
            "openai",
            "https://api.openai.com/v1/responses",
            headers={
                "Authorization": f"Bearer {self.settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.settings.openai_model,
                "instructions": system_prompt,
                "input": user_prompt,
            },
            timeout=self.settings.llm_timeout,
        )
        self._record_response("openai", result)
        return self._read_openai_text(result)

    @staticmethod
    def _read_openai_text(payload: dict[str, Any]) -> str:
        if payload.get("output_text"):
            return str(payload["output_text"]).strip()

        parts: list[str] = []
        for item in payload.get("output", []):
            for content in item.get("content", []):
                if content.get("type") == "output_text" and content.get("text"):
                    parts.append(str(content["text"]))
        text = "\n".join(parts).strip()
        if not text:
            raise RuntimeError("OpenAI trả về nội dung rỗng.")
        return text
