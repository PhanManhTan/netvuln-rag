"""Provider-neutral text generation client."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

from config.settings import Settings, get_settings


class LLMClient:
    """Dispatch text generation to the configured provider."""

    supported_providers = ("gemini", "groq", "ollama", "openai")

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

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
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{quote(model, safe='')}:generateContent",
            headers={"x-goog-api-key": self.settings.gemini_api_key},
            json=payload,
            timeout=self.settings.llm_timeout,
            allow_redirects=False,
        )
        response.raise_for_status()
        result = response.json()
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
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.settings.groq_api_key}"},
            json=payload,
            timeout=self.settings.llm_timeout,
            allow_redirects=False,
        )
        response.raise_for_status()
        result = response.json()
        self._record_response("groq", result)
        choice = next(iter(result.get("choices") or []), {})
        text = (choice.get("message", {}).get("content") or "").strip()
        if not text:
            raise RuntimeError("Groq trả về nội dung rỗng.")
        return text

    def _generate_ollama(self, system_prompt: str, user_prompt: str) -> str:
        response = requests.post(
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
        response.raise_for_status()
        result = response.json()
        self._record_response("ollama", result)
        content = result.get("message", {}).get("content", "").strip()
        if not content:
            raise RuntimeError("Ollama trả về nội dung rỗng.")
        return content

    def _generate_openai(self, system_prompt: str, user_prompt: str) -> str:
        if not self.settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY chưa được cấu hình.")
        response = requests.post(
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
        response.raise_for_status()
        result = response.json()
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
