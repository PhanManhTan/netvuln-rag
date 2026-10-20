"""Provider-neutral text generation client."""

from __future__ import annotations

from typing import Any

import requests

from rag_system.config import Settings, get_settings


class LLMClient:
    """Dispatch text generation to the configured provider."""

    supported_providers = ("ollama", "openai")

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
            "ollama": self.settings.ollama_model,
            "openai": self.settings.openai_model,
        }
        return models.get(selected, selected)

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
        content = response.json().get("message", {}).get("content", "").strip()
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
        return self._read_openai_text(response.json())

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
