"""RAG chatbot orchestration and terminal interaction."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from config.settings import Settings, get_settings
from generation.client import LLMClient
from retrieval.parser import VULNERABILITY_ID_PATTERN
from retrieval.retriever import Retriever


PROMPTS_PATH = Path(__file__).with_name("prompts.json")


def load_prompts(path: Path = PROMPTS_PATH) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as file:
        prompts = json.load(file)
    required = {"rag_system_prompt", "rag_user_template", "baseline_system_prompt"}
    missing = required - prompts.keys()
    if missing:
        raise ValueError(f"Prompt file thiếu key: {sorted(missing)}")
    return {key: str(value) for key, value in prompts.items()}


class RAGChatbot:
    """Combine a retriever and a text-generation client."""

    def __init__(
        self,
        settings: Settings | None = None,
        retriever: Retriever | None = None,
        llm: LLMClient | None = None,
        prompts: dict[str, str] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.retriever = retriever or Retriever(self.settings)
        self.llm = llm or LLMClient(self.settings)
        self.prompts = prompts or load_prompts()

    def search(self, query: str, top_k: int | None = None) -> dict[str, Any]:
        return self.retriever.search(query, top_k).to_dict()

    def ask(
        self,
        question: str,
        provider: str | None = None,
        top_k: int | None = None,
    ) -> dict[str, Any]:
        bundle = self.retriever.search(question, top_k)
        parsed_query = asdict(bundle.query)
        matches = [asdict(match) for match in bundle.version_matches]

        if not bundle.results:
            return {
                "status": "insufficient_evidence",
                "answer": (
                    "Không tìm thấy bằng chứng đủ tin cậy trong dữ liệu đã lập chỉ mục. "
                    "Hệ thống không đưa ra kết luận về lỗ hổng."
                ),
                "parsed_query": parsed_query,
                "matches": matches,
                "citations": [],
            }

        context, citations = self.retriever.format_context(bundle)
        user_prompt = self.prompts["rag_user_template"].format(
            question=bundle.query.original,
            context=context,
        )
        try:
            answer = self.llm.generate(
                self.prompts["rag_system_prompt"],
                user_prompt,
                provider,
            )
        except Exception as exc:
            return {
                "status": "error",
                "answer": f"Không thể gọi LLM: {exc}",
                "parsed_query": parsed_query,
                "matches": matches,
                "citations": citations,
            }

        allowed_ids = {
            result.vulnerability_id.upper() for result in bundle.results
        }
        mentioned_ids = {
            match.group(0).upper()
            for match in VULNERABILITY_ID_PATTERN.finditer(answer)
        }
        if mentioned_ids - allowed_ids:
            return {
                "status": "insufficient_evidence",
                "answer": (
                    "Phản hồi của mô hình đã bị loại vì chứa mã lỗ hổng "
                    "không có trong bằng chứng truy xuất."
                ),
                "parsed_query": parsed_query,
                "matches": matches,
                "citations": citations,
            }

        return {
            "status": "answered",
            "answer": self._append_sources(answer, citations),
            "parsed_query": parsed_query,
            "matches": matches,
            "citations": citations,
        }

    @staticmethod
    def _append_sources(answer: str, citations: list[dict[str, str]]) -> str:
        if not citations:
            return answer
        lines = ["", "Nguồn kiểm chứng:"]
        lines.extend(
            f"- [{item['source_id']}] {item['vulnerability_id']}: {item['url']}"
            for item in citations
        )
        return answer.rstrip() + "\n" + "\n".join(lines)


def _print_response(response: dict[str, Any]) -> None:
    print(f"\nBot [{response['status']}]:\n{response['answer']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Chat with NetVuln RAG")
    parser.add_argument("--text", help="Send one question and exit")
    parser.add_argument("--provider")
    parser.add_argument("--top-k", type=int)
    args = parser.parse_args()

    settings = get_settings()
    chatbot = RAGChatbot(settings)
    provider = args.provider or settings.llm_provider
    top_k = args.top_k or settings.top_k

    if args.text:
        _print_response(chatbot.ask(args.text, provider=provider, top_k=top_k))
        return 0

    print("NetVuln RAG CLI")
    supported = "|".join(chatbot.llm.supported_providers)
    print(f"Commands: /provider {supported}, /topk N, /exit")
    print(f"Provider: {provider}; top_k: {top_k}")
    while True:
        try:
            question = input("\nBạn: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nĐã thoát.")
            return 0

        if not question:
            continue
        if question.lower() in {"/exit", "/quit"}:
            print("Đã thoát.")
            return 0
        if question.startswith("/provider "):
            candidate = question.split(maxsplit=1)[1].strip().lower()
            if candidate not in chatbot.llm.supported_providers:
                supported = ", ".join(chatbot.llm.supported_providers)
                print(f"Provider hợp lệ: {supported}")
                continue
            provider = candidate
            print(f"Đã chọn provider: {provider}")
            continue
        if question.startswith("/topk "):
            try:
                top_k = max(1, min(20, int(question.split(maxsplit=1)[1])))
            except ValueError:
                print("Top-K phải là số nguyên từ 1 đến 20.")
                continue
            print(f"Đã đặt top_k={top_k}")
            continue

        _print_response(chatbot.ask(question, provider=provider, top_k=top_k))


if __name__ == "__main__":
    raise SystemExit(main())
