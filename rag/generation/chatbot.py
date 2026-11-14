"""RAG chatbot orchestration and terminal interaction."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from config.settings import Settings, get_settings
from rag.generation.answers import STRUCTURED_ANSWER_INSTRUCTION, parse_answer
from rag.generation.client import LLMClient
from rag.identifiers import find_cve_ids
from rag.retrieval.models import QueryIntent
from rag.retrieval.retriever import Retriever


PROMPTS_PATH = Path(__file__).with_name("prompts.json")
SOURCE_LIST_SEPARATOR = "\n\nNguồn kiểm chứng:\n"
CITATION_PATTERN = re.compile(r"[\[【]\s*(S[0-9]+)\s*[\]】]", re.IGNORECASE)


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
        *,
        max_context_chars: int | None = None,
    ) -> dict[str, Any]:
        bundle = self.retriever.search(question, top_k)
        context, sources = self.retriever.format_context(bundle, max_chars=max_context_chars)
        response = self.answer_with_evidence(bundle.query.original, context, sources, provider)
        if (
            bundle.query.intent == QueryIntent.VULNERABILITY_CHECK
            and len(bundle.version_matches) == 1
            and response.get("answer_format") == "structured"
            and response.get("status") == "answered"
            and response.get("verdict") in {"affected", "not_affected"}
            and response["verdict"] != bundle.version_matches[0].status.value
        ):
            response = {
                **response,
                "status": "insufficient_evidence",
                "model_verdict": response["verdict"],
                "model_asserted_cves": response.get("asserted_cves"),
                "verdict": "insufficient_evidence",
                "asserted_cves": [],
                "answer": "Phản hồi của mô hình đã bị loại vì kết luận trái với bằng chứng phiên bản.",
                "output_error": "version_verdict_conflict",
                "citations": [],
            }
        return {
            **response,
            "parsed_query": asdict(bundle.query),
            "matches": [asdict(match) for match in bundle.version_matches],
        }

    def answer_with_evidence(
        self,
        question: str,
        context: str,
        sources: list[dict[str, str]],
        provider: str | None = None,
    ) -> dict[str, Any]:
        allowed_ids = {source["vulnerability_id"].upper() for source in sources}
        metadata = {"retrieved_evidence_cves": sorted(allowed_ids)}
        if not sources:
            return {
                "status": "insufficient_evidence",
                "verdict": "insufficient_evidence",
                "asserted_cves": [],
                "answer_format": "deterministic",
                "verdict_source": "no_evidence",
                "answer": (
                    "Không tìm thấy bằng chứng đủ tin cậy trong dữ liệu đã lập chỉ mục. "
                    "Hệ thống không đưa ra kết luận về lỗ hổng."
                ),
                **metadata,
                "citations": [],
            }

        user_prompt = self.prompts["rag_user_template"].format(question=question, context=context)
        try:
            raw_answer = self.llm.generate(
                self.prompts["rag_system_prompt"] + "\n\n" + STRUCTURED_ANSWER_INSTRUCTION,
                user_prompt,
                provider,
            )
        except Exception as exc:
            return {
                "status": "error",
                "answer": f"Không thể gọi LLM: {exc}",
                **metadata,
                "citations": [],
            }

        parsed = parse_answer(raw_answer)
        trace = {
            "raw_answer": raw_answer,
            "answer_format": "structured" if parsed.structured else "legacy",
            "verdict_source": "structured" if parsed.structured else "legacy_text",
            "verdict": parsed.verdict,
            "asserted_cves": list(parsed.asserted_cves) if parsed.asserted_cves is not None else None,
        }
        if parsed.error:
            return {
                "status": "error",
                "answer": "Phản hồi của mô hình không đúng định dạng kết quả yêu cầu.",
                **metadata,
                **trace,
                "output_error": parsed.error,
                "citations": [],
            }
        answer = parsed.answer
        cited_ids = {source_id.upper() for source_id in CITATION_PATTERN.findall(answer)}
        allowed_source_ids = {item["source_id"] for item in sources}
        if set(find_cve_ids(answer)) - allowed_ids or cited_ids - allowed_source_ids:
            return {
                "status": "insufficient_evidence",
                "answer": (
                    "Phản hồi của mô hình đã bị loại vì chứa mã lỗ hổng hoặc "
                    "tham chiếu nguồn không có trong bằng chứng truy xuất."
                ),
                **metadata,
                **trace,
                "verdict": "insufficient_evidence",
                "model_verdict": parsed.verdict,
                "model_asserted_cves": trace["asserted_cves"],
                "asserted_cves": [],
                "output_error": "unsupported_identifier_or_citation",
                "rejected_cves": sorted(set(find_cve_ids(answer)) - allowed_ids),
                "rejected_source_ids": sorted(cited_ids - allowed_source_ids),
                "citations": [],
            }

        citations = [item for item in sources if item["source_id"] in cited_ids]
        return {
            "status": "answered",
            "answer": self._append_sources(answer, citations),
            **metadata,
            **trace,
            "citations": citations,
        }

    @staticmethod
    def _append_sources(answer: str, citations: list[dict[str, str]]) -> str:
        if not citations:
            return answer
        lines = [
            f"- [{item['source_id']}] {item['vulnerability_id']}: {item['url']}"
            for item in citations
        ]
        return answer.rstrip() + SOURCE_LIST_SEPARATOR + "\n".join(lines)


def _print_response(response: dict[str, Any]) -> None:
    print(f"\nBot [{response['status']}]:\n{response['answer']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Chat with NetVuln RAG")
    parser.add_argument("--text", help="Send one question and exit")
    parser.add_argument("--provider")
    parser.add_argument("--top-k", type=int)
    parser.add_argument("--stream", action="store_true", help="Show live LLM output before the final checked answer")
    args = parser.parse_args()

    settings = get_settings()
    chatbot = RAGChatbot(settings)
    if args.stream:
        chatbot.llm.on_chunk = lambda text: print(text, end="", flush=True)
    provider = args.provider or settings.llm_provider
    top_k = args.top_k or settings.top_k

    if args.text:
        if args.stream:
            print("LLM draft (streaming; final validation follows):", flush=True)
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

        if args.stream:
            print("LLM draft (streaming; final validation follows):", flush=True)
        _print_response(chatbot.ask(question, provider=provider, top_k=top_k))


if __name__ == "__main__":
    raise SystemExit(main())
