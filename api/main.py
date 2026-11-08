"""FastAPI entry point for a future web UI."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, StringConstraints, field_validator

from rag.generation.chatbot import RAGChatbot
from rag.generation.client import LLMClient


QueryText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class ChatRequest(BaseModel):
    question: QueryText
    provider: str | None = None
    top_k: int | None = Field(default=None, ge=1, le=20)

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str | None) -> str | None:
        if value is None:
            return None
        provider = value.strip().lower()
        if provider not in LLMClient.supported_providers:
            raise ValueError("Unknown language model provider")
        return provider


class SearchRequest(BaseModel):
    query: QueryText
    top_k: int | None = Field(default=None, ge=1, le=20)


@lru_cache(maxsize=1)
def get_chatbot() -> RAGChatbot:
    return RAGChatbot()


app = FastAPI(
    title="NetVuln RAG API",
    description="Tra cứu lỗ hổng thiết bị mạng có trích dẫn.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health(response: Response, chatbot: RAGChatbot = Depends(get_chatbot)) -> dict[str, Any]:
    try:
        return {"status": "healthy", **chatbot.retriever.health()}
    except Exception:
        response.status_code = 503
        return {"status": "degraded", "detail": "Corpus or vector store unavailable"}


@app.post("/search")
def search(
    request: SearchRequest,
    chatbot: RAGChatbot = Depends(get_chatbot),
) -> dict[str, Any]:
    try:
        return chatbot.search(request.query, request.top_k)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Search failed") from exc


@app.post("/chat")
def chat(
    request: ChatRequest,
    chatbot: RAGChatbot = Depends(get_chatbot),
) -> dict[str, Any]:
    try:
        result = chatbot.ask(request.question, request.provider, request.top_k)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="RAG pipeline failed") from exc
    if result["status"] == "error":
        raise HTTPException(status_code=502, detail="Language model request failed")
    return result
