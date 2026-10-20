"""FastAPI entry point for a future web UI."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from llm.chatbot import RAGChatbot


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    provider: str | None = None
    top_k: int | None = Field(default=None, ge=1, le=20)


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
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
def health(chatbot: RAGChatbot = Depends(get_chatbot)) -> dict[str, Any]:
    try:
        return {"status": "healthy", **chatbot.retriever.health()}
    except Exception as exc:
        return {"status": "degraded", "detail": str(exc)}


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
        return chatbot.ask(request.question, request.provider, request.top_k)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="RAG pipeline failed") from exc
