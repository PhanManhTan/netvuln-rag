"""Shared data contracts for retrieval and version evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from data_pipeline.versioning import MatchStatus, VersionDecision


class QueryIntent(str, Enum):
    VULNERABILITY_CHECK = "vulnerability_check"
    VERSION_INVENTORY = "version_inventory"
    VULNERABILITY_DETAIL = "vulnerability_detail"
    SEMANTIC = "semantic"


@dataclass(frozen=True)
class ParsedQuery:
    original: str
    intent: QueryIntent
    vulnerability_id: str | None = None
    product_id: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class SearchResult:
    point_id: str
    score: float
    vulnerability_id: str
    section: str
    text: str
    source_url: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchBundle:
    query: ParsedQuery
    results: list[SearchResult]
    version_matches: list[VersionDecision]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
