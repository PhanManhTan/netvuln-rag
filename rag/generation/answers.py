"""Shared answer envelope, independent of provider-specific API features."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from rag.identifiers import find_cve_ids, normalize_dashes


ANSWER_SCHEMA_VERSION = "1.0"
VERDICTS = frozenset({"affected", "not_affected", "insufficient_evidence", "answered"})
STRUCTURED_ANSWER_INSTRUCTION = """
Return exactly one JSON object, without Markdown fences or surrounding text:
{"verdict": "affected|not_affected|insufficient_evidence", "answer": "Vietnamese explanation with [S1] citations when sources are supplied", "asserted_cves": ["CVE-YYYY-NNNN"]}
The verdict describes the conclusion for the question, not advice about another version.
For a supported CVE list or description, use affected. Use not_affected only with
explicit support for that conclusion for the requested scope; absence
of a CVE from a search is not evidence of safety. State platform/configuration
conditions and limitations from the evidence. Use insufficient_evidence when the
requested conclusion cannot be established. asserted_cves lists CVEs substantively
identified or adjudicated in the answer (including explicitly not affected ones),
excluding IDs merely repeated as unconfirmed questions. Preserve any supported
partial assertions even when the overall verdict is insufficient_evidence. Every
asserted ID must also appear in answer. Do not put unsupported claims in answer.
""".strip()


@dataclass(frozen=True)
class ParsedAnswer:
    answer: str
    verdict: str | None = None
    asserted_cves: tuple[str, ...] | None = None
    structured: bool = False
    error: str | None = None


def parse_answer(text: str) -> ParsedAnswer:
    """Validate an envelope; keep old prose explicitly distinguishable in logs.

    Invalid JSON is never silently converted into a successful legacy answer.
    Semantic correctness still needs evidence review; a valid envelope is only
    a format contract.
    """
    original = text.strip()
    candidate = original
    fenced = re.fullmatch(r"```(?:json)?\s*\n?(.*?)\n?```", candidate, re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced.group(1).strip()
    if not candidate.startswith(("{", "[")):
        if original.startswith("```") or re.search(r'\{\s*"(?:verdict|answer|asserted_cves)"\s*:', candidate):
            return ParsedAnswer(original, structured=True, error="invalid_structured_answer")
        if not original:
            return ParsedAnswer(original, error="empty_answer")
        return ParsedAnswer(original)
    try:
        payload = json.loads(candidate, object_pairs_hook=_unique_keys)
    except (ValueError, TypeError):
        return ParsedAnswer(original, structured=True, error="invalid_structured_answer")
    if not isinstance(payload, dict):
        return ParsedAnswer(original, structured=True, error="answer_must_be_an_object")
    verdict = payload.get("verdict")
    answer = payload.get("answer")
    identifiers = payload.get("asserted_cves")
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        return ParsedAnswer(original, structured=True, error="invalid_verdict")
    if not isinstance(answer, str) or not answer.strip():
        return ParsedAnswer(original, structured=True, error="invalid_answer_text")
    if not isinstance(identifiers, list):
        return ParsedAnswer(answer.strip(), structured=True, error="invalid_asserted_cves")
    normalized: list[str] = []
    for value in identifiers:
        if not isinstance(value, str):
            return ParsedAnswer(answer.strip(), structured=True, error="invalid_asserted_cves")
        identifier = normalize_dashes(value.strip()).upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
            return ParsedAnswer(answer.strip(), structured=True, error="invalid_asserted_cves")
        if identifier not in normalized:
            normalized.append(identifier)
    if set(normalized) - set(find_cve_ids(answer)):
        return ParsedAnswer(answer.strip(), structured=True, error="asserted_cve_missing_from_answer")
    if verdict in {"affected", "not_affected"} and find_cve_ids(answer) and not normalized:
        return ParsedAnswer(answer.strip(), structured=True, error="missing_asserted_cves_for_verdict")
    return ParsedAnswer(answer.strip(), verdict, tuple(normalized), structured=True)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result
