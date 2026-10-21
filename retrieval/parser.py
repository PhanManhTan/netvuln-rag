"""Parse natural-language questions into structured retrieval intents."""

from __future__ import annotations

import re

from retrieval.models import ParsedQuery, QueryIntent


VULNERABILITY_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
EXPLICIT_VERSION_PATTERN = re.compile(
    r"(?:phiên\s*bản|version)\s*v?([0-9]+(?:\.[0-9A-Za-z-]+)+)",
    re.IGNORECASE,
)


def parse_query(
    question: str,
    default_product: str | None = None,
    product_aliases: tuple[str, ...] = (),
) -> ParsedQuery:
    """Parse a query using a configurable product profile."""
    text = question.strip()
    identifier_match = VULNERABILITY_ID_PATTERN.search(text)
    vulnerability_id = (
        identifier_match.group(0).upper() if identifier_match else None
    )

    aliases = tuple(alias for alias in product_aliases if alias)
    matched_alias = next(
        (alias for alias in aliases if alias.lower() in text.lower()),
        None,
    )
    product = default_product if matched_alias else None

    version = None
    match = EXPLICIT_VERSION_PATTERN.search(text)
    if match:
        version = match.group(1)
    else:
        for alias in aliases:
            alias_pattern = re.compile(
                rf"\b{re.escape(alias)}\s+v?([0-9]+(?:\.[0-9A-Za-z-]+)+)",
                re.IGNORECASE,
            )
            match = alias_pattern.search(text)
            if match:
                version = match.group(1)
                break

    if version and default_product:
        product = default_product

    if vulnerability_id and version:
        intent = QueryIntent.VULNERABILITY_CHECK
    elif product and version:
        intent = QueryIntent.VERSION_INVENTORY
    elif vulnerability_id:
        intent = QueryIntent.VULNERABILITY_DETAIL
    else:
        intent = QueryIntent.SEMANTIC

    return ParsedQuery(text, intent, vulnerability_id, product, version)
