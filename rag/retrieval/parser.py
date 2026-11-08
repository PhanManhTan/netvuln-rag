"""Parse natural-language questions into structured retrieval intents."""

from __future__ import annotations

import re

from config.products import ProductCatalog
from rag.identifiers import find_cve_ids
from rag.retrieval.models import ParsedQuery, QueryIntent


EXPLICIT_VERSION_PATTERN = re.compile(
    r"\b(?:phiên\s*bản|version)\s*v?([0-9]+(?:\.[0-9A-Za-z-]+)+)",
    re.IGNORECASE,
)


def parse_query(
    question: str,
    default_product: str | None = None,
    product_aliases: tuple[str, ...] = (),
    catalog: ProductCatalog | None = None,
) -> ParsedQuery:
    """Parse a query using a configurable product profile."""
    text = question.strip()
    identifiers = find_cve_ids(text)
    vulnerability_id = identifiers[0] if identifiers else None

    alias_pairs: list[tuple[str, str]] = []
    if catalog:
        for profile in catalog.products:
            alias_pairs.extend((alias, profile.product_id) for alias in profile.all_aliases)
    else:
        alias_pairs.extend((alias, default_product or alias.lower()) for alias in product_aliases if alias)
    alias_pairs.sort(key=lambda item: len(item[0]), reverse=True)
    product_id = next(
        (
            product_id
            for alias, product_id in alias_pairs
            if re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", text, re.IGNORECASE)
        ),
        None,
    )

    version = None
    match = EXPLICIT_VERSION_PATTERN.search(text)
    if match:
        version = match.group(1)
    else:
        for alias, alias_product_id in alias_pairs:
            alias_pattern = re.compile(
                rf"(?<!\w){re.escape(alias)}\s+v?([0-9]+(?:\.[0-9A-Za-z-]+)+)",
                re.IGNORECASE,
            )
            match = alias_pattern.search(text)
            if match:
                version = match.group(1)
                product_id = alias_product_id
                break

    if version and default_product:
        product_id = product_id or default_product

    if vulnerability_id and version:
        intent = QueryIntent.VULNERABILITY_CHECK
    elif product_id and version:
        intent = QueryIntent.VERSION_INVENTORY
    elif vulnerability_id:
        intent = QueryIntent.VULNERABILITY_DETAIL
    else:
        intent = QueryIntent.SEMANTIC

    return ParsedQuery(
        original=text,
        intent=intent,
        vulnerability_id=vulnerability_id,
        product_id=product_id,
        version=version,
    )
