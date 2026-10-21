"""Transform normalized vulnerability records into retrieval chunks."""

from __future__ import annotations

from typing import Any


def format_version_rule(rule: dict[str, Any]) -> str:
    exact_version = rule.get("version")
    if exact_version and exact_version not in {"*", "-"}:
        return f"version {exact_version}"

    boundaries = []
    labels = (
        ("version_start_including", ">="),
        ("version_start_excluding", ">"),
        ("version_end_including", "<="),
        ("version_end_excluding", "<"),
    )
    for field, operator in labels:
        if rule.get(field):
            boundaries.append(f"version {operator} {rule[field]}")
    return " và ".join(boundaries) if boundaries else "all versions"


def create_chunks(record: dict[str, Any]) -> list[dict[str, str]]:
    """Create source-independent overview and applicability chunks."""
    identifier = str(
        record.get("vulnerability_id") or record.get("cve_id") or ""
    )
    vendor = str(record.get("vendor", "unknown"))
    product = str(record.get("product", "unknown"))
    cvss = record.get("cvss") or {}
    overview = (
        f"{identifier} affects {vendor} {product}.\n"
        f"Description: {record.get('description', '')}\n"
        f"CVSS: {cvss.get('score', 'unknown')} "
        f"({cvss.get('severity', 'unknown')}).\n"
        f"Weaknesses: {', '.join(record.get('weaknesses', [])) or 'unknown'}."
    )
    chunks = [{"section": "overview", "text": overview}]

    vulnerable_rules = [
        rule
        for rule in record.get("affected_versions", [])
        if rule.get("vulnerable", True)
    ]
    if vulnerable_rules:
        formatted_rules = "\n".join(
            f"- {format_version_rule(rule)}" for rule in vulnerable_rules
        )
        chunks.append(
            {
                "section": "applicability",
                "text": (
                    f"{identifier} affected {product} version rules:\n"
                    f"{formatted_rules}"
                ),
            }
        )
    return chunks
