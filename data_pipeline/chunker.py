"""Create source-attributed text chunks from validated records."""

from __future__ import annotations

import hashlib

from data_pipeline.schemas import TextChunk, VersionRule, VulnerabilityRecord


def format_version_rule(rule: VersionRule) -> str:
    pieces: list[str] = []
    if rule.all_versions:
        pieces.append("all explicitly covered versions")
    if rule.branch:
        pieces.append(f"branch {rule.branch}")
    if rule.exact_versions:
        pieces.append("exact " + ", ".join(rule.exact_versions))
    labels = (
        (rule.version_start_including, ">="),
        (rule.version_start_excluding, ">"),
        (rule.version_end_including, "<="),
        (rule.version_end_excluding, "<"),
    )
    pieces.extend(f"version {operator} {value}" for value, operator in labels if value)
    return "; ".join(pieces) or "unknown coverage"


def _make_chunk(
    record: VulnerabilityRecord,
    section: str,
    text: str,
    source_id: str,
    source_url: str,
    branch: str | None,
    ordinal: int,
    version_rule: VersionRule | None = None,
) -> TextChunk:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    identity = f"{record.record_id}|{source_id}|{section}|{branch or ''}|{ordinal}|{digest}"
    return TextChunk(
        chunk_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        record_id=record.record_id,
        vulnerability_id=record.vulnerability_id,
        product_id=record.product_id,
        vendor=record.vendor,
        product=record.product,
        section=section,
        branch=branch,
        text=text,
        source_id=source_id,
        source_url=source_url,
        content_hash=digest,
        version_rule=version_rule,
    )


def create_chunks(value: VulnerabilityRecord | dict[str, object]) -> list[TextChunk]:
    """Create chunks where every row is attributable to exactly one source."""

    record = value if isinstance(value, VulnerabilityRecord) else VulnerabilityRecord.model_validate(value)
    sources = {source.source_id: source for source in record.sources}
    chunks: list[TextChunk] = []

    nvd_sources = [source for source in record.sources if source.authority == "nvd"]
    overview_sources = nvd_sources or list(record.sources[:1])
    for source in overview_sources:
        cvss = record.cvss or {}
        text = (
            f"{record.vulnerability_id} — {record.display_name}.\n"
            f"Description: {record.description or 'No description supplied.'}\n"
            f"CVSS: {cvss.get('score', 'unknown')} ({cvss.get('severity', 'unknown')}).\n"
            f"CWE: {', '.join(record.weaknesses) or 'unknown'}."
        )
        chunks.append(_make_chunk(record, "overview", text, source.source_id, source.url, None, len(chunks)))

    for rule in record.effective_rules:
        source = sources[rule.source_id]
        text = (
            f"{record.vulnerability_id} {record.display_name}: {rule.status}. "
            f"Coverage: {format_version_rule(rule)}. Evidence: {rule.evidence_text}"
        )
        chunks.append(_make_chunk(record, "applicability", text, source.source_id, source.url, rule.branch, len(chunks), rule))
        if rule.fixed_versions:
            remediation = (
                f"{record.vulnerability_id} remediation for {record.display_name}: "
                f"fixed versions {', '.join(rule.fixed_versions)}. Evidence: {rule.evidence_text}"
            )
            chunks.append(_make_chunk(record, "remediation", remediation, source.source_id, source.url, rule.branch, len(chunks), rule))
    return chunks
