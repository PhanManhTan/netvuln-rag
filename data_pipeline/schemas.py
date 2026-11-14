"""Validated contracts for structured vulnerability and chunk artifacts."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SCHEMA_VERSION = "1.0"


class SourceReference(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_id: str
    authority: Literal["vendor", "nvd"]
    source_type: str
    url: str
    title: str = ""
    published: str | None = None
    updated: str | None = None
    retrieved_at: str | None = None
    raw_path: str | None = None


class VersionRule(BaseModel):
    """One source assertion about a version set on an optional product branch."""

    model_config = ConfigDict(frozen=True)

    source_id: str
    authority: Literal["vendor", "nvd"]
    status: Literal["affected", "not_affected"]
    branch: str | None = None
    all_versions: bool = False
    exact_versions: tuple[str, ...] = ()
    literal_exact: bool = False
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    fixed_versions: tuple[str, ...] = ()
    evidence_text: str = ""
    priority: int = Field(default=2, ge=1)

    @model_validator(mode="after")
    def require_version_coverage(self) -> "VersionRule":
        has_range = any(
            (
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        )
        if not self.exact_versions and not has_range and not self.branch and not self.all_versions:
            raise ValueError("Version rule phải có exact version, range hoặc branch")
        if self.literal_exact and (not self.exact_versions or has_range or self.branch or self.all_versions):
            raise ValueError("Literal rule chỉ hỗ trợ đối chiếu nhãn phiên bản chính xác")
        return self


class ConflictInterval(BaseModel):
    model_config = ConfigDict(frozen=True)

    branch: str | None = None
    version_start: str | None = None
    start_including: bool = True
    version_end: str | None = None
    end_including: bool = True
    left_source_id: str
    right_source_id: str
    left_status: Literal["affected", "not_affected"]
    right_status: Literal["affected", "not_affected"]


class VulnerabilityRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_VERSION
    record_id: str
    vulnerability_id: str
    product_id: str
    vendor: str
    product: str
    display_name: str
    description: str = ""
    published: str | None = None
    last_modified: str | None = None
    status: str | None = None
    cvss: dict[str, object] | None = None
    weaknesses: tuple[str, ...] = ()
    sources: tuple[SourceReference, ...]
    applicability: tuple[VersionRule, ...] = ()
    effective_rules: tuple[VersionRule, ...] = ()
    applicability_notes: tuple[str, ...] = ()
    has_source_conflict: bool = False
    conflict_intervals: tuple[ConflictInterval, ...] = ()

    @field_validator("vulnerability_id")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        normalized = value.upper()
        if not CVE_PATTERN.fullmatch(normalized):
            raise ValueError(f"CVE ID không hợp lệ: {value}")
        return normalized

    @model_validator(mode="after")
    def validate_record_id(self) -> "VulnerabilityRecord":
        expected = f"{self.product_id}:{self.vulnerability_id}"
        if self.record_id != expected:
            raise ValueError(f"record_id phải là {expected!r}")
        source_ids = {source.source_id for source in self.sources}
        for rule in (*self.applicability, *self.effective_rules):
            if rule.source_id not in source_ids:
                raise ValueError(f"Rule tham chiếu source không tồn tại: {rule.source_id}")
        return self


class TextChunk(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_VERSION
    chunk_id: str
    record_id: str
    vulnerability_id: str
    product_id: str
    vendor: str
    product: str
    section: Literal["overview", "applicability", "remediation"]
    branch: str | None = None
    text: str
    source_id: str
    source_url: str
    content_hash: str
    version_rule: VersionRule | None = None


class CuratedRouterOSAdvisory(BaseModel):
    """Human-reviewed RouterOS vendor evidence, one row per CVE/product pair."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_VERSION
    product_id: Literal["routeros"] = "routeros"
    vulnerability_id: str
    advisory_id: str
    title: str
    source_url: str
    source_type: Literal["announcement", "changelog", "official_forum"]
    published: str | None = None
    updated: str | None = None
    retrieved_at: str
    version_rules: tuple[VersionRule, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    evidence_text: str
    source_content_hash: str
    review_status: Literal["draft", "approved", "rejected"]
    normalized_by: str
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    notes: str = ""

    @field_validator("vulnerability_id")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        normalized = value.upper()
        if not CVE_PATTERN.fullmatch(normalized):
            raise ValueError(f"CVE ID không hợp lệ: {value}")
        return normalized

    @model_validator(mode="after")
    def validate_review(self) -> "CuratedRouterOSAdvisory":
        official_hosts = (
            "https://mikrotik.com/",
            "https://help.mikrotik.com/",
            "https://forum.mikrotik.com/",
            "https://blog.mikrotik.com/",
        )
        if not self.source_url.startswith(official_hosts):
            raise ValueError("RouterOS curated source phải thuộc domain MikroTik chính thức")
        if self.review_status == "approved" and not (
            self.reviewed_by and self.reviewed_at
        ):
            raise ValueError("Advisory approved phải có reviewed_by và reviewed_at")
        if self.source_type == "official_forum" and not self.notes.strip():
            raise ValueError("Official forum row phải ghi xác minh đại diện MikroTik trong notes")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", self.source_content_hash):
            raise ValueError("source_content_hash phải là SHA-256 hex gồm 64 ký tự")
        for rule in self.version_rules:
            if rule.authority != "vendor":
                raise ValueError("RouterOS curated rule phải có authority='vendor'")
            if rule.source_id != self.advisory_id:
                raise ValueError("Curated rule source_id phải trùng advisory_id")
            if not rule.evidence_text:
                raise ValueError("Curated version rule phải có evidence_text")
        return self
