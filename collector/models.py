"""Inventory contracts shared by agents, the collector and experiment checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SoftwareFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str
    component: str
    version: str | None = None
    binary: str | None = None
    binary_sha256: str | None = None
    package_version: str | None = None
    running: bool | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class DeviceSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    device_id: str = Field(pattern=r"^[A-Z][A-Z0-9]*-[AB]$")
    collected_at: datetime
    boot_id: str
    management_ip: str
    collection_status: Literal["collected", "partial", "error"]
    os: dict[str, str]
    software: list[SoftwareFacts] = Field(max_length=256)
    packages: list[dict[str, str]] = Field(default_factory=list, max_length=10000)
    network: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list, max_length=256)
    limitations: list[str] = Field(default_factory=list, max_length=256)

    @field_validator("collected_at")
    @classmethod
    def timestamp_requires_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Snapshot timestamp requires a timezone")
        return value.astimezone(timezone.utc)
