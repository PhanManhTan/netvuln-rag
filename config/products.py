"""Validated product profiles used across ingestion and retrieval."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from config.settings import DEFAULT_PRODUCT_CONFIG


class VersionTarget(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str = Field(pattern=r"^[0-9]+(?:\.[0-9A-Za-z-]+)+$")
    cpe: str


class ProductProfile(BaseModel):
    """Stable identity and source configuration for a supported product."""

    model_config = ConfigDict(frozen=True)

    product_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    vendor: str
    product: str
    display_name: str
    aliases: tuple[str, ...] = ()
    cpe: str
    version_strategy: Literal["numeric_branch_intervals"] = "numeric_branch_intervals"
    vendor_source: str | None = None
    versions: tuple[VersionTarget, ...] = ()

    @model_validator(mode="after")
    def validate_version_targets(self) -> "ProductProfile":
        labels = {target.version.lower() for target in self.versions}
        cpes = {target.cpe.lower() for target in self.versions}
        if len(labels) != len(self.versions) or len(cpes) != len(self.versions):
            raise ValueError("Danh sách versions có nhãn phiên bản hoặc CPE trùng")
        for target in self.versions:
            parts = target.cpe.split(":", 6)
            if (
                len(parts) != 7
                or parts[:2] != ["cpe", "2.3"]
                or parts[2] not in {"a", "o", "h"}
                or parts[3:5] != [self.vendor, self.product]
                or parts[5] in {"", "*", "-"}
            ):
                raise ValueError(f"Version {target.version} cần CPE chính xác của {self.product_id}")
        return self

    @field_validator("product_id", "vendor", "product", "vendor_source")
    @classmethod
    def normalize_identifier(cls, value: str | None) -> str | None:
        return value.strip().lower() if value else value

    @field_validator("aliases")
    @classmethod
    def normalize_aliases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.strip().lower() for item in value if item.strip()))

    @property
    def all_aliases(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.product, self.display_name.lower(), *self.aliases)))


class ProductCatalog(BaseModel):
    model_config = ConfigDict(frozen=True)

    products: tuple[ProductProfile, ...]

    def by_id(self, product_id: str) -> ProductProfile:
        normalized = product_id.strip().lower()
        for profile in self.products:
            if profile.product_id == normalized:
                return profile
        supported = ", ".join(profile.product_id for profile in self.products)
        raise ValueError(f"Product {product_id!r} chưa được hỗ trợ. Có: {supported}")


def load_product_catalog(path: Path) -> ProductCatalog:
    with path.open("r", encoding="utf-8") as file:
        catalog = ProductCatalog.model_validate(json.load(file))
    identifiers = [profile.product_id for profile in catalog.products]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"Product catalog có product_id trùng lặp: {path}")
    if not catalog.products:
        raise ValueError(f"Product catalog không có product: {path}")
    return catalog


@lru_cache(maxsize=4)
def get_product_catalog(path: Path | None = None) -> ProductCatalog:
    selected = (path or DEFAULT_PRODUCT_CONFIG).resolve()
    return load_product_catalog(selected)
