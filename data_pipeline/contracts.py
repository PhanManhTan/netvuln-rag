"""Contracts implemented by external vulnerability-data adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class CrawlOptions:
    """Source-independent controls for a single crawl run."""

    output_dir: Path | None = None
    limit: int | None = None

    def __post_init__(self) -> None:
        if self.limit is not None and self.limit < 1:
            raise ValueError("Crawl limit phải lớn hơn 0")


class SourceAdapter(Protocol):
    """A source must support both raw collection and normalization."""

    def crawl(self, options: CrawlOptions | None = None) -> Path:
        """Collect raw source records and return their directory."""
        ...

    def process(self, input_path: Path, output_path: Path) -> int:
        """Normalize raw records and return the output record count."""
        ...
