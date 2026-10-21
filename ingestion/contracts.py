"""Contracts implemented by external vulnerability-data adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol


class SourceAdapter(Protocol):
    """A source must support both raw collection and normalization."""

    def crawl(self, output_dir: Path | None = None) -> Path:
        """Collect raw source records and return their directory."""
        ...

    def process(self, input_path: Path, output_path: Path) -> int:
        """Normalize raw records and return the output record count."""
        ...
