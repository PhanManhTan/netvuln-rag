"""Registry for source-specific ingestion adapters."""

from __future__ import annotations

from collections.abc import Callable

from rag_system.config import Settings
from rag_system.ingestion.base import SourceAdapter
from rag_system.ingestion.adapters.nvd import NVDAdapter


AdapterFactory = Callable[[Settings], SourceAdapter]
ADAPTERS: dict[str, AdapterFactory] = {
    "nvd": NVDAdapter,
}


def get_source_adapter(settings: Settings) -> SourceAdapter:
    try:
        factory = ADAPTERS[settings.data_source]
    except KeyError as exc:
        supported = ", ".join(sorted(ADAPTERS))
        raise ValueError(
            f"DATA_SOURCE={settings.data_source!r} chưa được hỗ trợ. Có: {supported}"
        ) from exc
    return factory(settings)
