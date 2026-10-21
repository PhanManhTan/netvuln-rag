"""Registry for source-specific ingestion adapters."""

from __future__ import annotations

from collections.abc import Callable

from config.settings import Settings
from ingestion.contracts import SourceAdapter
from ingestion.nvd import NVDAdapter


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
