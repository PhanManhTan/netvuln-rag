"""Application configuration."""

from config.settings import PROJECT_ROOT, Settings, get_settings
from config.products import ProductCatalog, ProductProfile, get_product_catalog

__all__ = [
    "PROJECT_ROOT",
    "ProductCatalog",
    "ProductProfile",
    "Settings",
    "get_product_catalog",
    "get_settings",
]
