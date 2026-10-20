from rag_system.models import QueryIntent
from rag_system.retrieval import parse_query


def test_parse_cve_and_version() -> None:
    parsed = parse_query(
        "FortiOS 7.2.5 có bị CVE-2024-21762 ảnh hưởng không?",
        default_product="fortios",
        product_aliases=("fortios",),
    )

    assert parsed.vulnerability_id == "CVE-2024-21762"
    assert parsed.product == "fortios"
    assert parsed.version == "7.2.5"
    assert parsed.intent == QueryIntent.VULNERABILITY_CHECK


def test_parse_version_inventory() -> None:
    parsed = parse_query(
        "FortiOS phiên bản 7.0.12 có lỗ hổng nào?",
        default_product="fortios",
        product_aliases=("fortios",),
    )

    assert parsed.version == "7.0.12"
    assert parsed.intent == QueryIntent.VERSION_INVENTORY

