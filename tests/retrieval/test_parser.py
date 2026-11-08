from rag.retrieval.models import QueryIntent
from rag.retrieval.parser import parse_query


def test_parse_cve_and_version() -> None:
    parsed = parse_query(
        "FortiOS 7.2.5 có bị CVE-2024-21762 ảnh hưởng không?",
        default_product="fortios",
        product_aliases=("fortios",),
    )

    assert parsed.vulnerability_id == "CVE-2024-21762"
    assert parsed.product_id == "fortios"
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


def test_parse_unicode_cve_in_version_question() -> None:
    parsed = parse_query(
        "Does OpenSSH 9.5p1 have ｃｖｅ‑2023‑51384?",
        default_product="openssh",
        product_aliases=("openssh",),
    )

    assert parsed.vulnerability_id == "CVE-2023-51384"
    assert parsed.version == "9.5p1"
    assert parsed.intent == QueryIntent.VULNERABILITY_CHECK


def test_product_alias_is_not_a_substring_of_an_unrelated_word() -> None:
    parsed = parse_query(
        "Are there weaknesses in opensshd?",
        default_product="openssh",
        product_aliases=("openssh",),
    )

    assert parsed.product_id is None

