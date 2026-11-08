from config.products import ProductProfile
from config.settings import Settings
from data_pipeline.fortiguard import FortiGuardAdapter


def adapter() -> FortiGuardAdapter:
    return FortiGuardAdapter(
        Settings(),
        ProductProfile(
            product_id="fortios", vendor="fortinet", product="fortios",
            display_name="Fortinet FortiOS", cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
            vendor_source="fortiguard",
        ),
    )


def test_fortiguard_or_above_creates_explicit_safe_range() -> None:
    rules = adapter()._parse_rule(
        "FortiOS 7.2", "7.2.0 through 7.2.5", "Upgrade to 7.2.6 or above", "FG-IR-test"
    )
    assert [(rule.status, rule.version_start_including, rule.version_end_including) for rule in rules] == [
        ("affected", "7.2.0", "7.2.5"),
        ("not_affected", "7.2.6", None),
    ]


def test_fortiguard_fixed_without_or_above_is_exact_only() -> None:
    rules = adapter()._parse_rule("FortiOS 7.0", "7.0.1", "Fixed in 7.0.2", "FG-IR-test")
    safe = rules[-1]
    assert safe.status == "not_affected"
    assert safe.exact_versions == ("7.0.2",)
    assert safe.version_start_including is None
