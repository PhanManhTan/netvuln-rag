from retrieval.models import MatchStatus
from retrieval.version_matcher import VersionMatcher


RULES = [
    {
        "vulnerable": True,
        "version": "*",
        "version_start_including": "7.2.0",
        "version_end_excluding": "7.2.7",
    }
]


def test_version_inside_range_is_affected() -> None:
    result = VersionMatcher().evaluate("CVE-2024-21762", "7.2.5", RULES)
    assert result.status == MatchStatus.AFFECTED


def test_exclusive_upper_boundary_is_not_affected() -> None:
    result = VersionMatcher().evaluate("CVE-2024-21762", "7.2.7", RULES)
    assert result.status == MatchStatus.NOT_AFFECTED


def test_missing_rules_is_unknown() -> None:
    result = VersionMatcher().evaluate("CVE-2024-21762", "7.2.5", [])
    assert result.status == MatchStatus.UNKNOWN

