from data_pipeline.schemas import SourceReference, VersionRule, VulnerabilityRecord
from rag.retrieval.models import MatchStatus
from rag.retrieval.version_matcher import VersionMatcher, detect_conflicts


def make_record(*rules: VersionRule) -> VulnerabilityRecord:
    sources = tuple(
        SourceReference(
            source_id=source_id,
            authority=next(rule.authority for rule in rules if rule.source_id == source_id),
            source_type="test",
            url=f"https://example.test/{source_id}",
        )
        for source_id in dict.fromkeys(rule.source_id for rule in rules)
    )
    conflicts = detect_conflicts(rules)
    return VulnerabilityRecord(
        record_id="fortios:CVE-2024-21762",
        vulnerability_id="CVE-2024-21762",
        product_id="fortios",
        vendor="fortinet",
        product="fortios",
        display_name="Fortinet FortiOS",
        sources=sources,
        applicability=rules,
        effective_rules=rules,
        has_source_conflict=bool(conflicts),
        conflict_intervals=conflicts,
    )


def test_vendor_wins_only_on_covered_interval_and_keeps_conflict() -> None:
    nvd = VersionRule(
        source_id="nvd",
        authority="nvd",
        status="affected",
        branch="7.2",
        version_start_including="7.2.0",
        version_end_including="7.2.9",
    )
    vendor = VersionRule(
        source_id="vendor",
        authority="vendor",
        status="not_affected",
        branch="7.2",
        exact_versions=("7.2.5",),
        priority=1,
    )
    record = make_record(nvd, vendor)

    covered = VersionMatcher().evaluate_record(record, "7.2.5")
    fallback = VersionMatcher().evaluate_record(record, "7.2.4")

    assert covered.status == MatchStatus.NOT_AFFECTED
    assert covered.query_has_conflict is True
    assert set(covered.source_ids) == {"vendor", "nvd"}
    assert fallback.status == MatchStatus.AFFECTED
    assert fallback.source_ids == ("nvd",)


def test_rule_from_other_branch_never_overrides_nvd() -> None:
    nvd = VersionRule(source_id="nvd", authority="nvd", status="affected", branch="7.0")
    vendor = VersionRule(source_id="vendor", authority="vendor", status="not_affected", branch="7.2", priority=1)
    decision = VersionMatcher().evaluate_record(make_record(nvd, vendor), "7.0.12")
    assert decision.status == MatchStatus.AFFECTED
    assert decision.query_has_conflict is False


def test_same_priority_vendor_contradiction_is_unknown() -> None:
    left = VersionRule(source_id="vendor-a", authority="vendor", status="affected", branch="7.2", priority=1)
    right = VersionRule(source_id="vendor-b", authority="vendor", status="not_affected", branch="7.2", priority=1)
    decision = VersionMatcher().evaluate_record(make_record(left, right), "7.2.1")
    assert decision.status == MatchStatus.UNKNOWN
    assert decision.query_has_conflict is True


def test_fixed_version_is_exact_unless_range_is_explicit() -> None:
    exact = VersionRule(
        source_id="vendor", authority="vendor", status="not_affected", branch="7.2",
        exact_versions=("7.2.5",), fixed_versions=("7.2.5",), priority=1,
    )
    matcher = VersionMatcher()
    record = make_record(exact)
    assert matcher.evaluate_record(record, "7.2.5").status == MatchStatus.NOT_AFFECTED
    assert matcher.evaluate_record(record, "7.2.6").status == MatchStatus.UNKNOWN


def test_conflict_interval_respects_exclusive_ties_at_both_boundaries() -> None:
    nvd = VersionRule(
        source_id="nvd", authority="nvd", status="affected",
        version_start_including="7.2.0", version_end_including="7.2.9",
    )
    vendor = VersionRule(
        source_id="vendor", authority="vendor", status="not_affected",
        version_start_excluding="7.2.0", version_end_excluding="7.2.9",
    )

    (conflict,) = detect_conflicts((nvd, vendor))

    assert not conflict.start_including
    assert not conflict.end_including


def test_literal_version_query_records_conflicting_sources() -> None:
    nvd = VersionRule(
        source_id="nvd", authority="nvd", status="affected",
        literal_exact=True, exact_versions=("9.5p1",),
    )
    vendor = VersionRule(
        source_id="vendor", authority="vendor", status="not_affected",
        literal_exact=True, exact_versions=("9.5p1",),
    )

    decision = VersionMatcher().evaluate_record(make_record(nvd, vendor), "9.5p1")

    assert decision.status == MatchStatus.NOT_AFFECTED
    assert decision.query_has_conflict
    assert set(decision.source_ids) == {"nvd", "vendor"}
