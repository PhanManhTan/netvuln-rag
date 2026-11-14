"""Version interval normalization, precedence, and conflict evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from packaging.version import InvalidVersion, Version

from data_pipeline.schemas import ConflictInterval, VersionRule, VulnerabilityRecord


class MatchStatus(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VersionDecision:
    vulnerability_id: str
    version: str
    status: MatchStatus
    reason: str
    product_id: str | None = None
    source_ids: tuple[str, ...] = ()
    query_has_conflict: bool = False


def parse_version(value: str) -> Version:
    """Parse a numeric product version without guessing non-version labels."""

    return Version(value.strip().lower().removeprefix("v"))


def derive_branch(value: str) -> str | None:
    """Return the major.minor branch used to isolate product release lines."""

    try:
        release = parse_version(value).release
    except InvalidVersion:
        return None
    if len(release) < 2:
        return str(release[0]) if release else None
    return f"{release[0]}.{release[1]}"


def _coerce_rule(value: VersionRule | Mapping[str, Any]) -> VersionRule:
    if isinstance(value, VersionRule):
        return value
    exact = str(value.get("version") or "").strip()
    status = value.get("status")
    if status not in {"affected", "not_affected"}:
        status = "affected" if value.get("vulnerable", True) else "not_affected"
    return VersionRule(
        source_id=str(value.get("source_id") or "legacy"),
        authority=str(value.get("authority") or "nvd"),
        status=status,
        branch=value.get("branch"),
        all_versions=exact == "*" and not any(
            value.get(field)
            for field in (
                "version_start_including", "version_start_excluding",
                "version_end_including", "version_end_excluding",
            )
        ),
        exact_versions=(exact,) if exact and exact not in {"*", "-"} else (),
        version_start_including=value.get("version_start_including"),
        version_start_excluding=value.get("version_start_excluding"),
        version_end_including=value.get("version_end_including"),
        version_end_excluding=value.get("version_end_excluding"),
        fixed_versions=tuple(value.get("fixed_versions") or ()),
        evidence_text=str(value.get("evidence_text") or ""),
        priority=int(value.get("priority") or (1 if value.get("authority") == "vendor" else 2)),
    )


def rule_matches(rule: VersionRule, version: Version | str) -> bool:
    if rule.literal_exact:
        label = str(version).strip().lower().removeprefix("v")
        return any(label == exact.lower() for exact in rule.exact_versions)
    if isinstance(version, str):
        try:
            version = parse_version(version)
        except InvalidVersion:
            return False

    branch = derive_branch(str(version))
    if rule.branch and rule.branch != branch:
        return False
    if rule.all_versions:
        return True
    if rule.exact_versions:
        for exact in rule.exact_versions:
            try:
                if version == parse_version(exact):
                    return True
            except InvalidVersion:
                continue
        if not any(
            (
                rule.version_start_including,
                rule.version_start_excluding,
                rule.version_end_including,
                rule.version_end_excluding,
            )
        ):
            return False
    comparisons = (
        (rule.version_start_including, lambda current, limit: current >= limit),
        (rule.version_start_excluding, lambda current, limit: current > limit),
        (rule.version_end_including, lambda current, limit: current <= limit),
        (rule.version_end_excluding, lambda current, limit: current < limit),
    )
    has_boundary = False
    for raw_limit, comparison in comparisons:
        if not raw_limit:
            continue
        has_boundary = True
        try:
            if not comparison(version, parse_version(raw_limit)):
                return False
        except InvalidVersion:
            return False
    return has_boundary or bool(rule.branch)


@dataclass(frozen=True)
class _Interval:
    branch: str | None
    start: Version | None
    start_including: bool
    end: Version | None
    end_including: bool


def _branch_bounds(branch: str) -> tuple[Version, Version] | None:
    try:
        parts = [int(part) for part in branch.split(".")]
    except ValueError:
        return None
    if len(parts) == 1:
        return Version(str(parts[0])), Version(str(parts[0] + 1))
    prefix = parts[:-1]
    return Version(".".join(map(str, parts))), Version(".".join(map(str, [*prefix, parts[-1] + 1])))


def _rule_intervals(rule: VersionRule) -> list[_Interval]:
    intervals: list[_Interval] = []
    for exact in rule.exact_versions:
        try:
            parsed = parse_version(exact)
        except InvalidVersion:
            continue
        intervals.append(_Interval(rule.branch or derive_branch(exact), parsed, True, parsed, True))

    raw_boundaries = (
        rule.version_start_including,
        rule.version_start_excluding,
        rule.version_end_including,
        rule.version_end_excluding,
    )
    if any(raw_boundaries):
        try:
            start = parse_version(rule.version_start_including or rule.version_start_excluding) if (rule.version_start_including or rule.version_start_excluding) else None
            end = parse_version(rule.version_end_including or rule.version_end_excluding) if (rule.version_end_including or rule.version_end_excluding) else None
        except InvalidVersion:
            return intervals
        intervals.append(
            _Interval(
                rule.branch,
                start,
                bool(rule.version_start_including),
                end,
                bool(rule.version_end_including),
            )
        )
    elif rule.branch and not rule.exact_versions:
        bounds = _branch_bounds(rule.branch)
        if bounds:
            intervals.append(_Interval(rule.branch, bounds[0], True, bounds[1], False))
    elif rule.all_versions:
        intervals.append(_Interval(None, None, True, None, True))
    return intervals


def _intersection(left: _Interval, right: _Interval) -> _Interval | None:
    if left.branch and right.branch and left.branch != right.branch:
        return None
    branch = left.branch or right.branch
    starts = [(left.start, left.start_including), (right.start, right.start_including)]
    starts = [(value, inclusive) for value, inclusive in starts if value is not None]
    ends = [(left.end, left.end_including), (right.end, right.end_including)]
    ends = [(value, inclusive) for value, inclusive in ends if value is not None]
    start, start_including = max(starts, key=lambda item: (item[0], not item[1])) if starts else (None, True)
    end, end_including = min(ends, key=lambda item: (item[0], item[1])) if ends else (None, True)
    if start is not None and end is not None:
        if start > end:
            return None
        if start == end and not (start_including and end_including):
            return None
    return _Interval(branch, start, start_including, end, end_including)


def detect_conflicts(rules: Iterable[VersionRule]) -> tuple[ConflictInterval, ...]:
    selected = list(rules)
    conflicts: list[ConflictInterval] = []
    seen: set[tuple[object, ...]] = set()
    for index, left in enumerate(selected):
        for right in selected[index + 1 :]:
            if left.status == right.status:
                continue
            for left_interval in _rule_intervals(left):
                for right_interval in _rule_intervals(right):
                    overlap = _intersection(left_interval, right_interval)
                    if overlap is None:
                        continue
                    key = (
                        overlap.branch,
                        overlap.start,
                        overlap.start_including,
                        overlap.end,
                        overlap.end_including,
                        left.source_id,
                        right.source_id,
                        left.status,
                        right.status,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    conflicts.append(
                        ConflictInterval(
                            branch=overlap.branch,
                            version_start=str(overlap.start) if overlap.start else None,
                            start_including=overlap.start_including,
                            version_end=str(overlap.end) if overlap.end else None,
                            end_including=overlap.end_including,
                            left_source_id=left.source_id,
                            right_source_id=right.source_id,
                            left_status=left.status,
                            right_status=right.status,
                        )
                    )
    return tuple(conflicts)


class VersionMatcher:
    """Apply branch-local vendor precedence without treating absent coverage as safe."""

    def evaluate_record(self, record: VulnerabilityRecord, version_text: str) -> VersionDecision:
        try:
            version = parse_version(version_text)
        except InvalidVersion:
            version = None

        matches = []
        for rule in record.applicability:
            candidate = version_text if rule.literal_exact else version
            if candidate is not None and rule_matches(rule, candidate):
                matches.append(rule)
        if not matches and version is None:
            return VersionDecision(record.vulnerability_id, version_text, MatchStatus.UNKNOWN, "Không thể chuẩn hóa phiên bản để so sánh an toàn.", record.product_id)
        has_conflict = len({rule.status for rule in matches}) > 1
        conflict_sources = [rule.source_id for rule in matches] if has_conflict else []
        vendor = [rule for rule in matches if rule.authority == "vendor"]
        candidates = vendor or [rule for rule in matches if rule.authority == "nvd"]
        if not candidates:
            reason = "Không có source rule bao phủ phiên bản này."
            if record.applicability_notes:
                reason += " " + " ".join(record.applicability_notes)
            return VersionDecision(record.vulnerability_id, version_text, MatchStatus.UNKNOWN, reason, record.product_id)

        best_priority = min(rule.priority for rule in candidates)
        winners = [rule for rule in candidates if rule.priority == best_priority]
        statuses = {rule.status for rule in winners}
        source_ids = tuple(dict.fromkeys([rule.source_id for rule in winners] + conflict_sources))
        if len(statuses) != 1:
            return VersionDecision(record.vulnerability_id, version_text, MatchStatus.UNKNOWN, "Các rule cùng mức ưu tiên tự mâu thuẫn trên phiên bản này.", record.product_id, source_ids, True)
        status = MatchStatus(next(iter(statuses)))
        authority = "vendor" if vendor else "NVD"
        return VersionDecision(record.vulnerability_id, version_text, status, f"Kết luận từ {authority} rule bao phủ phiên bản được hỏi.", record.product_id, source_ids, has_conflict)

    def evaluate(
        self,
        vulnerability_id: str,
        version_text: str,
        rules: Iterable[VersionRule | Mapping[str, Any]],
    ) -> VersionDecision:
        """Compatibility helper for callers that only have a list of rules."""

        normalized = tuple(_coerce_rule(rule) for rule in rules)
        from data_pipeline.schemas import SourceReference

        sources = tuple(
            SourceReference(source_id=source_id, authority=next(rule.authority for rule in normalized if rule.source_id == source_id), source_type="compatibility", url="https://example.invalid")
            for source_id in dict.fromkeys(rule.source_id for rule in normalized)
        )
        record = VulnerabilityRecord(
            record_id=f"unknown:{vulnerability_id.upper()}", vulnerability_id=vulnerability_id,
            product_id="unknown", vendor="unknown", product="unknown", display_name="unknown",
            sources=sources, applicability=normalized, effective_rules=normalized,
            conflict_intervals=detect_conflicts(normalized), has_source_conflict=bool(detect_conflicts(normalized)),
        )
        return self.evaluate_record(record, version_text)
