"""Version-range evaluation independent of a specific vendor or product."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from packaging.version import InvalidVersion, Version

from rag_system.models import MatchStatus, VersionDecision


class VersionMatcher:
    """Evaluate numeric versions against normalized range boundaries."""

    @staticmethod
    def _parse(value: str) -> Version:
        return Version(value.strip().lower().removeprefix("v"))

    def _rule_matches(self, version: Version, rule: Mapping[str, Any]) -> bool:
        exact = str(rule.get("version") or "").strip()
        if exact and exact not in {"*", "-"}:
            return version == self._parse(exact)

        boundaries = (
            ("version_start_including", lambda value, limit: value >= limit),
            ("version_start_excluding", lambda value, limit: value > limit),
            ("version_end_including", lambda value, limit: value <= limit),
            ("version_end_excluding", lambda value, limit: value < limit),
        )
        has_boundary = False
        for field, compare in boundaries:
            raw_limit = rule.get(field)
            if not raw_limit:
                continue
            has_boundary = True
            if not compare(version, self._parse(str(raw_limit))):
                return False
        return has_boundary or exact == "*"

    def evaluate(
        self,
        vulnerability_id: str,
        version_text: str,
        rules: Iterable[Mapping[str, Any]],
    ) -> VersionDecision:
        vulnerable_rules = [rule for rule in rules if rule.get("vulnerable", True)]
        if not vulnerable_rules:
            return VersionDecision(
                vulnerability_id=vulnerability_id,
                version=version_text,
                status=MatchStatus.UNKNOWN,
                reason="Không có version rule đủ để kiểm tra.",
            )

        try:
            version = self._parse(version_text)
            for rule in vulnerable_rules:
                if self._rule_matches(version, rule):
                    return VersionDecision(
                        vulnerability_id=vulnerability_id,
                        version=version_text,
                        status=MatchStatus.AFFECTED,
                        reason="Phiên bản nằm trong phạm vi ảnh hưởng đã công bố.",
                    )
        except InvalidVersion:
            return VersionDecision(
                vulnerability_id=vulnerability_id,
                version=version_text,
                status=MatchStatus.UNKNOWN,
                reason="Không thể chuẩn hóa phiên bản để so sánh an toàn.",
            )

        return VersionDecision(
            vulnerability_id=vulnerability_id,
            version=version_text,
            status=MatchStatus.NOT_AFFECTED,
            reason="Phiên bản nằm ngoài các phạm vi ảnh hưởng đã lưu.",
        )
