"""Compatibility imports for the shared corpus version rules."""

from data_pipeline.versioning import (
    MatchStatus,
    VersionDecision,
    VersionMatcher,
    derive_branch,
    detect_conflicts,
    parse_version,
    rule_matches,
)

__all__ = [
    "MatchStatus",
    "VersionDecision",
    "VersionMatcher",
    "derive_branch",
    "detect_conflicts",
    "parse_version",
    "rule_matches",
]
