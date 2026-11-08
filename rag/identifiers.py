"""Normalize CVE identifiers consistently across retrieval and answer checks."""

import re
from unicodedata import normalize


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
DASH_TRANSLATION = str.maketrans(dict.fromkeys("‐‑‒–—−－", "-"))


def normalize_dashes(text: str) -> str:
    return normalize("NFKC", text).translate(DASH_TRANSLATION)


def find_cve_ids(text: str) -> list[str]:
    """Return CVE mentions in order, normalized to uppercase and ASCII dashes."""
    return [match.group(0).upper() for match in CVE_PATTERN.finditer(normalize_dashes(text))]
