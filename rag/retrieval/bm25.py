"""Small dependency-free BM25 index for the local chunk artifacts."""

from __future__ import annotations

import math
import re
from collections import Counter

from rag.identifiers import normalize_dashes


TOKEN_PATTERN = re.compile(r"[^\W_]+(?:[_.-][^\W_]+)*")


def tokenize(text: str) -> list[str]:
    return TOKEN_PATTERN.findall(normalize_dashes(text).casefold())


class BM25Index:
    def __init__(self, documents: list[str], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.term_frequencies = [Counter(tokenize(document)) for document in documents]
        self.lengths = [sum(frequencies.values()) for frequencies in self.term_frequencies]
        self.average_length = sum(self.lengths) / len(self.lengths) if self.lengths else 0.0
        document_frequency: Counter[str] = Counter()
        for frequencies in self.term_frequencies:
            document_frequency.update(frequencies.keys())
        count = len(documents)
        self.idf = {
            term: math.log(1 + (count - frequency + 0.5) / (frequency + 0.5))
            for term, frequency in document_frequency.items()
        }

    def scores(self, query: str) -> list[float]:
        terms = tokenize(query)
        scores: list[float] = []
        for frequencies, length in zip(self.term_frequencies, self.lengths, strict=True):
            score = 0.0
            for term in terms:
                frequency = frequencies.get(term, 0)
                if not frequency:
                    continue
                denominator = frequency + self.k1 * (
                    1 - self.b + self.b * length / (self.average_length or 1)
                )
                score += self.idf.get(term, 0.0) * frequency * (self.k1 + 1) / denominator
            scores.append(score)
        return scores
