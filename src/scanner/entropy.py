"""Shannon entropy of a string, in bits per character."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """``H = -sum(p * log2(p))`` over the frequency of each character.

    ``""`` -> 0.0, ``"aaaa"`` -> 0.0, ``"ab"`` -> 1.0, ``"abcd"`` -> 2.0.
    Counter preserves first-seen order, so the floating-point sum is computed
    in the same order on every run.
    """
    if not text:
        return 0.0
    n = len(text)
    total = 0.0
    for count in Counter(text).values():
        p = count / n
        total -= p * math.log2(p)
    return total + 0.0  # normalise -0.0
