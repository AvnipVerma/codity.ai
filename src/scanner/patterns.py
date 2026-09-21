"""Dotted-path patterns used by sources, sinks and sanitizers.

Syntax
------
A pattern is a dot-separated list of segments. Each segment is either a
Python identifier or ``*``, which matches exactly one segment. There is no
``**`` and no partial wildcard (``exec*`` is rejected): a ``*`` must be a whole
segment.

Matching
--------
A pattern matches a *candidate name*: a tuple of segments produced by name
resolution (see :mod:`scanner.resolve`). The segment counts must be equal and
every segment must match. Matching is case-sensitive and done with a plain loop
over pre-split tuples; nothing here uses regular expressions.

The resolver presents a method call on a receiver whose type it cannot infer
as the two-segment name ``(<unknown>, method)``. The ``<unknown>`` segment can
only be matched by ``*`` (it is not a valid identifier), so ``*.execute``
matches ``cur.execute(...)`` whatever ``cur`` is, while ``sqlite3.execute``
never matches it.

Single-segment patterns naming a builtin (``open``, ``eval``...) are
normalised to ``builtins.<name>``, which is how the resolver presents
unshadowed builtins. ``open`` and ``builtins.open`` are therefore equivalent.
"""

from __future__ import annotations

import builtins
from typing import Generic, Iterable, TypeVar

WILDCARD = "*"
UNKNOWN = "<unknown>"
BUILTIN_NAMES = frozenset(dir(builtins))

T = TypeVar("T")


class PatternError(ValueError):
    pass


def compile_pattern(text: object) -> tuple[str, ...]:
    """Validate and split a dotted pattern. Raises :class:`PatternError`."""
    if not isinstance(text, str):
        raise PatternError(f"pattern must be a string, got {type(text).__name__}")
    if text == "":
        raise PatternError("pattern is empty")
    if text != text.strip() or any(ch.isspace() for ch in text):
        raise PatternError(f"pattern {text!r} contains whitespace")
    if text.startswith(".") or text.endswith("."):
        raise PatternError(f"pattern {text!r} has a leading or trailing dot")
    segments = tuple(text.split("."))
    for seg in segments:
        if seg == "":
            raise PatternError(f"pattern {text!r} has an empty segment")
        if seg == "**":
            raise PatternError(f"pattern {text!r} uses '**', which is not supported")
        if seg != WILDCARD and not seg.isidentifier():
            if WILDCARD in seg:
                raise PatternError(f"pattern {text!r}: '*' must be a whole segment")
            raise PatternError(f"pattern {text!r}: segment {seg!r} is not an identifier")
    if len(segments) == 1 and segments[0] in BUILTIN_NAMES:
        segments = ("builtins", segments[0])
    return segments


def matches(pattern: tuple[str, ...], name: tuple[str, ...]) -> bool:
    if len(pattern) != len(name):
        return False
    for p, n in zip(pattern, name):
        if p != WILDCARD and p != n:
            return False
    return True


class PatternIndex(Generic[T]):
    """A set of compiled patterns, each carrying a payload.

    Patterns are bucketed by their final segment so that looking up a call
    costs one dict probe plus a scan of the (usually tiny) wildcard-final
    bucket, rather than a scan over every rule.
    """

    def __init__(self) -> None:
        # entry = (segments, pattern_text, payload, insertion_seq)
        self._by_last: dict[str, list[tuple[tuple[str, ...], str, T, int]]] = {}
        self._wild_last: list[tuple[tuple[str, ...], str, T, int]] = []
        self._seq = 0

    def add(self, pattern_text: str, payload: T) -> None:
        segs = compile_pattern(pattern_text)
        entry = (segs, pattern_text, payload, self._seq)
        self._seq += 1
        if segs[-1] == WILDCARD:
            self._wild_last.append(entry)
        else:
            self._by_last.setdefault(segs[-1], []).append(entry)

    def __bool__(self) -> bool:
        return self._seq > 0

    def could_match_last(self, segment: str) -> bool:
        """Cheap pre-filter: could any pattern end with ``segment``?"""
        return bool(self._wild_last) or segment in self._by_last

    def match(self, names: Iterable[tuple[str, ...]]) -> list[tuple[str, T]]:
        """Return ``(pattern_text, payload)`` for every pattern matching any name.

        The result is de-duplicated and ordered by insertion order of the
        patterns, independent of the order of ``names``.
        """
        hits: dict[int, tuple[str, T]] = {}
        for name in names:
            if not name:
                continue
            for bucket in (self._by_last.get(name[-1], ()), self._wild_last):
                for segs, text, payload, seq in bucket:
                    if seq not in hits and matches(segs, name):
                        hits[seq] = (text, payload)
        return [hits[k] for k in sorted(hits)]


def dotted(name: tuple[str, ...]) -> str:
    return ".".join(name)
