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

    Patterns ending in a literal segment are bucketed by that segment;
    patterns ending in ``*`` are bucketed by their first segment (or kept in a
    catch-all list when that is ``*`` too). A lookup therefore touches only
    patterns that can possibly match. Results are memoised per candidate list,
    since the same names are looked up over and over.
    """

    def __init__(self) -> None:
        # entry = (segments, pattern_text, payload, insertion_seq)
        self._by_last: dict[str, list] = {}
        self._wild_by_first: dict[str, list] = {}
        self._wild_any: list = []
        self._seq = 0
        self._cache: dict[tuple, list] = {}

    def add(self, pattern_text: str, payload: T) -> None:
        segs = compile_pattern(pattern_text)
        entry = (segs, pattern_text, payload, self._seq)
        self._seq += 1
        self._cache.clear()
        if segs[-1] != WILDCARD:
            self._by_last.setdefault(segs[-1], []).append(entry)
        elif segs[0] != WILDCARD:
            self._wild_by_first.setdefault(segs[0], []).append(entry)
        else:
            self._wild_any.append(entry)

    def __bool__(self) -> bool:
        return self._seq > 0

    def match(self, names: Iterable[tuple[str, ...]]) -> list[tuple[str, T]]:
        """Return ``(pattern_text, payload)`` for every pattern matching any name.

        The result is de-duplicated and ordered by insertion order of the
        patterns, independent of the order of ``names``.
        """
        key = tuple(names)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        hits: dict[int, tuple[str, T]] = {}
        for name in key:
            if not name:
                continue
            for bucket in (self._by_last.get(name[-1], ()), self._wild_by_first.get(name[0], ()), self._wild_any):
                for segs, text, payload, seq in bucket:
                    if seq not in hits and matches(segs, name):
                        hits[seq] = (text, payload)
        result = [hits[k] for k in sorted(hits)]
        self._cache[key] = result
        return result


def dotted(name: tuple[str, ...]) -> str:
    return ".".join(name)
