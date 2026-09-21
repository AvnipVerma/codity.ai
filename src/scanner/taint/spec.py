"""Compiled form of taint rules: sources, sinks (with argument selectors and
``when`` conditions) and sanitizers, merged across rules into pattern indexes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..patterns import PatternIndex, compile_pattern

ANY = "any"
RECEIVER = "receiver"


@dataclass(frozen=True, slots=True)
class Condition:
    """A ``when:`` condition on a keyword (or positional) argument of a sink.

    * ``is_true: true`` holds when the argument is present and is a truthy
      constant or any non-constant expression (``shell=flag`` counts).
    * ``in: [...]`` holds when the argument resolves to one of the names, or
      cannot be resolved.
    * ``not_in: [...]`` holds when the argument is absent, or resolves to a
      name outside the list, or cannot be resolved.

    Unknown values always satisfy the condition: we would rather report a
    ``subprocess.run(cmd, shell=use_shell)`` than miss it.
    """

    kwarg: str
    pos: int | None
    op: str  # "is_true" | "in" | "not_in"
    expect: bool = True
    names: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True, slots=True)
class SinkSpec:
    rule_id: str
    pattern: str
    positions: tuple[int, ...] | None  # None means ``arg: any``
    receiver: bool
    kwargs: tuple[str, ...]
    when: tuple[Condition, ...]

    def describe(self) -> str:
        if self.receiver:
            return "receiver"
        if self.positions is None:
            return "any argument"
        if len(self.positions) == 1:
            return f"arg {self.positions[0]}"
        return "args " + ", ".join(str(p) for p in self.positions)


@dataclass(frozen=True, slots=True)
class CompiledTaintRule:
    sources: tuple[str, ...]
    sinks: tuple[SinkSpec, ...]
    sanitizers: tuple[str, ...]


def compile_condition(raw: dict) -> Condition:
    pos = raw.get("pos")
    if "is_true" in raw:
        return Condition(raw["kwarg"], pos, "is_true", expect=bool(raw["is_true"]))
    op = "in" if "in" in raw else "not_in"
    names = tuple(compile_pattern(p) for p in raw[op])
    return Condition(raw["kwarg"], pos, op, names=names)


def compile_rule(rule_id: str, raw: dict) -> CompiledTaintRule:
    sources = tuple(s["pattern"] for s in raw["sources"])
    sanitizers = tuple(s["pattern"] for s in raw.get("sanitizers") or ())
    sinks = []
    for s in raw["sinks"]:
        arg = s.get("arg", ANY)
        receiver = arg == RECEIVER
        if arg == ANY:
            positions = None
        elif receiver:
            positions = ()
        elif isinstance(arg, list):
            positions = tuple(sorted(set(arg)))
        else:
            positions = (arg,)
        kw = s.get("kwarg", s.get("kwargs", ()))
        kwargs = (kw,) if isinstance(kw, str) else tuple(kw)
        when_raw = s.get("when") or ()
        if isinstance(when_raw, dict):
            when_raw = [when_raw]
        when = tuple(compile_condition(c) for c in when_raw)
        sinks.append(SinkSpec(rule_id, s["pattern"], positions, receiver, kwargs, when))
    return CompiledTaintRule(sources, tuple(sinks), sanitizers)


class TaintRuleSet:
    """Every taint rule merged into three pattern indexes.

    One pass of the analysis serves all rules at once: facts carry the set of
    rule ids they are still live for.
    """

    def __init__(self, rules: Sequence) -> None:
        self.rules = {r.id: r for r in rules}
        self.rule_ids = frozenset(self.rules)
        self.sources: PatternIndex[str] = PatternIndex()
        self.sinks: PatternIndex[SinkSpec] = PatternIndex()
        self.sanitizers: PatternIndex[str] = PatternIndex()
        for rule in rules:
            compiled: CompiledTaintRule = rule.compiled
            for p in compiled.sources:
                self.sources.add(p, rule.id)
            for spec in compiled.sinks:
                self.sinks.add(spec.pattern, spec)
            for p in compiled.sanitizers:
                self.sanitizers.add(p, rule.id)
