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
class SourceSpec:
    rule_id: str
    pattern: str
    # For calls only: the call is a source only if every condition holds.
    when: tuple[Condition, ...] = ()


@dataclass(frozen=True, slots=True)
class CompiledTaintRule:
    sources: tuple[SourceSpec, ...]
    sinks: tuple[SinkSpec, ...]
    sanitizers: tuple[str, ...]
    safe_prefixes: tuple[str, ...] = ()


def compile_condition(raw: dict) -> Condition:
    pos = raw.get("pos")
    if "is_true" in raw:
        return Condition(raw["kwarg"], pos, "is_true", expect=bool(raw["is_true"]))
    op = "in" if "in" in raw else "not_in"
    names = tuple(compile_pattern(p) for p in raw[op])
    return Condition(raw["kwarg"], pos, op, names=names)


def _conditions(raw_when) -> tuple[Condition, ...]:
    if not raw_when:
        return ()
    if isinstance(raw_when, dict):
        raw_when = [raw_when]
    return tuple(compile_condition(c) for c in raw_when)


def compile_rule(rule_id: str, raw: dict) -> CompiledTaintRule:
    sources = tuple(SourceSpec(rule_id, s["pattern"], _conditions(s.get("when"))) for s in raw["sources"])
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
        sinks.append(SinkSpec(rule_id, s["pattern"], positions, receiver, kwargs, _conditions(s.get("when"))))
    return CompiledTaintRule(sources, tuple(sinks), sanitizers, tuple(raw.get("safe_prefixes") or ()))


class TaintRuleSet:
    """Every taint rule merged into three pattern indexes.

    One pass of the analysis serves all rules at once: facts carry the set of
    rule ids they are still live for.
    """

    def __init__(self, rules: Sequence) -> None:
        self.rules = {r.id: r for r in rules}
        self.rule_ids = frozenset(self.rules)
        self.sources: PatternIndex[SourceSpec] = PatternIndex()
        self.sinks: PatternIndex[SinkSpec] = PatternIndex()
        self.sanitizers: PatternIndex[str] = PatternIndex()
        # rule id -> globs for the constant leading text of built strings
        self.safe_prefixes: dict[str, tuple[str, ...]] = {}
        for rule in rules:
            if rule.compiled.safe_prefixes:
                self.safe_prefixes[rule.id] = rule.compiled.safe_prefixes
            compiled: CompiledTaintRule = rule.compiled
            for spec in compiled.sources:
                self.sources.add(spec.pattern, spec)
            for spec in compiled.sinks:
                self.sinks.add(spec.pattern, spec)
            for p in compiled.sanitizers:
                self.sanitizers.add(p, rule.id)
