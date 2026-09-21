"""Abstract values of the taint analysis.

A :class:`TaintValue` is a set of *facts*. Each fact says "this value may carry
data from ``origin``, and is still dangerous for the rules in ``rules``", and
records the route (a tuple of :class:`~scanner.model.PathStep`) the data took.
The empty value is clean.

Facts are keyed by ``(origin, rules)``. When two routes reach the same point
for the same key, the shorter one is kept (ties broken by comparing the steps'
positions), so joins are deterministic, idempotent and commutative, and loop
fixpoints terminate.

Origins are either a :class:`SourceSite` (a concrete source expression) or a
:class:`ParamOrigin` (a symbolic "whatever the caller passed for parameter
k", used to compute function summaries).

A :class:`VarVal` is the abstract value of one variable: taint on the variable
as a whole (``own``) plus taint on access paths below it (``fields``), keyed by
selector tuples such as ``(".query",)``, ``("['id']",)`` or ``("[*]",)``.
Selectors: ``.name`` for an attribute, ``[repr(key)]`` for a constant
subscript, ``[*]`` for an unknown key or index. At most :data:`MAX_DEPTH`
selectors are kept; deeper paths are truncated and updated weakly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..model import Location, PathStep, StepKind

MAX_PATH = 50
MAX_DEPTH = 2
ANY_KEY = "[*]"


@dataclass(frozen=True, slots=True)
class SourceSite:
    location: Location
    text: str  # ast.unparse of the source expression
    pattern: str  # the rule pattern that matched

    def sort_key(self) -> tuple:
        loc = self.location
        return (0, loc.file, loc.line, loc.col, self.text, self.pattern)


@dataclass(frozen=True, slots=True)
class ParamOrigin:
    function: str  # qualified name of the function whose parameter this is
    key: int  # position; -1 for *args, -2 for **kwargs
    name: str

    def sort_key(self) -> tuple:
        return (1, self.function, "", self.key, self.name)


Origin = SourceSite | ParamOrigin
Path = tuple[PathStep, ...]


def path_order(path: Path) -> tuple:
    return (len(path), tuple(step.sort_key() for step in path))


def better(p: Path, q: Path) -> bool:
    """Is route ``p`` preferable to ``q``? Shorter first, then by position."""
    if len(p) != len(q):
        return len(p) < len(q)
    return path_order(p) < path_order(q)


def _ellipsis(next_step: PathStep) -> PathStep:
    return PathStep(next_step.location, StepKind.STEP, "… intermediate steps omitted")


def _same_step(a: PathStep, b: PathStep) -> bool:
    """Consecutive steps that would read identically (``a + b + c`` makes two
    nested BinOps starting at the same column) are collapsed."""
    return (
        a.kind is b.kind
        and a.message == b.message
        and a.location.file == b.location.file
        and a.location.line == b.location.line
        and a.location.col == b.location.col
    )


def extend(path: Path, *steps: PathStep) -> Path:
    for step in steps:
        if path and _same_step(path[-1], step):
            continue
        path = path + (step,)
    if len(path) > MAX_PATH:
        head = MAX_PATH // 2 - 5
        tail = MAX_PATH - head - 1
        path = path[:head] + (_ellipsis(path[-tail]),) + path[-tail:]
    return path


def concat(first: Path, second: Path) -> Path:
    return extend(first, *second) if second else first


class TaintValue:
    """Immutable set of facts ``{(origin, rules): path}``."""

    __slots__ = ("facts",)

    def __init__(self, facts: dict | None = None) -> None:
        self.facts = facts if facts is not None else {}

    def __bool__(self) -> bool:
        return bool(self.facts)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TaintValue) and self.facts == other.facts

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        items = ", ".join(
            f"{getattr(o, 'text', getattr(o, 'name', o))}:{sorted(r)}" for (o, r) in self.facts
        )
        return f"TaintValue({items})"

    @staticmethod
    def of(origin: Origin, rules: frozenset, path: Path = ()) -> "TaintValue":
        return TaintValue({(origin, rules): path})

    def join(self, other: "TaintValue") -> "TaintValue":
        if not other.facts or other is self:
            return self
        if not self.facts:
            return other
        merged = dict(self.facts)
        for key, path in other.facts.items():
            cur = merged.get(key)
            if cur is None or (cur is not path and cur != path and better(path, cur)):
                merged[key] = path
        return TaintValue(merged)

    def __or__(self, other: "TaintValue") -> "TaintValue":
        return self.join(other)

    def with_step(self, step: PathStep) -> "TaintValue":
        if not self.facts:
            return self
        return TaintValue({key: extend(path, step) for key, path in self.facts.items()})

    def without_rules(self, rules: frozenset) -> "TaintValue":
        if not self.facts or not rules:
            return self
        out: dict = {}
        for (origin, live), path in self.facts.items():
            remaining = live - rules
            if not remaining:
                continue
            key = (origin, remaining)
            cur = out.get(key)
            if cur is None or better(path, cur):
                out[key] = path
        return TaintValue(out)

    def concrete(self) -> "TaintValue":
        """Only facts from real sources (drop symbolic parameter origins)."""
        if not self.facts:
            return self
        if all(isinstance(o, SourceSite) for (o, _) in self.facts):
            return self
        return TaintValue({k: p for k, p in self.facts.items() if isinstance(k[0], SourceSite)})

    def items(self):
        return self.facts.items()


EMPTY = TaintValue()


def join_all(values: Iterable[TaintValue]) -> TaintValue:
    out = EMPTY
    for v in values:
        out = out.join(v)
    return out


def compatible(a: str, b: str) -> bool:
    if a == b:
        return True
    return (a == ANY_KEY and b.startswith("[")) or (b == ANY_KEY and a.startswith("["))


def _prefix_compatible(prefix: tuple, full: tuple) -> bool:
    return all(compatible(x, y) for x, y in zip(prefix, full))


class VarVal:
    """Abstract value of one variable: whole-value taint plus per-field taint."""

    __slots__ = ("own", "fields")

    def __init__(self, own: TaintValue = EMPTY, fields: dict | None = None) -> None:
        self.own = own
        self.fields = fields if fields is not None else {}

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VarVal) and self.own == other.own and self.fields == other.fields

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"VarVal(own={self.own!r}, fields={self.fields!r})"

    def is_empty(self) -> bool:
        return not self.own and not any(self.fields.values())

    def read_all(self) -> TaintValue:
        out = self.own
        for tv in self.fields.values():
            out = out.join(tv)
        return out

    def read(self, sels: tuple) -> TaintValue:
        """Taint of the access path ``var<sels>``: the whole-variable taint,
        taint on any enclosing path, and taint anywhere below it."""
        if not sels:
            return self.read_all()
        sels = sels[:MAX_DEPTH]
        out = self.own
        for key, tv in self.fields.items():
            n = min(len(key), len(sels))
            if _prefix_compatible(key[:n], sels[:n]):
                out = out.join(tv)
        return out

    def subtree(self, sels: tuple) -> "VarVal":
        """The value found at ``var<sels>``, keeping structure below it."""
        if not sels:
            return self
        sels = sels[:MAX_DEPTH]
        own = self.own
        fields: dict = {}
        for key, tv in self.fields.items():
            if len(key) <= len(sels):
                if _prefix_compatible(key, sels[: len(key)]):
                    own = own.join(tv)
            elif _prefix_compatible(sels, key[: len(sels)]):
                rest = key[len(sels):]
                fields[rest] = fields.get(rest, EMPTY).join(tv)
        return VarVal(own, fields)

    def write(self, sels: tuple, value: "VarVal", strong: bool) -> "VarVal":
        """Store ``value`` at ``var<sels>``; strong updates replace, weak ones join."""
        if not sels:
            if strong:
                return value
            return self.join(value)
        if len(sels) > MAX_DEPTH or ANY_KEY in sels:
            strong = False
        sels = sels[:MAX_DEPTH]
        fields = dict(self.fields)
        if strong:
            for key in list(fields):
                if key[: len(sels)] == sels:
                    del fields[key]
        entries = [(sels, value.own)] + [((sels + k)[:MAX_DEPTH], tv) for k, tv in value.fields.items()]
        for key, tv in entries:
            if tv:
                fields[key] = fields[key].join(tv) if key in fields else tv
        return VarVal(self.own, fields)

    def join(self, other: "VarVal | None") -> "VarVal":
        if other is None or other is self:
            return self
        if self.is_empty():
            return other
        if other.is_empty():
            return self
        fields = dict(self.fields)
        for key, tv in other.fields.items():
            fields[key] = fields[key].join(tv) if key in fields else tv
        return VarVal(self.own.join(other.own), fields)

    def with_step(self, step: PathStep) -> "VarVal":
        if self.is_empty():
            return self
        return VarVal(self.own.with_step(step), {k: v.with_step(step) for k, v in self.fields.items()})

    def without_rules(self, rules: frozenset) -> "VarVal":
        return VarVal(self.own.without_rules(rules), {k: v.without_rules(rules) for k, v in self.fields.items()})

    def concrete(self) -> "VarVal":
        own = self.own.concrete()
        fields = {k: v.concrete() for k, v in self.fields.items()}
        return VarVal(own, {k: v for k, v in fields.items() if v})


CLEAN = VarVal()


class State:
    """Abstract program state at a point inside one function.

    ``vars`` maps local names to :class:`VarVal`; ``aliases`` maps names to the
    dotted references they are known to stand for (``r = flask.request``,
    ``from os import system``, ``repo = Repo()``), tracked flow-sensitively.
    """

    __slots__ = ("vars", "aliases")

    def __init__(self, vars: dict | None = None, aliases: dict | None = None) -> None:
        self.vars = vars if vars is not None else {}
        self.aliases = aliases if aliases is not None else {}

    def copy(self) -> "State":
        return State(dict(self.vars), dict(self.aliases))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, State) and self.vars == other.vars and self.aliases == other.aliases

    __hash__ = None  # type: ignore[assignment]

    @staticmethod
    def join(a: "State | None", b: "State | None") -> "State | None":
        """Merge two control-flow paths. ``None`` is the unreachable state."""
        if a is None:
            return b
        if b is None:
            return a
        vars = dict(a.vars)
        for name, vv in b.vars.items():
            cur = vars.get(name)
            vars[name] = vv if cur is None else cur.join(vv)
        aliases = dict(a.aliases)
        for name, refs in b.aliases.items():
            cur = aliases.get(name)
            aliases[name] = refs if cur is None else (cur | refs)
        return State(vars, aliases)

    @staticmethod
    def join_all(states: Iterable["State | None"]) -> "State | None":
        out = None
        for s in states:
            out = State.join(out, s)
        return out
