"""Registry of rule kinds.

``REGISTRY`` maps the ``kind:`` value used in rules.yaml to a handler object.
The built-in kinds register themselves at import time; anything else (a
plugin, a test) can call :func:`register_kind` with no change to the engine.
"""

from __future__ import annotations

from .base import Issue, RuleKind

REGISTRY: dict[str, RuleKind] = {}


def register_kind(kind: RuleKind, *, replace: bool = False) -> RuleKind:
    if not kind.name:
        raise ValueError("a rule kind needs a non-empty name")
    if kind.name in REGISTRY and not replace:
        raise ValueError(f"rule kind {kind.name!r} is already registered")
    REGISTRY[kind.name] = kind
    return kind


def unregister_kind(name: str) -> None:
    REGISTRY.pop(name, None)


def get_kind(name: str) -> RuleKind | None:
    return REGISTRY.get(name)


def _register_builtins() -> None:
    from .pattern import PatternKind
    from .taint import TaintKind

    for kind in (TaintKind(), PatternKind()):
        if kind.name not in REGISTRY:
            register_kind(kind)


_register_builtins()

__all__ = ["REGISTRY", "Issue", "RuleKind", "get_kind", "register_kind", "unregister_kind"]
