"""The interface every rule kind implements.

The engine knows nothing about any particular kind. It parses each file once,
groups the loaded rules by their ``kind`` field, and calls these hooks through
the registry in :mod:`scanner.kinds`. Adding a new kind means writing one
subclass and calling :func:`scanner.kinds.register_kind`; see
``tests/test_extensibility.py`` for a complete third kind defined in a test.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any, ClassVar, Iterable, Mapping, Sequence

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Rule
    from ..context import ModuleContext, ProgramContext
    from ..model import Finding

# (field path, message), e.g. ("sinks[0].arg", "must be a non-negative integer or 'any'")
Issue = tuple[str, str]


class RuleKind(abc.ABC):
    #: The value of a rule's ``kind:`` field that selects this handler.
    name: ClassVar[str] = ""
    #: Top-level rule keys owned by this kind (beyond id/severity/cwe/...).
    #: Keys that are neither common nor listed here produce a warning.
    fields: ClassVar[frozenset[str]] = frozenset()
    #: SARIF ``precision`` used when a rule does not set one.
    default_precision: ClassVar[str] = "medium"

    @abc.abstractmethod
    def validate(self, rule: Mapping[str, Any]) -> list[Issue]:
        """Check this kind's section of a raw rule mapping; return problems."""

    def compile(self, rule: "Rule") -> Any:
        """Pre-compute whatever :meth:`analyze` needs (patterns, globs...).

        Called once per rule after validation succeeded. The return value is
        stored on ``rule.compiled``.
        """
        return None

    def prepare(self, program: "ProgramContext", rules: Sequence["Rule"]) -> None:
        """Optional whole-program pass, run once before any :meth:`analyze`.

        Kinds that need facts spanning files (the taint kind builds function
        summaries and a call graph here) do that work now.
        """

    @abc.abstractmethod
    def analyze(self, module: "ModuleContext", rules: Sequence["Rule"]) -> Iterable["Finding"]:
        """Return the findings located in ``module`` for the given rules."""
