"""Core data types shared by every part of the scanner.

Positions are stored the way SARIF wants them: 1-based lines and 1-based
columns counted in Unicode code points, with ``end_col`` exclusive. The
conversion from ``ast``'s 0-based UTF-8 byte offsets happens in exactly one
place, :meth:`scanner.context.ModuleContext.location`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[str(text).upper()]
        except KeyError:
            raise ValueError(f"unknown severity {text!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


SEVERITY_NAMES = tuple(s.label for s in sorted(Severity, reverse=True))


@dataclass(frozen=True, slots=True, order=True)
class Location:
    file: str  # path relative to the scan root, POSIX separators
    line: int  # 1-based
    col: int  # 1-based, Unicode code points
    end_line: int
    end_col: int  # 1-based, exclusive

    def short(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


class StepKind(str, enum.Enum):
    SOURCE = "source"
    STEP = "step"
    CALL = "call"
    RETURN = "return"
    SINK = "sink"


@dataclass(frozen=True, slots=True)
class PathStep:
    location: Location
    kind: StepKind
    message: str
    # Name of the variable the value was assigned to at this step, if any.
    # Used only to build readable finding messages ("... via query").
    var: str | None = None

    def sort_key(self) -> tuple:
        loc = self.location
        return (loc.file, loc.line, loc.col, self.kind.value, self.message)


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: Severity
    cwe: str | None
    message: str
    location: Location
    # source step, intermediate steps, sink step. Empty for non-flow findings.
    path: tuple[PathStep, ...] = ()
    # Normalised, position-independent strings supplied by the rule kind; the
    # baseline fingerprint is a hash of (rule_id, file, *identity).
    identity: tuple[str, ...] = ()
    # Short human-readable code snippet (secrets already redacted).
    snippet: str = ""
    # One-line summary for the table's MESSAGE column (falls back to message).
    summary: str = ""
    fingerprint: str = ""
    suppressed: bool = False
    suppression_reason: str | None = None
    properties: dict = field(default_factory=dict)

    def sort_key(self) -> tuple:
        loc = self.location
        return (-int(self.severity), loc.file, loc.line, loc.col, self.rule_id, self.fingerprint)


@dataclass(slots=True)
class Diagnostic:
    """A warning about the scan itself (unparseable file, handler crash...)."""

    file: str | None
    message: str

    def render(self) -> str:
        return f"warning: {self.file}: {self.message}" if self.file else f"warning: {self.message}"
