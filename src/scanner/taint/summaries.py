"""Function summaries.

A summary describes a function's taint behaviour in terms of its parameters,
so a call site can be analysed without re-analysing the callee:

* ``ret``          taint of the return value. Facts whose origin is a
                   :class:`ParamOrigin` of this function are *parameter to
                   return* flows (with the route inside the callee); facts with
                   a :class:`SourceSite` origin are *source to return* flows
                   (``def get_q(): return request.args["q"]``). Sanitising
                   inside the callee shows up as missing rule ids.
* ``hits``         parameter to sink flows: parameter ``k`` reaches sink ``S``
                   for rule ``R`` along route ``P``. A caller passing a tainted
                   argument for ``k`` gets a finding at ``S`` whose route runs
                   through the call.
* ``self_writes``  ``self.<attr> = <param>`` effects, instantiated at call
                   sites into the class's field store.
* ``defaults``     taint of parameter default values.
* ``closure`` /    flow-insensitive record of this function's local variables
  ``closure_aliases``  (concrete facts only), read by nested functions.

Source to sink flows inside a function are reported directly as findings when
that function is analysed; they are not part of the summary.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import Location, PathStep
from .values import EMPTY, Path, TaintValue


@dataclass(frozen=True, slots=True)
class SinkSite:
    location: Location
    callee: str  # e.g. "cursor.execute"
    text: str  # ast.unparse of the whole sink call: part of the finding identity
    arg: str  # e.g. "arg 0"
    step: PathStep  # the final step of every route ending here


@dataclass(frozen=True, slots=True)
class SinkHit:
    rule_id: str
    param: int
    path: Path
    sink: SinkSite


@dataclass
class Summary:
    ret: TaintValue = field(default_factory=lambda: EMPTY)
    hits: dict = field(default_factory=dict)  # (rule, param, sink location) -> SinkHit
    self_writes: dict = field(default_factory=dict)  # selector tuple -> TaintValue
    defaults: dict = field(default_factory=dict)  # param key -> TaintValue
    closure: dict = field(default_factory=dict)  # name -> VarVal
    closure_aliases: dict = field(default_factory=dict)  # name -> frozenset[Ref]

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Summary)
            and self.ret == other.ret
            and self.hits == other.hits
            and self.self_writes == other.self_writes
            and self.defaults == other.defaults
            and self.closure == other.closure
            and self.closure_aliases == other.closure_aliases
        )

    __hash__ = None  # type: ignore[assignment]


BOTTOM = Summary()
