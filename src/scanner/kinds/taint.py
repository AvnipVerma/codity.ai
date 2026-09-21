"""The ``taint`` rule kind: untrusted data from a source reaching a sink.

Rule schema (see rules.yaml for real examples)::

    kind: taint
    sources:    [{pattern: flask.request.args.get}, ...]      # required
                # an entry may list several: {patterns: [a.b, c.d]} (handy with YAML anchors)
    sinks:
      - pattern: "*.execute"
        arg: 0              # int, list of ints, "any" (default) or "receiver"
        kwarg: sql          # optional: keyword name(s) equivalent to ``arg``
        when:               # optional: conditions on other arguments
          {kwarg: shell, is_true: true}
    sanitizers: [{pattern: shlex.quote}, ...]                 # optional
    safe_prefixes: ["https://*/*"]                            # optional
    typed_parameters:                                          # optional
      - {name: request, type: django.http.HttpRequest, module_imports: [django]}

``safe_prefixes`` are globs matched against the constant leading text of a
string built by concatenation, an f-string, ``%`` or ``str.format``. When it
matches, the result no longer carries this rule's taint: for SSRF, a URL whose
scheme and host are fixed constants cannot be pointed at another host by what
follows.

``typed_parameters`` give a type to parameters that frameworks inject: in a
module importing one of ``module_imports``, a parameter called ``name`` is
treated as an instance of ``type``, so ``request.GET`` resolves to
``django.http.HttpRequest.GET`` and ordinary dotted source patterns apply.
(Parameters with a type annotation are typed from the annotation already.)

The analysis itself lives in :mod:`scanner.taint`; this class only validates
and compiles rules, runs the whole-program pass in :meth:`prepare`, and hands
each module its findings in :meth:`analyze`.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from ..patterns import PatternError, compile_pattern
from ..taint.spec import ANY, RECEIVER, compile_rule
from .base import Issue, RuleKind

SINK_KEYS = frozenset({"pattern", "arg", "kwarg", "kwargs", "when"})
SOURCE_KEYS = frozenset({"pattern", "patterns", "when"})
SIMPLE_KEYS = frozenset({"pattern", "patterns"})
TYPED_KEYS = frozenset({"name", "type", "module_imports"})
WHEN_KEYS = frozenset({"kwarg", "pos", "is_true", "in", "not_in"})


def _pattern_issues(field: str, value: Any) -> list[Issue]:
    try:
        compile_pattern(value)
    except PatternError as exc:
        return [(field, str(exc))]
    return []


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class TaintKind(RuleKind):
    name = "taint"
    fields = frozenset({"sources", "sinks", "sanitizers", "safe_prefixes", "typed_parameters"})
    default_precision = "high"

    def validate(self, rule: Mapping[str, Any]) -> list[Issue]:
        issues: list[Issue] = []
        for section, required in (("sources", True), ("sinks", True), ("sanitizers", False)):
            items = rule.get(section)
            if items is None and not required:
                continue
            if not isinstance(items, list) or (required and not items):
                issues.append((section, "must be a non-empty list" if required else "must be a list"))
                continue
            for i, item in enumerate(items):
                where = f"{section}[{i}]"
                many = section != "sinks" and isinstance(item, dict) and "patterns" in item
                if not isinstance(item, dict) or (("pattern" in item) == many):
                    wanted = "'pattern' key" if section == "sinks" else "'pattern' or a 'patterns' list"
                    issues.append((where, f"must be a mapping with a {wanted}"))
                    continue
                if many:
                    pats = item["patterns"]
                    if not isinstance(pats, list) or not pats:
                        issues.append((f"{where}.patterns", "must be a non-empty list of patterns"))
                        continue
                    for k, pat in enumerate(pats):
                        issues += _pattern_issues(f"{where}.patterns[{k}]", pat)
                else:
                    issues += _pattern_issues(f"{where}.pattern", item["pattern"])
                allowed = {"sinks": SINK_KEYS, "sources": SOURCE_KEYS}.get(section, SIMPLE_KEYS)
                for key in item:
                    if key not in allowed:
                        issues.append((f"{where}.{key}", "unknown key"))
                if section == "sinks":
                    issues += self._sink_issues(where, item)
                elif section == "sources" and "when" in item:
                    issues += self._when_issues(where, item["when"])
        if "safe_prefixes" in rule:
            prefixes = rule["safe_prefixes"]
            if not isinstance(prefixes, list) or not all(isinstance(p, str) and p for p in prefixes):
                issues.append(("safe_prefixes", "must be a list of non-empty glob strings"))
        if "typed_parameters" in rule:
            typed = rule["typed_parameters"]
            if not isinstance(typed, list):
                issues.append(("typed_parameters", "must be a list of mappings"))
            else:
                for i, entry in enumerate(typed):
                    where = f"typed_parameters[{i}]"
                    if not isinstance(entry, dict):
                        issues.append((where, "must be a mapping"))
                        continue
                    if not isinstance(entry.get("name"), str) or not entry["name"].isidentifier():
                        issues.append((f"{where}.name", "is required and must be an identifier"))
                    issues += _pattern_issues(f"{where}.type", entry.get("type"))
                    if isinstance(entry.get("type"), str) and "*" in entry["type"]:
                        issues.append((f"{where}.type", "must be a dotted name without wildcards"))
                    mods = entry.get("module_imports", [])
                    if not isinstance(mods, list) or not all(isinstance(m, str) and m.isidentifier() for m in mods):
                        issues.append((f"{where}.module_imports", "must be a list of top-level module names"))
                    for key in entry:
                        if key not in TYPED_KEYS:
                            issues.append((f"{where}.{key}", "unknown key"))
        return issues

    def _sink_issues(self, where: str, item: dict) -> list[Issue]:
        issues: list[Issue] = []
        if "arg" in item:
            arg = item["arg"]
            ok = (
                _nonneg_int(arg)
                or arg in (ANY, RECEIVER)
                or (isinstance(arg, list) and arg and all(_nonneg_int(a) for a in arg))
            )
            if not ok:
                issues.append((f"{where}.arg", "must be a non-negative integer or 'any'"))
        for key in ("kwarg", "kwargs"):
            if key in item:
                kw = item[key]
                names = [kw] if isinstance(kw, str) else kw
                if not isinstance(names, list) or not all(isinstance(n, str) and n.isidentifier() for n in names):
                    issues.append((f"{where}.{key}", "must be an identifier or a list of identifiers"))
        if "when" in item:
            issues += self._when_issues(where, item["when"])
        return issues

    def _when_issues(self, where: str, conds) -> list[Issue]:
        issues: list[Issue] = []
        conds = [conds] if isinstance(conds, dict) else conds
        if not isinstance(conds, list) or not conds:
            issues.append((f"{where}.when", "must be a mapping or a list of mappings"))
            return issues
        for j, cond in enumerate(conds):
            cw = f"{where}.when" if len(conds) == 1 else f"{where}.when[{j}]"
            if not isinstance(cond, dict):
                issues.append((cw, "must be a mapping"))
                continue
            if not isinstance(cond.get("kwarg"), str) or not cond["kwarg"].isidentifier():
                issues.append((f"{cw}.kwarg", "is required and must be an identifier"))
            if "pos" in cond and not _nonneg_int(cond["pos"]):
                issues.append((f"{cw}.pos", "must be a non-negative integer"))
            ops = [k for k in ("is_true", "in", "not_in") if k in cond]
            if len(ops) != 1:
                issues.append((cw, "needs exactly one of is_true, in, not_in"))
            elif ops[0] == "is_true":
                if not isinstance(cond["is_true"], bool):
                    issues.append((f"{cw}.is_true", "must be true or false"))
            else:
                values = cond[ops[0]]
                if not isinstance(values, list) or not values:
                    issues.append((f"{cw}.{ops[0]}", "must be a non-empty list of patterns"))
                else:
                    for k, v in enumerate(values):
                        issues += _pattern_issues(f"{cw}.{ops[0]}[{k}]", v)
            for key in cond:
                if key not in WHEN_KEYS:
                    issues.append((f"{cw}.{key}", "unknown key"))
        return issues

    def compile(self, rule):
        return compile_rule(rule.id, rule.raw)

    def prepare(self, program, rules: Sequence) -> None:
        from ..taint.inter import TaintProgram

        analysis = TaintProgram(program, rules)
        analysis.run()
        program.shared[self.name] = analysis

    def analyze(self, module, rules: Sequence) -> Iterable:
        analysis = module.program.shared.get(self.name)
        if analysis is None:
            return []
        return analysis.findings_for(module.path)
