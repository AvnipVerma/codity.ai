"""The ``pattern`` rule kind: structural matches that need no data flow.

It currently supports one matcher, literal values bound to suspicious names,
which is what hard-coded-secret rules need::

    match:
      assigned_to: ["*_key", "*_secret", "*password*", "*token*"]
      value: literal_string
      min_entropy: 3.5
      # optional extensions
      min_length: 8
      ignore_values: ["changeme", "<*>", "xxx*"]
      ignore_names: ["*_url", "*_field"]
      forms: [assign, attribute, subscript, keyword, dict_key, default, compare]

``assigned_to`` globs match *identifier names*, not dotted paths: ``*`` matches
any run of characters inside a name (``fnmatch`` semantics), compared
case-insensitively. That is intentionally different from the dotted-path ``*``
used by taint rules, which matches exactly one segment.

Forms (where a "name" comes from):
  assign     ``api_key = "..."`` and ``api_key: str = "..."`` and walrus
  attribute  ``self.api_key = "..."`` (the attribute name)
  subscript  ``config["api_key"] = "..."`` (a constant string key)
  keyword    ``connect(password="...")`` (the keyword name)
  dict_key   ``{"api_key": "..."}`` (a constant string key)
  default    ``def login(password="...")`` (the parameter name)
  compare    ``if token == "..."`` (a name or attribute compared with ``==``)
"""

from __future__ import annotations

import ast
import fnmatch
import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping, Sequence

from ..entropy import shannon_entropy
from ..model import Finding
from .base import Issue, RuleKind

FORMS = ("assign", "attribute", "subscript", "keyword", "dict_key", "default", "compare")
VALUE_KINDS = ("literal_string",)
MATCH_KEYS = frozenset(
    {"assigned_to", "value", "min_entropy", "min_length", "ignore_values", "ignore_names", "forms"}
)


def redact(value: str) -> str:
    """Show a short prefix and the length, never the secret itself.

    Four characters for values of 16+ characters, fewer for shorter ones so a
    short secret is never mostly revealed.
    """
    keep = min(4, len(value) // 4)
    return f"{value[:keep]}…({len(value)} chars)"


@dataclass(frozen=True, slots=True)
class CompiledMatch:
    names: tuple[str, ...]
    ignore_names: tuple[str, ...]
    ignore_values: tuple[str, ...]
    min_entropy: float
    min_length: int
    forms: frozenset[str]


def _str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def _globs_match(name: str, globs: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(name, g) for g in globs)


class PatternKind(RuleKind):
    name = "pattern"
    fields = frozenset({"match"})
    default_precision = "medium"

    def validate(self, rule: Mapping[str, Any]) -> list[Issue]:
        issues: list[Issue] = []
        match = rule.get("match")
        if not isinstance(match, dict):
            return [("match", "is required and must be a mapping")]
        if not _str_list(match.get("assigned_to")) or not match.get("assigned_to"):
            issues.append(("match.assigned_to", "must be a non-empty list of name globs"))
        if match.get("value") not in VALUE_KINDS:
            issues.append(("match.value", f"must be one of {', '.join(VALUE_KINDS)}"))
        ent = match.get("min_entropy", 0)
        if isinstance(ent, bool) or not isinstance(ent, (int, float)) or ent < 0:
            issues.append(("match.min_entropy", "must be a non-negative number"))
        length = match.get("min_length", 1)
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            issues.append(("match.min_length", "must be a non-negative integer"))
        for key in ("ignore_values", "ignore_names"):
            if key in match and not _str_list(match[key]):
                issues.append((f"match.{key}", "must be a list of non-empty strings"))
        if "forms" in match:
            forms = match["forms"]
            if not _str_list(forms) or any(f not in FORMS for f in forms):
                issues.append(("match.forms", f"must be a list drawn from {', '.join(FORMS)}"))
        for key in match:
            if key not in MATCH_KEYS:
                issues.append((f"match.{key}", "unknown key"))
        return issues

    def compile(self, rule) -> CompiledMatch:
        m = rule.raw["match"]
        return CompiledMatch(
            names=tuple(g.lower() for g in m["assigned_to"]),
            ignore_names=tuple(g.lower() for g in m.get("ignore_names", ())),
            ignore_values=tuple(g.lower() for g in m.get("ignore_values", ())),
            min_entropy=float(m.get("min_entropy", 0)),
            min_length=int(m.get("min_length", 1)),
            forms=frozenset(m.get("forms", FORMS)),
        )

    # -- analysis ------------------------------------------------------------------

    def analyze(self, module, rules: Sequence) -> Iterable[Finding]:
        candidates = list(_candidates(module.tree))
        findings: list[Finding] = []
        for rule in rules:
            cm: CompiledMatch = rule.compiled
            seen: set[tuple] = set()
            for form, name, value_node, anchor in candidates:
                if form not in cm.forms:
                    continue
                value = value_node.value
                lname = name.lower()
                if not _globs_match(lname, cm.names) or _globs_match(lname, cm.ignore_names):
                    continue
                if len(value) < max(cm.min_length, 1):
                    continue
                if _globs_match(value.lower(), cm.ignore_values):
                    continue
                entropy = shannon_entropy(value)
                if entropy < cm.min_entropy:
                    continue
                loc = module.location(anchor)
                key = (loc.line, loc.col, name)
                if key in seen:
                    continue
                seen.add(key)
                shown = redact(value)
                digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        cwe=rule.cwe,
                        message=f"{rule.message}: `{name}` = \"{shown}\" (entropy {entropy:.2f})",
                        location=loc,
                        identity=(name, digest),
                        snippet=f'{name} = "{shown}"',
                        properties={"entropy": round(entropy, 2), "form": form},
                    )
                )
        return findings


def _is_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _target_name(target: ast.AST) -> tuple[str, str] | None:
    if isinstance(target, ast.Name):
        return "assign", target.id
    if isinstance(target, ast.Attribute):
        return "attribute", target.attr
    if isinstance(target, ast.Subscript) and _is_str(target.slice):
        return "subscript", target.slice.value
    return None


def _candidates(tree: ast.AST) -> Iterator[tuple[str, str, ast.Constant, ast.AST]]:
    """Yield ``(form, name, string-constant node, node to report)``."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for t in targets:
                if isinstance(t, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
                    if len(t.elts) == len(value.elts):
                        for sub_t, sub_v in zip(t.elts, value.elts):
                            got = _target_name(sub_t)
                            if got and _is_str(sub_v):
                                yield got[0], got[1], sub_v, node
                    continue
                got = _target_name(t)
                if got and _is_str(value):
                    yield got[0], got[1], value, node
        elif isinstance(node, ast.NamedExpr):
            if _is_str(node.value):
                yield "assign", node.target.id, node.value, node
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and _is_str(kw.value):
                    yield "keyword", kw.arg, kw.value, kw
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if _is_str(k) and _is_str(v):
                    yield "dict_key", k.value, v, k
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            positional = args.posonlyargs + args.args
            for param, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
                if _is_str(default):
                    yield "default", param.arg, default, default
            for param, default in zip(args.kwonlyargs, args.kw_defaults):
                if default is not None and _is_str(default):
                    yield "default", param.arg, default, default
        elif isinstance(node, ast.Compare):
            if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
                left, right = node.left, node.comparators[0]
                for named, lit in ((left, right), (right, left)):
                    if _is_str(lit):
                        if isinstance(named, ast.Name):
                            yield "compare", named.id, lit, node
                        elif isinstance(named, ast.Attribute):
                            yield "compare", named.attr, lit, node
