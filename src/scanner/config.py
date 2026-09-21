"""Loading and validating rules.yaml.

Common fields (id, severity, cwe, message, kind) are checked here. Each kind
validates its own section through its registered handler, so the loader never
needs to know what a "source" or a "match" block is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from .kinds import REGISTRY, get_kind
from .model import Severity

REQUIRED_FIELDS = ("id", "severity", "cwe", "message", "kind")
OPTIONAL_FIELDS = ("name", "description", "help", "precision", "tags")
COMMON_FIELDS = frozenset(REQUIRED_FIELDS + OPTIONAL_FIELDS)
PRECISIONS = ("very-high", "high", "medium", "low")


class RuleError(Exception):
    """The rules file is invalid. The message lists every problem found."""


@dataclass(slots=True)
class Rule:
    id: str
    severity: Severity
    cwe: str | None
    message: str
    kind: str
    raw: dict
    name: str = ""
    description: str | None = None
    help: str | None = None
    precision: str = "medium"
    tags: tuple[str, ...] = ()
    compiled: Any = field(default=None, repr=False)


def _valid_cwe(value: object) -> bool:
    return isinstance(value, str) and value.startswith("CWE-") and value[4:].isdigit()


def _pascal(rule_id: str) -> str:
    tail = rule_id.rsplit(".", 1)[-1]
    parts = tail.replace("_", "-").split("-")
    return "".join(p[:1].upper() + p[1:] for p in parts if p) or rule_id


def parse_rules(data: Any, source: str = "rules.yaml") -> tuple[list[Rule], list[str]]:
    """Validate an already-parsed YAML document. Returns ``(rules, warnings)``."""
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(data, dict) or "rules" not in data:
        raise RuleError(f"{source}: top level must be a mapping with a 'rules' list")
    for key in sorted(k for k in data if k != "rules"):
        warnings.append(f"{source}: unknown top-level key {key!r} ignored")
    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise RuleError(f"{source}: 'rules' must be a list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules):
        where = f"rules[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{source}: {where}: each rule must be a mapping")
            continue
        rid = raw.get("id")
        label = f"rule {rid!r}" if isinstance(rid, str) and rid else where

        def err(field_name: str, message: str) -> None:
            errors.append(f"{source}: {label}: field '{field_name}': {message}")

        before = len(errors)
        for name in REQUIRED_FIELDS:
            if name not in raw or raw[name] is None or raw[name] == "":
                err(name, "is required")
        if isinstance(rid, str) and rid:
            if rid in seen:
                err("id", f"duplicate rule id {rid!r}")
            seen.add(rid)
        elif "id" in raw and raw["id"] not in (None, ""):
            err("id", "must be a non-empty string")
        sev = raw.get("severity")
        if sev not in (None, ""):
            if not isinstance(sev, str) or sev.lower() not in ("critical", "high", "medium", "low"):
                err("severity", f"must be one of critical, high, medium, low (got {sev!r})")
        cwe = raw.get("cwe")
        if cwe not in (None, "") and not _valid_cwe(cwe):
            err("cwe", f"must look like 'CWE-<digits>' (got {cwe!r})")
        msg = raw.get("message")
        if msg not in (None, "") and not isinstance(msg, str):
            err("message", "must be a string")
        prec = raw.get("precision")
        if prec is not None and prec not in PRECISIONS:
            err("precision", f"must be one of {', '.join(PRECISIONS)}")
        tags = raw.get("tags")
        if tags is not None and not (isinstance(tags, list) and all(isinstance(t, str) for t in tags)):
            err("tags", "must be a list of strings")

        kind_name = raw.get("kind")
        handler = get_kind(kind_name) if isinstance(kind_name, str) else None
        if kind_name not in (None, "") and handler is None:
            known = ", ".join(sorted(REGISTRY))
            err("kind", f"unknown kind {kind_name!r} (registered kinds: {known})")
        if handler is not None:
            for field_name, message in handler.validate(raw):
                err(field_name, message)
            known_fields = COMMON_FIELDS | handler.fields
            for key in raw:
                if key not in known_fields:
                    warnings.append(f"{source}: {label}: unknown field {key!r} ignored")
        if len(errors) != before or handler is None:
            continue

        rule = Rule(
            id=rid,
            severity=Severity.parse(sev),
            cwe=cwe,
            message=msg,
            kind=kind_name,
            raw=raw,
            name=raw.get("name") or _pascal(rid),
            description=raw.get("description"),
            help=raw.get("help"),
            precision=prec or handler.default_precision,
            tags=tuple(tags or ()),
        )
        try:
            rule.compiled = handler.compile(rule)
        except ValueError as exc:  # PatternError and friends
            errors.append(f"{source}: {label}: {exc}")
            continue
        rules.append(rule)

    if errors:
        raise RuleError("\n".join(errors))
    return rules, warnings


def load_rules(path: str) -> tuple[list[Rule], list[str]]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        raise RuleError(f"rules file not found: {path}") from None
    except OSError as exc:
        raise RuleError(f"cannot read rules file {path}: {exc}") from None
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from None
    return parse_rules(data, source=path)
