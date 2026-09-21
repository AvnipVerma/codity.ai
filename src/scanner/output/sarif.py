"""SARIF 2.1.0 output.

Determinism: no timestamps, no absolute paths, no machine-specific values.
``originalUriBaseIds.SRCROOT`` carries only a description, never the scan
root's absolute path, so the same checkout produces the same bytes on any
machine. Consumers resolve ``uriBaseId: SRCROOT`` against their own checkout.

Columns are 1-based and counted in Unicode code points
(``run.columnKind = "unicodeCodePoints"``).
"""

from __future__ import annotations

import json
from urllib.parse import quote

from .. import INFORMATION_URI, TOOL_NAME, __version__
from ..baseline import FINGERPRINT_VERSION
from ..engine import ScanResult
from ..model import Finding, Location, PathStep, Severity
from ..suppress import META_RULES

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
FINGERPRINT_KEY = "codityFinding/v1"
assert FINGERPRINT_VERSION.endswith("v1")

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}


def _cwe_uri(cwe: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe.split('-', 1)[1]}.html"


def _rule_descriptor(rule) -> dict:
    tags = ["security", rule.cwe] if rule.cwe else ["scanner"]
    tags += [t for t in rule.tags if t not in tags]
    props = {
        "tags": tags,
        "precision": rule.precision,
        "security-severity": SECURITY_SEVERITY[rule.severity],
        "severity": rule.severity.label,
    }
    if rule.cwe:
        props["cwe"] = rule.cwe
    help_text = rule.help or (f"{rule.message}. See {rule.cwe}." if rule.cwe else rule.message)
    desc = {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.message},
        "fullDescription": {"text": rule.description or rule.message},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": props,
    }
    if rule.cwe:
        desc["helpUri"] = _cwe_uri(rule.cwe)
    return desc


def _uri(path: str) -> str:
    return quote(path, safe="/")


def _physical(loc: Location) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": _uri(loc.file), "uriBaseId": "SRCROOT"},
            "region": {
                "startLine": loc.line,
                "startColumn": loc.col,
                "endLine": loc.end_line,
                "endColumn": max(loc.end_col, 1),
            },
        }
    }


def _flow_location(step: PathStep, order: int) -> dict:
    location = _physical(step.location)
    location["message"] = {"text": step.message}
    return {"location": location, "kinds": [step.kind.value], "executionOrder": order}


def _result(finding: Finding, rule_index: dict[str, int], baseline_used: bool) -> dict:
    props = {"severity": finding.severity.label}
    if finding.cwe:
        props["cwe"] = finding.cwe
    for key in sorted(finding.properties):
        props[key] = finding.properties[key]
    res = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index[finding.rule_id],
        "level": LEVELS[finding.severity],
        "message": {"text": finding.message},
        "locations": [_physical(finding.location)],
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "properties": props,
    }
    if finding.path:
        res["codeFlows"] = [
            {
                "threadFlows": [
                    {"locations": [_flow_location(step, i + 1) for i, step in enumerate(finding.path)]}
                ]
            }
        ]
    if finding.suppressed:
        sup = {"kind": "inSource", "status": "accepted"}
        if finding.suppression_reason:
            sup["justification"] = finding.suppression_reason
        res["suppressions"] = [sup]
    if baseline_used:
        res["baselineState"] = "new"
    return res


def to_sarif(result: ScanResult) -> dict:
    rules = list(result.rules) + [META_RULES[k] for k in sorted(META_RULES)]
    rule_index = {r.id: i for i, r in enumerate(rules)}
    findings = sorted(result.findings + result.suppressed, key=Finding.sort_key)
    invocation: dict = {"executionSuccessful": True}
    if result.diagnostics:
        notes = []
        for d in result.diagnostics:
            note: dict = {"level": "warning", "message": {"text": d.message}}
            if d.file:
                note["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"uri": _uri(d.file), "uriBaseId": "SRCROOT"}}}
                ]
            notes.append(note)
        invocation["toolExecutionNotifications"] = notes
    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": [_rule_descriptor(r) for r in rules],
            }
        },
        "originalUriBaseIds": {"SRCROOT": {"description": {"text": "The directory that was scanned."}}},
        "columnKind": "unicodeCodePoints",
        "invocations": [invocation],
        "results": [_result(f, rule_index, result.baseline_used) for f in findings],
    }
    return {"$schema": SCHEMA_URI, "version": "2.1.0", "runs": [run]}


def render_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
