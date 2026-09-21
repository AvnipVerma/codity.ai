"""Inline suppressions: ``# codity: ignore[rule-id, other-id] reason text``.

Comments are found with the stdlib ``tokenize`` module (never by searching the
source text), then parsed with plain string methods.

Which lines a suppression covers
--------------------------------
A finding is suppressed by a matching comment that is

* on any line of the finding's reported span (for a taint finding that is the
  sink call, so a trailing comment on the first or the last line of a call
  split over several lines both work), or
* on a comment-only line directly above the first line of that span.

A suppression names rule ids explicitly; one for rule A never hides rule B.
A suppression without reason text still suppresses, but is itself reported as
a low-severity ``scanner.suppression-missing-reason`` finding. A malformed one
(``# codity: ignore`` with no brackets, an unclosed bracket, an empty id)
suppresses nothing and is reported under the same meta rule.
"""

from __future__ import annotations

import io
import tokenize
from dataclasses import dataclass, field

from .config import Rule
from .model import Finding, Location, Severity

MISSING_REASON = "scanner.suppression-missing-reason"
UNUSED = "scanner.unused-suppression"
DIRECTIVE = "codity:"

META_RULES = {
    MISSING_REASON: Rule(
        id=MISSING_REASON,
        severity=Severity.LOW,
        cwe=None,
        message="Suppression comment is missing a reason or is malformed",
        kind="scanner",
        raw={},
        name="SuppressionMissingReason",
        description=(
            "Every `# codity: ignore[rule-id]` comment must explain why the finding is safe. "
            "Malformed suppression comments are reported under this rule too."
        ),
        help="Write the justification after the closing bracket: `# codity: ignore[rule-id] reason`.",
        precision="very-high",
    ),
    UNUSED: Rule(
        id=UNUSED,
        severity=Severity.LOW,
        cwe=None,
        message="Suppression comment does not suppress anything",
        kind="scanner",
        raw={},
        name="UnusedSuppression",
        description="An inline suppression that matched no finding (reported with --report-unused-suppressions).",
        help="Remove the stale suppression comment.",
        precision="very-high",
    ),
}

_REASON_PUNCTUATION = "-–—:#; "


@dataclass(slots=True)
class Suppression:
    line: int
    col: int  # 1-based
    end_col: int
    comment_only: bool
    text: str
    rule_ids: tuple[str, ...] = ()
    reason: str = ""
    error: str | None = None
    used: bool = field(default=False)

    def covers(self, loc: Location) -> bool:
        if loc.line <= self.line <= loc.end_line:
            return True
        return self.comment_only and self.line == loc.line - 1


def parse_comment(comment: str) -> tuple[bool, tuple[str, ...], str, str | None]:
    """Parse one comment token. Returns ``(is_directive, rule_ids, reason, error)``."""
    body = comment[1:].strip() if comment.startswith("#") else comment.strip()
    if not body.lower().startswith(DIRECTIVE):
        return False, (), "", None
    rest = body[len(DIRECTIVE):].strip()
    if not rest.lower().startswith("ignore"):
        word = rest.split()[0] if rest.split() else ""
        return True, (), "", f"unknown directive {word!r}; expected 'ignore[rule-id] reason'"
    after = rest[len("ignore"):].lstrip()
    if not after.startswith("["):
        return True, (), "", "expected '[rule-id]' after 'ignore'"
    close = after.find("]")
    if close < 0:
        return True, (), "", "unclosed '[' in suppression"
    ids = tuple(part.strip() for part in after[1:close].split(","))
    if not ids or any(not i for i in ids):
        return True, (), "", "empty rule id in suppression"
    reason = after[close + 1:].strip().lstrip(_REASON_PUNCTUATION).strip()
    return True, ids, reason, None


def parse_suppressions(text: str) -> list[Suppression]:
    out: list[Suppression] = []
    readline = io.StringIO(text).readline
    for tok in tokenize.generate_tokens(readline):
        if tok.type != tokenize.COMMENT:
            continue
        is_directive, ids, reason, error = parse_comment(tok.string)
        if not is_directive:
            continue
        line, col = tok.start
        out.append(
            Suppression(
                line=line,
                col=col + 1,
                end_col=tok.end[1] + 1,
                comment_only=tok.line[:col].strip() == "",
                text=" ".join(tok.string.split()),
                rule_ids=ids,
                reason=reason,
                error=error,
            )
        )
    return out


def apply_suppressions(
    findings: list[Finding],
    suppressions: list[Suppression],
    path: str,
    report_unused: bool = False,
) -> list[Finding]:
    """Mark suppressed findings in place; return the meta-findings produced."""
    for finding in findings:
        for sup in suppressions:
            if sup.error is None and finding.rule_id in sup.rule_ids and sup.covers(finding.location):
                finding.suppressed = True
                finding.suppression_reason = sup.reason or None
                sup.used = True
                break

    meta: list[Finding] = []
    rule = META_RULES[MISSING_REASON]
    for sup in suppressions:
        loc = Location(path, sup.line, sup.col, sup.line, sup.end_col)
        if sup.error is not None:
            meta.append(_meta(rule, loc, f"Malformed suppression comment: {sup.error}", sup))
        elif not sup.reason:
            ids = ", ".join(sup.rule_ids)
            meta.append(
                _meta(rule, loc, f"Suppression of [{ids}] has no reason; explain why after the closing bracket", sup)
            )
        elif report_unused and not sup.used:
            ids = ", ".join(sup.rule_ids)
            meta.append(_meta(META_RULES[UNUSED], loc, f"Suppression of [{ids}] matched no finding", sup))
    return meta


def _meta(rule: Rule, loc: Location, message: str, sup: Suppression) -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        cwe=None,
        message=message,
        location=loc,
        identity=(sup.text,),
        snippet=sup.text,
    )
