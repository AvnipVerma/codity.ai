from scanner.suppress import MISSING_REASON, UNUSED, parse_comment, parse_suppressions

H = "import os\nfrom flask import request\n"
CMD = "py.command-injection"


def reported(result):
    return sorted((f.rule_id, f.location.line) for f in result.findings)


def test_trailing_comment_suppresses(run_scan):
    result = run_scan(H + f"os.system(request.args['c'])  # codity: ignore[{CMD}] admin-only endpoint\n")
    assert reported(result) == []
    [s] = result.suppressed
    assert s.suppression_reason == "admin-only endpoint"


def test_comment_on_line_above_suppresses(run_scan):
    result = run_scan(H + f"# codity: ignore[{CMD}] input is an allowlisted host name\nos.system(request.args['c'])\n")
    assert reported(result) == []


def test_comment_two_lines_above_does_not_suppress(run_scan):
    result = run_scan(H + f"# codity: ignore[{CMD}] reason\nx = 1\nos.system(request.args['c'])\n")
    assert reported(result) == [(CMD, 5)]


def test_trailing_comment_on_previous_code_line_does_not_suppress_next_line(run_scan):
    result = run_scan(H + f"x = 1  # codity: ignore[{CMD}] reason\nos.system(request.args['c'])\n")
    assert reported(result) == [(CMD, 4)]


def test_suppression_for_other_rule_does_not_apply(run_scan):
    result = run_scan(H + "os.system(request.args['c'])  # codity: ignore[py.sql-injection] wrong rule\n")
    assert reported(result) == [(CMD, 3)]


def test_multiple_rule_ids(run_scan):
    result = run_scan(H + f"os.system(request.args['c'])  # codity: ignore[py.sql-injection, {CMD}] both reviewed\n")
    assert reported(result) == []


def test_missing_reason_still_suppresses_but_is_reported(run_scan):
    result = run_scan(H + f"os.system(request.args['c'])  # codity: ignore[{CMD}]\n")
    assert reported(result) == [(MISSING_REASON, 3)]
    [meta] = result.findings
    assert meta.severity.label == "low" and meta.cwe is None
    assert meta.location.col == len("os.system(request.args['c'])  ") + 1
    assert [s.rule_id for s in result.suppressed] == [CMD]


def test_punctuation_only_reason_counts_as_missing(run_scan):
    result = run_scan(H + f"os.system(request.args['c'])  # codity: ignore[{CMD}] --\n")
    assert reported(result) == [(MISSING_REASON, 3)]


def test_malformed_suppressions_suppress_nothing(run_scan):
    for comment in ("# codity: ignore", "# codity: ignore[py.command-injection", "# codity: ignore[] x", "# codity: disable"):
        result = run_scan(H + f"os.system(request.args['c'])  {comment}\n")
        assert reported(result) == [(CMD, 3), (MISSING_REASON, 3)], comment


def test_multiline_call_first_line_last_line_and_line_above(run_scan):
    call = "os.system(\n    request.args['c']\n)"
    first = call.replace("os.system(", f"os.system(  # codity: ignore[{CMD}] reviewed", 1)
    last = call[:-1] + f")  # codity: ignore[{CMD}] reviewed"
    above = f"# codity: ignore[{CMD}] reviewed\n" + call
    for variant in (first, last, above):
        assert reported(run_scan(H + variant + "\n")) == [], variant


def test_directive_inside_string_is_not_a_comment(run_scan):
    result = run_scan(H + f"os.system(request.args['c'] + '# codity: ignore[{CMD}] nope')\n")
    assert reported(result) == [(CMD, 3)]


def test_unused_suppressions_reported_behind_flag(run_scan):
    code = H + f"x = 1  # codity: ignore[{CMD}] stale\n"
    assert reported(run_scan(code)) == []
    assert reported(run_scan(code, report_unused_suppressions=True)) == [(UNUSED, 3)]


def test_suppression_applies_to_secret_rule_too(run_scan):
    code = 'API_KEY = "Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1"  # codity: ignore[py.hardcoded-secret] public demo key\n'
    assert reported(run_scan(code)) == []


def test_parse_comment_unit():
    assert parse_comment("# codity: ignore[a.b] why") == (True, ("a.b",), "why", None)
    assert parse_comment("#codity:ignore[a,b]") == (True, ("a", "b"), "", None)
    assert parse_comment("# regular comment") == (False, (), "", None)
    assert parse_comment("# codity: ignore(a)")[3] is not None


def test_parse_suppressions_records_comment_only_lines():
    sups = parse_suppressions("x = 1  # codity: ignore[r] a\n# codity: ignore[r] b\ny = 2\n")
    assert [(s.line, s.comment_only) for s in sups] == [(1, False), (2, True)]
