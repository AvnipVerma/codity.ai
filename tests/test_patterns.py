import pytest

from scanner.patterns import UNKNOWN, PatternError, PatternIndex, compile_pattern, matches


def seg(text):
    return tuple(text.split("."))


def test_compile_splits_segments():
    assert compile_pattern("flask.request.args.get") == ("flask", "request", "args", "get")
    assert compile_pattern("*.execute") == ("*", "execute")


def test_builtin_single_segment_is_normalised():
    assert compile_pattern("open") == ("builtins", "open")
    assert compile_pattern("builtins.open") == ("builtins", "open")
    # a non-builtin single segment stays as written
    assert compile_pattern("myfunc") == ("myfunc",)


@pytest.mark.parametrize("bad", ["", "a..b", ".a", "a.", "a.**", "a b", "exec*", "a.1b", 3])
def test_invalid_patterns(bad):
    with pytest.raises(PatternError):
        compile_pattern(bad)


def test_star_matches_exactly_one_segment():
    p = compile_pattern("*.execute")
    assert matches(p, seg("cursor.execute"))
    assert matches(p, (UNKNOWN, "execute"))
    assert not matches(p, seg("sqlite3.Cursor.execute"))
    assert not matches(p, ("execute",))


def test_trailing_star():
    p = compile_pattern("flask.request.form.*")
    assert matches(p, seg("flask.request.form.get"))
    assert matches(p, seg("flask.request.form.getlist"))
    assert not matches(p, seg("flask.request.form"))
    assert not matches(p, seg("flask.request.args.get"))


def test_unknown_segment_only_matches_wildcard():
    assert not matches(compile_pattern("sqlite3.execute"), (UNKNOWN, "execute"))


def test_matching_is_case_sensitive():
    assert not matches(compile_pattern("os.System"), seg("os.system"))


def test_index_returns_all_matches_in_insertion_order():
    idx = PatternIndex()
    idx.add("*.execute", "generic")
    idx.add("sqlite3.Cursor.execute", "typed")
    idx.add("flask.request.form.*", "form")
    idx.add("*.execute", "generic-again")
    got = idx.match([seg("sqlite3.Cursor.execute"), (UNKNOWN, "execute")])
    assert [payload for _, payload in got] == ["generic", "typed", "generic-again"]
    assert idx.match([seg("flask.request.form.get")]) == [("flask.request.form.*", "form")]
    assert idx.match([seg("os.system")]) == []


def test_index_order_independent_of_candidate_order():
    idx = PatternIndex()
    idx.add("a.b", 1)
    idx.add("*.b", 2)
    assert idx.match([seg("a.b"), ("x", "b")]) == idx.match([("x", "b"), seg("a.b")])
