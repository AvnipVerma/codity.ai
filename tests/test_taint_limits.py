"""Known limitations (Part 2, section 6.4): these tests pin down behaviour the
analysis deliberately does not support, so the README stays truthful."""

import pytest

pytestmark = pytest.mark.known_limitation

H = "import os, sqlite3\nfrom flask import request, send_file\ncur = sqlite3.connect('x').cursor()\n"


def test_validation_through_a_function_is_not_understood(check):
    # A guard hidden behind a call is invisible to a path-insensitive analysis.
    check(
        H
        + """
def is_valid(col):
    return col in {"name", "email"}

def f():
    col = request.args['sort']
    if is_valid(col):
        cur.execute(f"SELECT * FROM t ORDER BY {col}")  # SINK
"""
    )


def test_realpath_startswith_guard_is_not_recognised(check):
    check(
        H
        + """
BASE = '/srv/files'

def f():
    path = os.path.realpath(os.path.join(BASE, request.args['p']))
    if path.startswith(BASE):
        return send_file(path)  # SINK
""",
        rule="py.path-traversal",
    )


def test_taint_through_exceptions_is_not_tracked(check):
    check(
        H
        + """
def f():
    try:
        raise ValueError(request.args['q'])
    except ValueError as exc:
        cur.execute(str(exc))
"""
    )


def test_implicit_flows_are_not_tracked(check):
    check(H + "def f():\n    q = 'SELECT 1'\n    if request.args['q'] == 'x':\n        q = 'SELECT 2'\n    cur.execute(q)\n")


def test_dynamic_getattr_is_not_followed(check):
    check(H + "def f(name):\n    run = getattr(cur, name)\n    run(request.args['q'])\n")


def test_aliasing_through_mutation_is_not_tracked(check):
    check(H + "def f():\n    a = []\n    b = a\n    b.append(request.args['q'])\n    cur.execute(a[0])\n")


def test_framework_injected_request_parameter_is_not_a_source(check):
    # Django-style views receive `request` as a parameter; it is not flask.request.
    check(H.replace("from flask import request, send_file\n", "") + "def view(request):\n    cur.execute(request.GET['q'])\n")
