"""Part 2 kill rules: each snippet must produce NO finding (unless marked)."""

import pytest

H = "import sqlite3, uuid, shlex, subprocess, os\nfrom flask import request\ncur = sqlite3.connect('x').cursor()\n"


def test_reassignment_to_clean_value(check):
    check(H + "def f():\n    q = request.args['q']\n    q = 'SELECT 1'\n    cur.execute(q)\n")


def test_reassignment_in_one_branch_only_keeps_taint(check):
    check(H + "def f(c):\n    q = request.args['q']\n    if c:\n        q = 'SELECT 1'\n    cur.execute(q)  # SINK\n")


def test_declared_sanitizer_kills_for_its_rule(check):
    check(H + "def f():\n    q = int(request.args['id'])\n    cur.execute(f'SELECT * FROM t WHERE id = {q}')\n")


def test_sanitizer_is_rule_specific(check):
    # shlex.quote sanitizes command injection, not SQL injection
    code = H + "def f():\n    q = shlex.quote(request.args['q'])\n    os.system('ls ' + q)\n    cur.execute(q)  # SINK\n"
    check(code, rule="py.sql-injection")
    check(code.replace("  # SINK", ""), rule="py.command-injection")


def test_sanitizer_inside_helper_function(check):
    check(H + "def clean(v):\n    return int(v)\n\ndef f():\n    cur.execute('SELECT %d' % clean(request.args['id']))\n")


@pytest.mark.parametrize("conv", ["int", "float", "uuid.UUID", "bool"])
def test_type_narrowing_conversions(check, conv):
    check(H + f"def f():\n    v = {conv}(request.args['v'])\n    cur.execute('SELECT * FROM t WHERE id = ' + str(v))\n")


def test_int_does_not_sanitize_deserialization(check):
    check(H + "import pickle\ndef f():\n    pickle.loads(bytes(int(request.args['v'])))  # SINK\n",
          rule="py.insecure-deserialization")


@pytest.mark.parametrize(
    "expr",
    ["'SELECT 1'", "'SELECT ' + '*'", "'x' * 3", "f'SELECT {1}'", "'SELECT {}'.format('a')",
     "'SELECT %s' % 'a'", "b'SELECT'", "42", "None", "QUERY"],
)
def test_provably_constant(check, expr):
    check(H + "QUERY = 'SELECT * FROM t'\n" + f"def f():\n    cur.execute({expr})\n")


def test_every_reaching_definition_constant(check):
    check(H + "def f(c):\n    if c:\n        q = 'SELECT 1'\n    else:\n        q = 'SELECT 2'\n    cur.execute(q)\n")


def test_del_removes_binding(check):
    check(H + "def f():\n    q = request.args['q']\n    del q\n    q = 'SELECT 1'\n    cur.execute(q)\n")


def test_parameterized_queries_are_safe(check):
    check(
        H
        + """
def f():
    uid = request.args['id']
    cur.execute("SELECT * FROM t WHERE id = %s", (uid,))
    cur.execute("SELECT * FROM t WHERE id = ?", [uid])
    cur.execute("SELECT * FROM t WHERE id = :id", {"id": uid})
    cur.execute("SELECT * FROM t WHERE id = %s" % uid)  # SINK
"""
    )


def test_allowlist_membership_guard_kills_in_branch(check):
    check(
        H
        + """
ALLOWED = {"name", "created"}

def f():
    col = request.args['sort']
    if col in ALLOWED:
        cur.execute(f"SELECT * FROM t ORDER BY {col}")
    cur.execute(f"SELECT * FROM t ORDER BY {col}")  # SINK
    if col not in ("a", "b"):
        return
    cur.execute(f"SELECT * FROM t ORDER BY {col}")
"""
    )


def test_allowlist_guard_with_abort(check):
    check(
        H
        + """
from flask import abort
ALLOWED_COLUMNS = ("name", "email")

def f():
    col = request.args['sort']
    if col not in ALLOWED_COLUMNS:
        abort(400)
    cur.execute(f"SELECT * FROM users ORDER BY {col}")
"""
    )


def test_mutated_collection_is_not_an_allowlist(check):
    check(
        H
        + """
ALLOWED = {"name"}

def add(x):
    ALLOWED.add(x)

def f():
    col = request.args['sort']
    if col in ALLOWED:
        cur.execute(f"SELECT * FROM t ORDER BY {col}")  # SINK
"""
    )


def test_equality_and_digit_guards(check):
    check(
        H
        + """
def f():
    mode = request.args['mode']
    if mode == 'fast':
        cur.execute('SELECT ' + mode)
    uid = request.args['id']
    if not uid.isdigit():
        raise ValueError('bad id')
    cur.execute('SELECT * FROM t WHERE id = ' + uid)
"""
    )


def test_lookup_table_indexed_by_tainted_key_is_clean(check):
    check(H + "ORDER = {'new': 'created DESC', 'old': 'created ASC'}\ndef f():\n    cur.execute('SELECT * FROM t ORDER BY ' + ORDER[request.args['o']])\n")


def test_subprocess_list_without_shell(check):
    check(H + "def f():\n    subprocess.run(['ls', request.args['d']])\n    subprocess.run(['ls', request.args['d']], shell=False)\n",
          rule="py.command-injection")
