"""Part 2 propagation rules: one focused test per construct.

Each snippet marks the lines where a finding is expected with ``# SINK``;
lines without the marker must produce nothing.
"""

import pytest

H = "import sqlite3\nfrom flask import request\ncur = sqlite3.connect('x').cursor()\n"


def test_assignment_chain(check):
    check(H + "def f():\n    a = request.args['q']\n    b = a\n    c = b\n    cur.execute(c)  # SINK\n")


def test_augmented_assignment(check):
    check(H + "def f():\n    q = 'SELECT * FROM t WHERE a = '\n    q += request.args['q']\n    cur.execute(q)  # SINK\n")


def test_tuple_unpacking(check):
    check(
        H
        + """
def f():
    a, b = request.args['a'], request.args['b']
    cur.execute(a)  # SINK
    x, *rest = request.args.getlist('x')
    cur.execute(rest[0])  # SINK
    (p, (q, r)) = ('const', ('const', request.args['r']))
    cur.execute(p)
    cur.execute(q)
    cur.execute(r)  # SINK
"""
    )


def test_literal_tuple_unpacking_is_positional(check):
    check(H + "def f():\n    a, b = ('SELECT 1', request.args['q'])\n    cur.execute(a)\n    cur.execute(b)  # SINK\n")


def test_walrus(check):
    check(H + "def f():\n    if (x := request.args.get('q')):\n        cur.execute(x)  # SINK\n")


@pytest.mark.parametrize(
    "expr",
    [
        "'SELECT ' + t",
        "t + ' LIMIT 1'",
        "f'SELECT {t}'",
        "f'SELECT {t!r:>10}'",
        "f'SELECT {f\"{t}\"}'",
        "f'{0:{t}}'",
        "'SELECT {}'.format(t)",
        "'SELECT {x}'.format(x=t)",
        "'SELECT {q}'.format(**{'q': t})",
        "'SELECT %s' % t",
        "'SELECT %s %s' % ('a', t)",
        "'SELECT %(q)s' % {'q': t}",
        "''.join([t])",
        "' '.join(['SELECT', t])",
        "'SELECT {q}'.format_map({'q': t})",
    ],
)
def test_string_building(check, expr):
    check(H + f"def f():\n    t = request.args['q']\n    cur.execute({expr})  # SINK\n")


@pytest.mark.parametrize(
    "expr",
    ["t.strip()", "t.lower()", "t.upper()", "t.replace('a', 'b')", "t.encode()", "t.encode().decode()",
     "t.split(',')[0]", "t[1:]", "t[0]", "str(t)", "t.title().strip()"],
)
def test_string_methods_propagate(check, expr):
    check(H + f"def f():\n    t = request.args['q']\n    cur.execute({expr})  # SINK\n")


@pytest.mark.parametrize(
    "expr",
    ["t.startswith('a')", "t.endswith('a')", "t.isdigit()", "t.isalnum()", "t.count('a')", "t.find('a')",
     "len(t)", "bool(t)", "t == 'a'", "'a' in t", "not t", "isinstance(t, str)"],
)
def test_non_injectable_results_do_not_propagate(check, expr):
    check(H + f"def f():\n    t = request.args['q']\n    cur.execute({expr})\n")


def test_list_literal_and_retrieval(check):
    check(H + "def f():\n    lst = ['a', request.args['q']]\n    cur.execute(lst[1])  # SINK\n    cur.execute(lst)  # SINK\n")


@pytest.mark.parametrize(
    "mutation",
    ["lst.append(t)", "lst.extend([t])", "lst.insert(0, t)", "lst.add(t)"],
)
def test_container_mutation(check, mutation):
    check(H + f"def f():\n    t = request.args['q']\n    lst = []\n    {mutation}\n    cur.execute(lst[0])  # SINK\n")


def test_dict_update_and_setdefault(check):
    check(
        H
        + """
def f():
    t = request.args['q']
    d = {}
    d.update({'k': t})
    cur.execute(d['k'])  # SINK
    e = {}
    e.setdefault('k', t)
    cur.execute(e['k'])  # SINK
    cur.execute(e['other'])
"""
    )


def test_dict_is_field_sensitive_on_constant_keys(check):
    check(
        H
        + """
def f():
    params = {'q': request.args['q'], 'order': 'name'}
    cur.execute(params['q'])  # SINK
    cur.execute(params['order'])
    params['order'] = request.args['o']
    cur.execute(params['order'])  # SINK
    params['order'] = 'id'
    cur.execute(params['order'])
"""
    )


def test_dynamic_key_taints_whole_container(check):
    check(H + "def f(k):\n    d = {}\n    d[k] = request.args['q']\n    cur.execute(d['anything'])  # SINK\n")


@pytest.mark.parametrize(
    "read",
    ["d.get('k')", "list(d.values())[0]", "list(d.items())[0][1]", "d.pop('k')", "next(iter(d.values()))"],
)
def test_dict_retrieval(check, read):
    check(H + f"def f():\n    d = {{'k': request.args['q']}}\n    cur.execute({read})  # SINK\n")


def test_for_loop_over_tainted_iterable(check):
    check(H + "def f():\n    for x in request.args.getlist('q'):\n        cur.execute(x)  # SINK\n")


def test_list_pop_and_iter(check):
    check(H + "def f():\n    lst = [request.args['q']]\n    cur.execute(lst.pop())  # SINK\n    cur.execute(next(iter(lst)))  # SINK\n")


@pytest.mark.parametrize(
    "comp",
    ["[x for x in items]", "{x for x in items}", "(x for x in items)", "{x: 1 for x in items}",
     "[y for x in items for y in x]", "[x.upper() for x in items if x]"],
)
def test_comprehensions(check, comp):
    check(H + f"def f():\n    items = request.args.getlist('q')\n    cur.execute(' '.join({comp}))  # SINK\n")


def test_object_attributes(check):
    check(
        H
        + """
class Obj:
    pass

def f():
    o = Obj()
    o.field = request.args['q']
    o.other = 'SELECT 1'
    cur.execute(o.field)  # SINK
    cur.execute(o.other)
"""
    )


def test_unknown_library_call_propagates(check):
    check(H + "import json\ndef f():\n    data = json.loads(request.data)\n    cur.execute(data['q'])  # SINK\n")


def test_local_function_return_value(check):
    check(H + "def build(v):\n    return 'SELECT * FROM t WHERE x = ' + v\n\ndef f():\n    cur.execute(build(request.args['q']))  # SINK\n")


def test_if_else_join(check):
    check(
        H
        + """
def f(flag):
    if flag:
        q = request.args['q']
    else:
        q = 'SELECT 1'
    cur.execute(q)  # SINK
    if flag:
        r = 'SELECT 1'
    elif flag is None:
        r = 'SELECT 2'
    else:
        r = 'SELECT 3'
    cur.execute(r)
"""
    )


def test_ternary(check):
    check(H + "def f(flag):\n    q = request.args['q'] if flag else 'x'\n    cur.execute(q)  # SINK\n")


def test_boolean_operators(check):
    check(H + "def f():\n    q = request.args.get('q') or 'default'\n    cur.execute(q)  # SINK\n    r = request.args.get('r') and 'x'\n    cur.execute(r)  # SINK\n")


def test_match_statement(check):
    check(
        H
        + """
def f(cmd):
    match cmd:
        case 'a':
            q = request.args['q']
        case _:
            q = 'SELECT 1'
    cur.execute(q)  # SINK
    match request.args['m']:
        case str() as captured:
            cur.execute(captured)  # SINK
"""
    )


def test_try_except_else_finally(check):
    check(
        H
        + """
def f():
    try:
        a = request.args['a']
    except KeyError:
        a = 'x'
    cur.execute(a)  # SINK
    try:
        b = 'x'
    except Exception:
        b = request.args['b']
    cur.execute(b)  # SINK
    try:
        c = 'x'
    except Exception:
        pass
    else:
        c = request.args['c']
    finally:
        d = request.args['d']
    cur.execute(c)  # SINK
    cur.execute(d)  # SINK
"""
    )


def test_with_statement(check):
    check(H + "def f():\n    with open('x') as fh:\n        q = request.args['q']\n    cur.execute(q)  # SINK\n")


def test_loop_fixpoint_carries_taint_backwards(check):
    check(
        H
        + """
def f(items):
    q = 'SELECT 1'
    for item in items:
        cur.execute(q)  # SINK
        q = request.args['q']
"""
    )


def test_while_loop(check):
    check(
        H
        + """
def f(n):
    q = 'x'
    while n:
        cur.execute(q)  # SINK
        q = request.args['q']
        n -= 1
"""
    )


def test_break_state_reaches_after_loop(check):
    check(
        H
        + """
def f(items):
    q = 'x'
    for item in items:
        q = request.args['q']
        if item:
            break
        q = 'y'
    cur.execute(q)  # SINK
"""
    )


def test_await_and_async_constructs(check):
    check(
        H
        + """
async def fetch(v):
    return v

async def f(stream, lock):
    q = await fetch(request.args['q'])
    cur.execute(q)  # SINK
    async for row in stream:
        cur.execute(row)
    async with lock as l:
        r = request.args['r']
    cur.execute(r)  # SINK
"""
    )


def test_closure_reads_outer_tainted_variable(check):
    check(
        H
        + """
def f():
    q = request.args['q']
    def inner():
        cur.execute(q)  # SINK
    inner()
"""
    )


def test_lambda_assigned_to_name_gets_a_summary(check):
    check(H + "wrap = lambda v: 'SELECT ' + v\n\ndef f():\n    cur.execute(wrap(request.args['q']))  # SINK\n")


def test_inline_lambda_closure(check):
    check(H + "def f():\n    q = request.args['q']\n    run = lambda: cur.execute(q)  # SINK\n    run()\n")


def test_module_level_value_read_in_function(check):
    check(H + "USER = request.args.get('u')\n\ndef f():\n    cur.execute(USER)  # SINK\n")


def test_global_declaration_writes_through(check):
    check(
        H
        + """
current = 'SELECT 1'

def set_it():
    global current
    current = request.args['q']

def use_it():
    cur.execute(current)  # SINK
"""
    )


def test_nonlocal_and_closures_over_params_are_not_tracked(check):
    # a closure over the *enclosing function's parameter* is a documented gap
    check(H + "def f(p):\n    def inner():\n        cur.execute(p)\n    inner()\n\ndef g():\n    f(request.args['q'])\n")


def test_source_used_directly_in_sink(check):
    check(H + "def f():\n    cur.execute(request.args['q'])  # SINK\n")


def test_two_sinks_two_findings(check):
    check(H + "def f():\n    q = request.args['q']\n    cur.execute(q)  # SINK\n    cur.executemany(q, [])  # SINK\n")


def test_one_sink_two_sources_two_findings(run_scan):
    result = run_scan(H + "def f():\n    q = request.args['a'] + request.args['b']\n    cur.execute(q)\n")
    assert len(result.findings) == 2
    assert {f.path[0].message for f in result.findings} == {
        "untrusted data from `request.args['a']`",
        "untrusted data from `request.args['b']`",
    }


def test_keyword_argument_to_sink(check):
    check(H + "def f():\n    cur.execute(sql=request.args['q'])  # SINK\n    cur.execute('SELECT 1', params=request.args['q'])\n")


def test_starred_argument_to_sink(check):
    check(H + "def f():\n    cur.execute(*[request.args['q']])  # SINK\n")


def test_method_on_string_literal(check):
    check(H + "def f():\n    cur.execute('SELECT {}'.format(request.args['q']))  # SINK\n")


def test_decorated_view_is_analysed(check):
    check(
        H
        + """
from flask import Flask
app = Flask(__name__)

@app.route('/x')
def view():
    cur.execute(request.args['q'])  # SINK
"""
    )


def test_annotations_and_dataclasses_do_not_crash(check):
    check(
        H
        + """
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Query:
    text: str
    limit: Optional[int] = None
    tags: list = field(default_factory=list)

def f() -> None:
    q: str = request.args['q']
    cur.execute(q)  # SINK
    ok: Optional[str] = None
    cur.execute(ok)
"""
    )
