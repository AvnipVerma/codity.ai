"""Interprocedural analysis within one file (Part 2, section 7.1)."""

H = "import sqlite3\nfrom flask import request\ncur = sqlite3.connect('x').cursor()\n"


def test_param_to_sink_reported_with_path_through_callee(check):
    result = check(
        H
        + """
def run_query(q):
    cur.execute("SELECT * FROM t WHERE n = '%s'" % q)  # SINK

def view():
    user_input = request.args['name']
    run_query(user_input)
"""
    )
    [f] = result.findings
    kinds = [s.kind.value for s in f.path]
    assert kinds == ["source", "step", "call", "step", "step", "sink"]
    call = f.path[2]
    assert call.location.line == 10 and "run_query()" in call.message
    assert f.path[3].message == "enters `run_query()` as parameter `q`"


def test_source_to_return(check):
    check(H + "def get_q():\n    return request.args['q']\n\ndef view():\n    cur.execute(get_q())  # SINK\n")


def test_param_to_return_chain_across_three_functions(check):
    check(
        H
        + """
def a(x):
    return x.strip()

def b(y):
    return 'SELECT ' + a(y)

def c():
    cur.execute(b(request.args['q']))  # SINK
"""
    )


def test_sink_two_calls_deep(check):
    check(
        H
        + """
def inner(v):
    cur.execute(v)  # SINK

def outer(w):
    inner('SELECT ' + w)

def view():
    outer(request.args['q'])
"""
    )


def test_callee_sanitizes_its_parameter(check):
    check(H + "def to_id(v):\n    return int(v)\n\ndef view():\n    cur.execute('SELECT %d' % to_id(request.args['id']))\n")


def test_clean_return_of_project_function_is_trusted(check):
    check(H + "def const(v):\n    return 'SELECT 1'\n\ndef view():\n    cur.execute(const(request.args['q']))\n")


def test_keyword_default_varargs_kwargs_binding(check):
    check(
        H
        + """
def kw(a, b='SELECT 1'):
    cur.execute(b)  # SINK

def star(*args):
    cur.execute(args[0])  # SINK

def dstar(**kwargs):
    cur.execute(kwargs['q'])  # SINK

def safe_default(a, b='SELECT 1'):
    cur.execute(b)

def view():
    t = request.args['q']
    kw('x', b=t)
    star(t)
    dstar(q=t)
    safe_default(t)
"""
    )


def test_recursion_terminates_and_finds_flow(check):
    check(
        H
        + """
def rec(q, n):
    if n == 0:
        cur.execute(q)  # SINK
        return q
    return rec(q + ' ', n - 1)

def even(q, n):
    return q if n == 0 else odd(q, n - 1)

def odd(q, n):
    return even(q, n - 1)

def view():
    rec(request.args['q'], 3)
    cur.execute(even(request.args['q'], 4))  # SINK
"""
    )


def test_self_attribute_flows_between_methods(check):
    result = check(
        H
        + """
class Repo:
    def __init__(self, conn, name):
        self.conn = conn
        self.name = name
        self.table = 'users'

    def find(self):
        self.conn.execute('SELECT * FROM ' + self.table + " WHERE name = '" + self.name + "'")  # SINK

def view():
    repo = Repo(cur, request.args['name'])
    repo.find()
"""
    )
    [f] = result.findings
    messages = [s.message for s in f.path]
    assert "passed to `Repo.__init__()` as `name`" in messages
    assert any(m.startswith("stored in `self.name`") for m in messages)
    assert any(m.startswith("read from `self.name`") for m in messages)


def test_self_attribute_set_from_source_in_another_method(check):
    check(
        H
        + """
class Handler:
    def load(self):
        self.q = request.args['q']

    def run(self):
        cur.execute(self.q)  # SINK
"""
    )


def test_method_call_on_self_uses_summary(check):
    check(
        H
        + """
class Service:
    def _quote(self, v):
        return "'" + v + "'"

    def lookup(self):
        cur.execute('SELECT * FROM t WHERE n = ' + self._quote(request.args['n']))  # SINK
"""
    )


def test_instance_method_param_to_sink(check):
    check(
        H
        + """
class Database:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)

    def query(self, sql):
        return self.conn.execute(sql)  # SINK

db = Database('app.db')

def view():
    db.query('SELECT * FROM t WHERE id = ' + request.args['id'])
"""
    )


def test_project_class_with_execute_method_is_not_a_db_sink(check):
    # `*.execute` would match any .execute(); a project class we can see is analysed instead.
    check(
        H
        + """
class TaskExecutor:
    def execute(self, task):
        return task.upper()

executor = TaskExecutor()

def view():
    executor.execute(request.args['task'])
"""
    )


def test_classmethod_staticmethod_and_inheritance(check):
    check(
        H
        + """
class Base:
    def find(self, v):
        cur.execute('SELECT ' + v)  # SINK

    @staticmethod
    def raw(v):
        cur.execute(v)  # SINK

    @classmethod
    def build(cls, v):
        return cls.wrap(v)

    @classmethod
    def wrap(cls, v):
        return 'SELECT ' + v

class Child(Base):
    pass

def view():
    t = request.args['q']
    Child().find(t)
    Base.raw(t)
    cur.execute(Base.build(t))  # SINK
"""
    )


def test_super_init_stores_field(check):
    check(
        H
        + """
class Base:
    def __init__(self, q):
        self.q = q

class Child(Base):
    def __init__(self, q):
        super().__init__(q)

    def run(self):
        cur.execute(self.q)  # SINK

def view():
    Child(request.args['q']).run()
"""
    )


def test_fields_set_on_instance_before_method_call(check):
    check(
        H
        + """
class Job:
    def run(self):
        cur.execute(self.sql)  # SINK

def view():
    job = Job()
    job.sql = 'SELECT ' + request.args['q']
    job.run()
"""
    )


def test_nested_function_in_route_factory(check):
    check(
        H
        + """
from flask import Flask

def create_app():
    app = Flask(__name__)

    @app.route('/q')
    def query():
        cur.execute(request.args['q'])  # SINK

    return app
"""
    )


def test_same_sink_from_two_call_sites_gives_two_findings(run_scan):
    result = run_scan(
        H
        + "def run(q):\n    cur.execute(q)\n\ndef a():\n    run(request.args['a'])\n\ndef b():\n    run(request.form['b'])\n"
    )
    assert len(result.findings) == 2
    assert len({f.location for f in result.findings}) == 1
