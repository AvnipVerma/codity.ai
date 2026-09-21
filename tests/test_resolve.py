import ast
import textwrap

from scanner.resolve import PATH, RET, ModuleResolver, Ref


def resolver(code, module="app", is_package=False):
    return ModuleResolver(module, is_package, ast.parse(textwrap.dedent(code)))


def names(res, expr):
    node = ast.parse(expr, mode="eval").body
    return sorted(r.name for r in res.refs_for(node, res.module_lookup) if r.kind == PATH)


def test_plain_import():
    res = resolver("import os")
    assert names(res, "os.system") == ["os.system"]


def test_dotted_import_binds_top_package():
    res = resolver("import os.path")
    assert names(res, "os.path.join") == ["os.path.join"]


def test_import_as():
    res = resolver("import subprocess as sp")
    assert names(res, "sp.run") == ["subprocess.run"]


def test_from_import():
    res = resolver("from flask import request")
    assert names(res, "request.args.get") == ["flask.request.args.get"]


def test_from_import_as():
    res = resolver("from flask import request as req")
    assert names(res, "req.form") == ["flask.request.form"]


def test_from_import_function_alias():
    res = resolver("from os import system as run_cmd")
    assert names(res, "run_cmd") == ["os.system"]


def test_builtins_resolve_unless_shadowed():
    assert names(resolver(""), "open") == ["builtins.open"]
    assert names(resolver("def open(p): pass"), "open") == ["app.open"]
    assert names(resolver("open = 3"), "open") == []
    assert names(resolver("from io import open"), "open") == ["io.open"]


def test_relative_imports():
    res = resolver("from .db import query\nfrom .. import util", module="pkg.sub.views")
    assert names(res, "query") == ["pkg.sub.db.query"]
    assert names(res, "util") == ["pkg.util"]


def test_relative_import_in_package_init():
    res = resolver("from . import helpers", module="pkg", is_package=True)
    assert names(res, "helpers.run") == ["pkg.helpers.run"]


def test_relative_import_above_top_level_is_unresolved():
    res = resolver("from ... import x", module="pkg.mod")
    assert names(res, "x") == []


def test_conditional_import_has_all_candidates():
    res = resolver(
        """
        try:
            import ujson as json
        except ImportError:
            import json
        """
    )
    assert names(res, "json.loads") == ["json.loads", "ujson.loads"]


def test_module_level_alias_of_attribute():
    res = resolver("import flask\nreq = flask.request\nr2 = req")
    assert names(res, "req.args") == ["flask.request.args"]
    assert names(res, "r2.args") == ["flask.request.args"]


def test_getattr_with_constant_string():
    res = resolver("import os")
    assert names(res, "getattr(os, 'system')") == ["os.system"]


def test_getattr_with_dynamic_string_is_not_followed():
    res = resolver("import os")
    node = ast.parse("getattr(os, name)", mode="eval").body
    refs = res.refs_for(node, res.module_lookup)
    assert all(r.kind == RET for r in refs)  # only "the result of calling getattr"


def test_unknown_names_do_not_resolve():
    res = resolver("")
    assert names(res, "cur.execute") == []


def test_star_import_is_not_resolved():
    res = resolver("from os import *")
    assert names(res, "system") == []


def test_call_result_reference():
    res = resolver("import sqlite3\nconn = sqlite3.connect('x')")
    assert Ref(RET, "sqlite3.connect") in res.bindings["conn"]


def test_function_level_imports_are_not_module_bindings():
    res = resolver("def f():\n    import os\n")
    assert "os" not in res.bindings
