"""Cross-file analysis (Part 2, section 7.2)."""

VIEW_HEADER = "from flask import request\n"
DB = "import sqlite3\n\ndef run_query(q):\n    sqlite3.connect('x').execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")  # SINK\n"


def test_relative_import_within_package(check):
    result = check(
        DB,
        files={
            "app/__init__.py": "",
            "app/views.py": VIEW_HEADER + "from .db import run_query\n\ndef view():\n    run_query(request.args['n'])\n",
        },
        target="app/db.py",
    )
    [f] = result.findings
    assert [s.location.file for s in f.path] == ["app/views.py", "app/views.py", "app/db.py", "app/db.py", "app/db.py"]


def test_absolute_import_as_module_alias(check):
    check(
        DB,
        files={
            "pkg/__init__.py": "",
            "main.py": VIEW_HEADER + "import pkg.db as db\n\ndef view():\n    db.run_query(request.args['n'])\n",
        },
        target="pkg/db.py",
    )


def test_from_package_import_module(check):
    check(
        DB,
        files={
            "pkg/__init__.py": "",
            "main.py": VIEW_HEADER + "from pkg import db\n\ndef view():\n    db.run_query(request.args['n'])\n",
        },
        target="pkg/db.py",
    )


def test_reexport_through_package_init(check):
    check(
        DB,
        files={
            "pkg/__init__.py": "from .db import run_query\n",
            "main.py": VIEW_HEADER + "from pkg import run_query\n\ndef view():\n    run_query(request.args['n'])\n",
        },
        target="pkg/db.py",
    )


def test_parent_relative_import(check):
    check(
        DB,
        files={
            "app/__init__.py": "",
            "app/data/__init__.py": "",
            "app/web/__init__.py": "",
            "app/web/views.py": VIEW_HEADER + "from ..data.db import run_query\n\ndef view():\n    run_query(request.args['n'])\n",
        },
        target="app/data/db.py",
    )


def test_source_returned_from_other_module(check):
    check(
        "import sqlite3\nfrom helpers import get_name\n\ndef view():\n    sqlite3.connect('x').execute('SELECT ' + get_name())  # SINK\n",
        files={"helpers.py": VIEW_HEADER + "def get_name():\n    return request.args['n']\n"},
        target="views.py",
    )


def test_import_cycle_terminates(check):
    check(
        "import sqlite3\nimport b\n\ndef sink(q):\n    sqlite3.connect('x').execute(q)  # SINK\n\ndef start(q):\n    b.bounce(q)\n",
        files={"b.py": VIEW_HEADER + "import a\n\ndef bounce(q):\n    a.sink(q)\n\ndef view():\n    a.start(request.args['q'])\n"},
        target="a.py",
    )


def test_src_layout(check):
    check(
        DB,
        files={
            "src/shop/__init__.py": "",
            "src/shop/views.py": VIEW_HEADER + "from shop.db import run_query\n\ndef view():\n    run_query(request.args['n'])\n",
        },
        target="src/shop/db.py",
    )


def test_tainted_module_global_imported_elsewhere(check):
    check(
        "import sqlite3\nfrom config import SEARCH\n\ndef view():\n    sqlite3.connect('x').execute(SEARCH)  # SINK\n",
        files={"config.py": VIEW_HEADER + "SEARCH = 'SELECT ' + request.args.get('s', '')\n"},
        target="views.py",
    )


def test_class_imported_from_other_module(check):
    check(
        "import sqlite3\n\nclass Repo:\n    def __init__(self, q):\n        self.q = q\n\n    def run(self):\n        sqlite3.connect('x').execute(self.q)  # SINK\n",
        files={"views.py": VIEW_HEADER + "from repo import Repo\n\ndef view():\n    Repo(request.args['q']).run()\n"},
        target="repo.py",
    )


def test_sibling_scripts_prefer_their_own_directory(check):
    # two directories each with a utils.py; each script imports its sibling
    check(
        "import sqlite3\n\ndef q(v):\n    sqlite3.connect('x').execute(v)  # SINK\n",
        files={
            "tool_a/main.py": VIEW_HEADER + "import utils\n\ndef view():\n    utils.q(request.args['v'])\n",
            "tool_b/utils.py": "def q(v):\n    return v\n",
            "tool_b/main.py": VIEW_HEADER + "import utils\n\ndef view():\n    utils.q(request.args['v'])\n",
        },
        target="tool_a/utils.py",
    )


def test_third_party_package_is_a_library_call(check):
    # `requests_toolbelt` is not in the scan, so its functions get the conservative default
    check(
        "import sqlite3\nfrom flask import request\nfrom requests_toolbelt import munge\n\ndef view():\n    sqlite3.connect('x').execute(munge(request.args['q']))  # SINK\n",
        target="views.py",
    )
