"""The shipped rules.yaml, one class at a time, against real library APIs."""

H = "import os, sys, subprocess, pickle, yaml, requests, sqlite3\nfrom flask import request\n"

SQL, CMD, PATH, SSRF, XSS, DESER = (
    "py.sql-injection",
    "py.command-injection",
    "py.path-traversal",
    "py.ssrf",
    "py.xss-template",
    "py.insecure-deserialization",
)


def test_sql_injection_sinks(check):
    check(
        H
        + """
import sqlalchemy, pandas
from sqlalchemy import text
conn = sqlite3.connect('db')

def view(engine, Model):
    q = request.args['q']
    conn.execute(f"SELECT * FROM t WHERE a = '{q}'")  # SINK
    conn.executemany("INSERT INTO t VALUES ('%s')" % q, [])  # SINK
    conn.executescript('DROP TABLE ' + q)  # SINK
    engine.execute(text('SELECT * FROM t WHERE a = ' + q))  # SINK
    Model.objects.raw('SELECT * FROM app_model WHERE a = ' + q)  # SINK
    pandas.read_sql('SELECT * FROM t WHERE a = ' + q, conn)  # SINK
    conn.execute('SELECT * FROM t WHERE a = ?', (q,))
    engine.execute(text('SELECT * FROM t WHERE a = :a'), {'a': q})
""",
        rule=SQL,
    )


def test_sql_injection_process_sources(check):
    check(
        H
        + "conn = sqlite3.connect('db')\n"
        + "conn.execute('SELECT * FROM t WHERE a = ' + sys.argv[1])  # SINK\n"
        + "conn.execute('SELECT * FROM t WHERE a = ' + input())  # SINK\n"
        + "conn.execute('SELECT * FROM t WHERE a = ' + os.environ.get('X'))  # SINK\n",
        rule=SQL,
    )


def test_command_injection_sinks(check):
    check(
        H
        + """
import shlex
from subprocess import Popen, check_output

def view(flag):
    c = request.args['c']
    os.system('ping ' + c)  # SINK
    os.popen('ls ' + c)  # SINK
    subprocess.run('ls ' + c, shell=True)  # SINK
    subprocess.call(f'ls {c}', shell=True)  # SINK
    check_output('ls ' + c, shell=True)  # SINK
    Popen('ls ' + c, shell=flag)  # SINK
    subprocess.getoutput('ls ' + c)  # SINK
    eval(c)  # SINK
    exec(c)  # SINK
    os.execvp('ls', ['ls', c])  # SINK
    subprocess.run(['ls', c])
    subprocess.run('ls ' + c, shell=False)
    subprocess.run(['ls', c], shell=False)
    os.system('ls ' + shlex.quote(c))
    subprocess.run('ls ' + shlex.quote(c), shell=True)
""",
        rule=CMD,
    )


def test_path_traversal_sinks(check):
    check(
        H
        + """
import shutil, pathlib
from pathlib import Path
from flask import send_file
from werkzeug.utils import secure_filename
BASE = '/srv/uploads'

def view():
    name = request.args['name']
    open(os.path.join(BASE, name))  # SINK
    send_file(BASE + '/' + name)  # SINK
    Path(name)  # SINK
    (Path(BASE) / name).read_text()  # SINK
    os.remove(os.path.join(BASE, name))  # SINK
    shutil.rmtree(name)  # SINK
    open(os.path.join(BASE, secure_filename(name)))
    open(os.path.join(BASE, os.path.basename(name)))
    open(os.environ['CONFIG_PATH'])
    open(os.path.join(BASE, 'fixed.txt'))
""",
        rule=PATH,
    )


def test_ssrf_sinks(check):
    check(
        H
        + """
import httpx, urllib.request
from urllib.request import urlopen

def view():
    url = request.args['url']
    requests.get(url)  # SINK
    requests.post(url, data={})  # SINK
    requests.request('GET', url)  # SINK
    urlopen(url)  # SINK
    urllib.request.Request(url)  # SINK
    httpx.get(url=url)  # SINK
    requests.get('https://api.example.com/search', params={'q': url})
    requests.request(url, 'https://api.example.com/')
    requests.get(sys.argv[1])
""",
        rule=SSRF,
    )


def test_xss_template_sinks(check):
    check(
        H
        + """
import jinja2, html
from flask import render_template_string, render_template
from markupsafe import Markup, escape

def view():
    name = request.args['name']
    render_template_string('<h1>Hello ' + name + '</h1>')  # SINK
    Markup('<b>%s</b>' % name)  # SINK
    jinja2.Template('Hello ' + name).render()  # SINK
    render_template_string('<h1>Hello {{ name }}</h1>', name=name)
    render_template('hello.html', name=name)
    Markup('<b>%s</b>' % escape(name))
    render_template_string('<p>' + html.escape(name) + '</p>')
""",
        rule=XSS,
    )


def test_insecure_deserialization_sinks(check):
    check(
        H
        + """
import base64, json, marshal, jsonpickle

def view():
    blob = request.get_data()
    pickle.loads(blob)  # SINK
    pickle.loads(base64.b64decode(request.cookies.get('session')))  # SINK
    marshal.loads(blob)  # SINK
    jsonpickle.decode(blob)  # SINK
    yaml.load(blob)  # SINK
    yaml.load(blob, Loader=yaml.Loader)  # SINK
    yaml.unsafe_load(blob)  # SINK
    yaml.full_load(blob)  # SINK
    yaml.safe_load(blob)
    yaml.load(blob, Loader=yaml.SafeLoader)
    yaml.load(blob, yaml.SafeLoader)
    json.loads(blob)
    pickle.loads(open('model.pkl', 'rb').read())
""",
        rule=DESER,
    )


def test_request_files_upload_to_pickle(check):
    check(H + "def view():\n    pickle.load(request.files['model'])  # SINK\n    pickle.loads(request.files['model'].read())  # SINK\n", rule=DESER)


# ---------------------------------------------------------------- resolution


def test_flow_sensitive_alias_of_request(check):
    check("import os\nfrom flask import request\ndef f():\n    r = request\n    os.system(r.args.get('c'))  # SINK\n", rule=CMD)


def test_import_inside_function(check):
    check("def f():\n    from flask import request\n    import os as o\n    o.system(request.args['c'])  # SINK\n", rule=CMD)


def test_aliased_module_and_function_imports(check):
    check(
        "import subprocess as sp\nfrom os import system as run_cmd\nfrom flask import request as req\n"
        "def f():\n    sp.run(req.form['c'], shell=True)  # SINK\n    run_cmd(req.form['c'])  # SINK\n",
        rule=CMD,
    )


def test_shadowed_builtin_is_not_a_sink(check):
    check("from flask import request\ndef open(p):\n    return p\n\ndef f():\n    open(request.args['p'])\n", rule=PATH)


def test_shadowing_parameter_is_not_a_source(check):
    check("import os\nfrom flask import request\ndef f(request):\n    os.system(request.args['c'])\n", rule=CMD)


def test_conditional_import_candidates(check):
    check(
        "from flask import request\ntry:\n    import cPickle as pickle\nexcept ImportError:\n    import pickle\n"
        "def f():\n    pickle.loads(request.data)  # SINK\n",
        rule=DESER,
    )


def test_getattr_with_constant_name(check):
    check("import os\nfrom flask import request\ndef f():\n    getattr(os, 'system')(request.args['c'])  # SINK\n", rule=CMD)


def test_unknown_receiver_matches_wildcard_sink(check):
    # executor's type is unknown, so `*.execute` matches: a documented false positive
    check("from flask import request\ndef f(executor):\n    executor.execute(request.args['task'])  # SINK\n", rule=SQL)


def test_sink_keyword_equivalents(check):
    check(
        H + "def f():\n    requests.get(url=request.args['u'])  # SINK\n    subprocess.run(args='ls ' + request.args['c'], shell=True)\n",
        rule=SSRF,
    )


def test_converted_request_values_are_not_sources(check):
    check(
        H
        + "conn = sqlite3.connect('db')\n"
        + "def f():\n"
        + "    page = request.args.get('page', 1, type=int)\n"
        + "    conn.execute('SELECT * FROM t LIMIT 10 OFFSET %d' % page)\n"
        + "    ids = request.args.getlist('id', type=int)\n"
        + "    conn.execute('SELECT * FROM t WHERE id IN (%s)' % ','.join(map(str, ids)))\n"
        + "    name = request.args.get('name', type=str)\n"
        + "    conn.execute('SELECT * FROM t WHERE n = ' + name)  # SINK\n",
        rule=SQL,
    )


def test_methods_on_library_session_objects(check):
    check(
        H
        + """
import httpx

def f():
    url = request.args['url']
    session = requests.Session()
    session.get(url)  # SINK
    with httpx.Client() as client:
        client.post(url)  # SINK
    requests.Session().request('GET', url)  # SINK
"""
    ,
        rule=SSRF,
    )


def test_lookup_in_module_level_dict_with_get(check):
    check(H + "ORDER = {'new': 'id DESC'}\nconn = sqlite3.connect('db')\ndef f():\n    conn.execute('SELECT * FROM t ORDER BY ' + ORDER.get(request.args['o'], 'id'))\n", rule=SQL)


def test_digest_of_tainted_value_is_clean(check):
    check(H + "import hashlib\nconn = sqlite3.connect('db')\ndef f():\n    h = hashlib.sha256(request.args['q'].encode()).hexdigest()\n    conn.execute(\"SELECT * FROM cache WHERE k = '\" + h + \"'\")\n", rule=SQL)


def test_ssrf_fixed_scheme_and_host_prefix_is_safe(check):
    check(
        H
        + """
API = "https://api.example.com"
BASE = API + "/v1/"

def f(host_only):
    u = request.args['u']
    requests.get(f"https://api.github.com/users/{u}")
    requests.get("https://api.example.com/items/" + u)
    requests.get("https://api.example.com/search?q={}".format(u))
    requests.get("https://api.example.com/search?q=%s" % u)
    requests.get(BASE + u)
    url = API + "/orders/" + u
    requests.get(url)
    requests.get(f"https://{u}/status")  # SINK
    requests.get("https://" + u)  # SINK
    requests.get(API + u)  # SINK
    requests.get(f"{u}/api")  # SINK
"""
    ,
        rule=SSRF,
    )


def test_safe_prefix_only_affects_its_own_rule(check):
    # the fixed-host prefix sanitizes SSRF, not SQL injection
    check(H + "conn = sqlite3.connect('db')\ndef f():\n    conn.execute('https://x.example/' + request.args['q'])  # SINK\n", rule=SQL)


def test_request_url_and_path_are_sources(check):
    check(
        H
        + """
from flask import render_template_string

def not_found(e):
    return render_template_string('<h3>%s</h3>' % request.url)  # SINK

def other():
    return render_template_string('<p>' + request.path + '</p>')  # SINK
"""
    ,
        rule=XSS,
    )


# ---------------------------------------------------------------- framework request parameters


def test_django_function_and_class_views(check):
    check(
        """
import subprocess
from django.db import connection
from django.views import View

def search(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM t WHERE n = '" + request.GET["n"] + "'")  # SINK
        cursor.execute("SELECT * FROM t WHERE n = %s", [request.GET["n"]])
        cursor.execute("SELECT * FROM t WHERE n = " + request.POST.get("n"))  # SINK

class Report(View):
    def post(self, request, *args, **kwargs):
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM t WHERE id = " + request.body.decode())  # SINK
""",
        rule=SQL,
    )


def test_request_parameter_needs_the_framework_import(check):
    # same code without importing django: `request` is just a parameter
    check("import sqlite3\ncur = sqlite3.connect('x').cursor()\ndef search(request):\n    cur.execute(request.GET['n'])\n", rule=SQL)


def test_drf_and_aiohttp_requests(check):
    check(
        """
import os, subprocess
from rest_framework.views import APIView

class Upload(APIView):
    def post(self, request):
        subprocess.run("convert " + request.data["file"], shell=True)  # SINK
        subprocess.run("ls " + request.query_params.get("d"), shell=True)  # SINK
""",
        rule=CMD,
    )
    check(
        """
import os
from aiohttp import web

async def handler(request):
    os.system("ping " + request.query["host"])  # SINK
    data = await request.post()
    os.system("echo " + data["msg"])  # SINK
""",
        rule=CMD,
    )


def test_annotated_request_parameter(check):
    check(
        """
import os
from starlette.requests import Request

async def hook(request: Request):
    payload = await request.json()
    os.system("notify " + payload["channel"])  # SINK
""",
        rule=CMD,
    )


def test_django_xss_sinks_and_sanitizers(check):
    check(
        """
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe

def view(request):
    q = request.GET.get("q", "")
    mark_safe("<b>" + q + "</b>")  # SINK
    mark_safe("<b>" + escape(q) + "</b>")
    format_html("<b>{}</b>", q)
    format_html("<b>" + q + "</b>")  # SINK
""",
        rule=XSS,
    )


def test_additional_library_idioms(check):
    check(
        H
        + """
import importlib, tarfile, jinja2
from psycopg2 import sql
from markupsafe import Markup

def f(cur):
    t = request.args['t']
    cur.execute(sql.SQL("SELECT * FROM {} WHERE a = %s").format(sql.Identifier(t)), (t,))
    cur.execute(sql.SQL("SELECT * FROM " + t))  # SINK
""",
        rule=SQL,
    )
    check(H + "import importlib\ndef f():\n    importlib.import_module(request.args['m'])  # SINK\n    __import__(request.args['m'])  # SINK\n", rule=CMD)
    check(H + "import tarfile\ndef f():\n    tarfile.open(request.args['archive'])  # SINK\n", rule=PATH)
    check(
        H
        + "import jinja2\nfrom markupsafe import Markup\n"
        + "def f():\n    env = jinja2.Environment()\n    env.from_string('Hi ' + request.args['n']).render()  # SINK\n"
        + "    Markup('<b>' + Markup.escape(request.args['n']) + '</b>')\n",
        rule=XSS,
    )
