import html

from flask import Flask, render_template_string, request
from markupsafe import Markup, escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = escape(request.args.get("name", "world"))
    banner = Markup("<strong>{}</strong>").format(name)
    return render_template_string("<h1>Hello " + str(name) + "</h1>") + str(banner)


@app.route("/echo")
def echo():
    msg = html.escape(request.args.get("msg", ""))
    return render_template_string("<pre>" + msg + "</pre>")
