from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/greeting")
def greeting():
    title = request.args.get("title", "Welcome")
    tmpl = Template("<title>" + title + "</title><p>{{ body }}</p>")
    return tmpl.render(body="Thanks for visiting")
