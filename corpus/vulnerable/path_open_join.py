import os

from flask import Flask, request

app = Flask(__name__)
DOCS = "/srv/app/docs"


@app.route("/docs")
def read_doc():
    page = request.args.get("page", "index.md")
    path = os.path.join(DOCS, page)
    with open(path, encoding="utf-8") as fh:
        return fh.read()
