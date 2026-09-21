import os

from flask import Flask, abort, request

app = Flask(__name__)
BASE_DIR = os.path.realpath("/srv/public")


@app.route("/public")
def public_file():
    candidate = os.path.realpath(os.path.join(BASE_DIR, request.args.get("f", "")))
    if not candidate.startswith(BASE_DIR + os.sep):
        abort(404)
    with open(candidate, "rb") as fh:
        return fh.read()
