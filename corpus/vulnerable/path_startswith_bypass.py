from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/static-file")
def static_file():
    rel = request.args.get("path", "")
    # Looks like a check, but "public/../../etc/passwd" starts with "public/" too.
    if not rel.startswith("public/"):
        abort(403)
    with open("/srv/site/" + rel, "rb") as fh:
        return fh.read()
