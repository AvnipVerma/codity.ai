import yaml
from flask import Flask, request

app = Flask(__name__)


def parse_manifest(text):
    return yaml.load(text, Loader=yaml.Loader)


@app.route("/deploy", methods=["POST"])
def deploy():
    manifest = parse_manifest(request.form["manifest"])
    return {"services": list(manifest.get("services", {}))}
