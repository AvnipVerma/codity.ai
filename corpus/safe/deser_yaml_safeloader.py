import yaml
from flask import Flask, request

app = Flask(__name__)


def parse(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


@app.route("/deploy", methods=["POST"])
def deploy():
    manifest = parse(request.form["manifest"])
    extras = yaml.load(request.form.get("extras", "{}"), yaml.CSafeLoader)
    return {"services": list(manifest.get("services", {})), "extras": len(extras)}
