import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["PUT"])
def update_config():
    document = request.data.decode("utf-8")
    config = yaml.load(document)
    return {"keys": sorted(config)}
