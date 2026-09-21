import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["PUT"])
def update_config():
    config = yaml.safe_load(request.data)
    return {"keys": sorted(config or {})}
