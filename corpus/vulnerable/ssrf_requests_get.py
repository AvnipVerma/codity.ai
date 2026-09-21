import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return {"status": resp.status_code, "length": len(resp.content)}
