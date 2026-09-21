import json
import urllib.request

from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_feed():
    payload = request.get_json()
    feed_url = payload["feed"]
    with urllib.request.urlopen(feed_url, timeout=10) as resp:
        items = json.load(resp)
    return {"imported": len(items)}
