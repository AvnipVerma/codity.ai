import requests
from flask import Flask, abort, request

app = Flask(__name__)
PARTNER_HOSTS = ("api.partner-one.example", "api.partner-two.example")


@app.route("/partner-status")
def partner_status():
    host = request.args.get("host", "")
    if host not in PARTNER_HOSTS:
        abort(400)
    resp = requests.get(f"https://{host}/status", timeout=3)
    return {"up": resp.ok}
