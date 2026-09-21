import httpx
from flask import Flask, request

app = Flask(__name__)


@app.route("/health")
def health():
    host = request.args.get("host", "localhost")
    port = request.args.get("port", "8080")
    r = httpx.get(f"http://{host}:{port}/healthz", timeout=2.0)
    return {"healthy": r.status_code == 200}
