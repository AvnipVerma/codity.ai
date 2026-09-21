import requests
from flask import Flask, request

app = Flask(__name__)
SEARCH_API = "https://search.internal.example.com/v1/query"


@app.route("/search")
def search():
    term = request.args.get("q", "")
    resp = requests.get(SEARCH_API, params={"q": term, "limit": 20}, timeout=5)
    return resp.json()
