"""The host is fixed; the user only picks which profile on that host."""
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/github-profile")
def github_profile():
    username = request.args.get("user", "octocat")
    resp = requests.get(f"https://api.github.com/users/{username}", timeout=5)
    return {"name": resp.json().get("name")}
