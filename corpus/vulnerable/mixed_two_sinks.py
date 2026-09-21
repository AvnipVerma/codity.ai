"""One tainted value reaching two different sinks, and one sink fed by two sources."""
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/export")
def export():
    table = request.args["table"]
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM " + table).fetchall()
    os.system("echo exported " + table + " >> /var/log/exports.log")
    return {"rows": len(rows)}


@app.route("/audit")
def audit():
    who = request.headers.get("X-User", "anonymous")
    what = request.args.get("action", "view")
    sqlite3.connect("audit.db").execute(f"INSERT INTO audit VALUES ('{who}', '{what}')")
    return "", 204
