import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/stats")
def stats():
    query = request.args.get("query")
    if query:
        app.logger.info("custom stats query requested: %s", query)
    # Custom queries were disabled; the variable is reused for the fixed one.
    query = "SELECT count(*) FROM visits"
    conn = sqlite3.connect("stats.db")
    return {"visits": conn.execute(query).fetchone()[0]}
