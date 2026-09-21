"""Report endpoint: the filter travels through several assignments."""
import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("reports.db", check_same_thread=False)


@app.route("/reports")
def reports():
    raw = request.args["from"]
    start = raw.strip()
    start_date = start
    template = "SELECT * FROM reports WHERE created >= '{}' ORDER BY created"
    sql = template.format(start_date)
    result = db.execute(sql).fetchall()
    return {"count": len(result)}
