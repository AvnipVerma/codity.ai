import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/invoice")
def invoice():
    invoice_id = int(request.args["id"])
    page = int(request.args.get("page", 1))
    offset = (page - 1) * 50
    conn = sqlite3.connect("billing.db")
    sql = f"SELECT * FROM lines WHERE invoice_id = {invoice_id} LIMIT 50 OFFSET {offset}"
    return {"lines": conn.execute(sql).fetchall()}
