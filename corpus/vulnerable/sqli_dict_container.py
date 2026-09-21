import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/orders")
def orders():
    filters = {"status": "open", "customer": request.args.get("customer")}
    parts = []
    for column in ("status", "customer"):
        parts.append(f"{column} = '{filters[column]}'")
    where = " AND ".join(parts)
    conn = sqlite3.connect("orders.db")
    return {"orders": conn.execute("SELECT * FROM orders WHERE " + where).fetchall()}
