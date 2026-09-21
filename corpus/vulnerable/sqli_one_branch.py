import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/inventory")
def inventory():
    conn = sqlite3.connect("stock.db")
    if request.args.get("mode") == "all":
        where = "1=1"
    else:
        where = "warehouse = '" + request.args.get("warehouse", "main") + "'"
    return {"items": conn.execute("SELECT sku, qty FROM stock WHERE " + where).fetchall()}
