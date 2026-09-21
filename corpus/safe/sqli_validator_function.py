"""The column name is validated, but by a helper function."""
import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)
SORTABLE = ("name", "price", "rating")


def is_sortable(column):
    return column in SORTABLE


@app.route("/catalog")
def catalog():
    column = request.args.get("sort", "name")
    if not is_sortable(column):
        abort(400)
    conn = sqlite3.connect("catalog.db")
    return {"items": conn.execute("SELECT * FROM items ORDER BY " + column).fetchall()}
