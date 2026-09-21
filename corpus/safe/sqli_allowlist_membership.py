import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED_SORT_COLUMNS = {"name", "email", "created_at"}


@app.route("/users")
def users():
    sort = request.args.get("sort", "name")
    if sort not in ALLOWED_SORT_COLUMNS:
        abort(400)
    direction = "DESC" if request.args.get("desc") else "ASC"
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT id, name FROM users ORDER BY {sort} {direction}").fetchall()
    return {"users": rows}
