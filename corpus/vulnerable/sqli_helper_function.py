import sqlite3

from flask import Flask, request

app = Flask(__name__)


def build_search(term, limit):
    clause = "name LIKE '%" + term + "%'"
    return "SELECT * FROM books WHERE " + clause + " LIMIT " + str(limit)


def run(sql):
    conn = sqlite3.connect("library.db")
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return {"results": run(build_search(term, 20))}
