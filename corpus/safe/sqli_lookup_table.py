import sqlite3

from flask import Flask, request

app = Flask(__name__)

ORDERINGS = {
    "newest": "created_at DESC",
    "oldest": "created_at ASC",
    "popular": "views DESC",
}


@app.route("/articles")
def articles():
    ordering = ORDERINGS.get(request.args.get("order"), "created_at DESC")
    conn = sqlite3.connect("cms.db")
    return {"articles": conn.execute("SELECT id, title FROM articles ORDER BY " + ordering).fetchall()}
