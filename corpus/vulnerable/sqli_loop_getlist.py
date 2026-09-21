import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/tags")
def by_tags():
    tags = request.args.getlist("tag")
    conditions = "1=1"
    for tag in tags:
        conditions += " OR tag = '" + tag + "'"
    conn = sqlite3.connect("blog.db")
    rows = conn.execute("SELECT post_id FROM post_tags WHERE " + conditions).fetchall()
    return {"posts": [r[0] for r in rows]}
