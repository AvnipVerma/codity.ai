import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/flags")
def flags():
    email = request.args.get("email", "")
    is_staff = email.endswith("@example.com")
    domain_len = len(email.partition("@")[2])
    conn = sqlite3.connect("app.db")
    sql = "SELECT name FROM features WHERE staff_only <= %d AND min_domain <= %d" % (is_staff, domain_len)
    return {"features": conn.execute(sql).fetchall()}
