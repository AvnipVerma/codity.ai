import psycopg2
from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    params = {"name": request.form["username"], "pw": request.form["password"]}
    conn = psycopg2.connect(dbname="app")
    cur = conn.cursor()
    query = "SELECT id FROM users WHERE name = %(name)s AND pw_hash = crypt(%(pw)s, pw_hash)"
    cur.execute(query, params)
    return "welcome" if cur.fetchone() else ("denied", 401)


@app.route("/bulk", methods=["POST"])
def bulk_insert():
    rows = [(item["sku"], item["qty"]) for item in request.get_json()["items"]]
    conn = psycopg2.connect(dbname="app")
    conn.cursor().executemany("INSERT INTO stock (sku, qty) VALUES (%s, %s)", rows)
    return {"inserted": len(rows)}
