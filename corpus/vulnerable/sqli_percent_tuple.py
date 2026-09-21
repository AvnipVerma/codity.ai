import psycopg2
from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = psycopg2.connect(dbname="app")
    cur = conn.cursor()
    # Classic mistake: string formatting instead of query parameters.
    cur.execute("SELECT id FROM users WHERE name = '%s' AND pw_hash = crypt('%s', pw_hash)" % (username, password))
    row = cur.fetchone()
    return "welcome" if row else ("denied", 401)
