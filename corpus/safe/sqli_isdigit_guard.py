import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/tickets/<ticket_id>")
def ticket(ticket_id):
    number = request.args.get("n", "")
    if not number.isdigit():
        abort(400)
    conn = sqlite3.connect("support.db")
    row = conn.execute("SELECT subject FROM tickets WHERE number = " + number).fetchone()
    return {"subject": row[0] if row else None}
