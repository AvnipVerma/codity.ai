import sqlite3

from flask import Flask, request

app = Flask(__name__)


class UserQuery:
    def __init__(self, conn, sort):
        self.conn = conn
        self.sort = sort
        self.table = "users"

    def order_clause(self):
        return " ORDER BY " + self.sort

    def all(self):
        sql = "SELECT id, email FROM " + self.table + self.order_clause()
        return self.conn.execute(sql).fetchall()


@app.route("/users")
def list_users():
    query = UserQuery(sqlite3.connect("app.db"), request.args.get("sort", "id"))
    return {"users": query.all()}
