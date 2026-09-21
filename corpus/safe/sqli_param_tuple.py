import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/products")
def products():
    category = request.args.get("category", "all")
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, price FROM products WHERE category = ?", (category,))
    return jsonify(cursor.fetchall())
