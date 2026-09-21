import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_connection():
    return sqlite3.connect("shop.db")


@app.route("/products")
def products():
    category = request.args.get("category", "all")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name, price FROM products WHERE category = '{category}'")
    rows = cursor.fetchall()
    return jsonify(rows)
