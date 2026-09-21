import sqlite3

_conn = sqlite3.connect("shop.db", check_same_thread=False)


def find_orders_for(customer_id):
    sql = "SELECT * FROM orders WHERE customer_id = " + customer_id
    return _conn.execute(sql).fetchall()


def find_by_status(status):
    return _conn.execute("SELECT * FROM orders WHERE status = ?", (status,)).fetchall()
