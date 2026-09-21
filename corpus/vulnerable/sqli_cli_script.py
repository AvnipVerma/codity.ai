"""Maintenance script: delete a customer by e-mail address."""
import sqlite3
import sys


def main():
    email = sys.argv[1]
    conn = sqlite3.connect("crm.db")
    conn.executescript("DELETE FROM customers WHERE email = '" + email + "'; VACUUM;")
    conn.commit()


if __name__ == "__main__":
    main()
