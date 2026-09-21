import sqlite3

TABLE = "audit_log"
COLUMNS = "id, actor, action, created"
BASE_QUERY = "SELECT " + COLUMNS + " FROM " + TABLE


def recent(conn, limit_clause=" ORDER BY created DESC LIMIT 100"):
    sql = BASE_QUERY + limit_clause
    return conn.execute(sql).fetchall()


def purge(conn):
    conn.executescript("DELETE FROM " + TABLE + " WHERE created < date('now', '-90 days'); VACUUM;")


if __name__ == "__main__":
    connection = sqlite3.connect("audit.db")
    print(recent(connection))
