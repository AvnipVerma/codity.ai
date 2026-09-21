import mysql.connector


def legacy_connection():
    # A real, if weak, production password committed to the repository.
    db_pass = "hunter2"
    return mysql.connector.connect(host="10.0.0.12", user="root", password=db_pass)
