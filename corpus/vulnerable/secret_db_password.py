import psycopg2

DATABASE = {
    "host": "db.internal",
    "user": "billing",
    "password": "Tr0ub4dor&3xK9#mQ2vL",
}


def connect():
    return psycopg2.connect(host="db.internal", user="reporting", password="p4ssW0rd!2024#Report")
