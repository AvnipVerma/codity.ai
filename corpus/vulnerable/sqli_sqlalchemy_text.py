from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine("postgresql:///analytics")


@app.route("/events")
def events():
    kind = request.args.get("kind", "click")
    with engine.connect() as connection:
        stmt = text(f"SELECT count(*) FROM events WHERE kind = '{kind}'")
        count = connection.execute(stmt).scalar()
    return {"kind": kind, "count": count}
