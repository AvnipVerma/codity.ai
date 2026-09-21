from flask import Flask, request
from sqlalchemy import Column, Integer, String, create_engine, select
from sqlalchemy.orm import Session, declarative_base

Base = declarative_base()
engine = create_engine("sqlite:///people.db")
app = Flask(__name__)


class Person(Base):
    __tablename__ = "people"
    id = Column(Integer, primary_key=True)
    name = Column(String)


@app.route("/people")
def people():
    name = request.args.get("name", "")
    with Session(engine) as session:
        stmt = select(Person).where(Person.name == name)
        return {"people": [p.id for p in session.execute(stmt).scalars()]}
