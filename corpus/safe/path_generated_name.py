import os
import uuid

from flask import Flask, request

app = Flask(__name__)
SCRATCH = "/tmp/scratch"


@app.route("/notes", methods=["POST"])
def save_note():
    note_id = uuid.uuid4().hex
    path = os.path.join(SCRATCH, note_id + ".txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(request.form.get("text", ""))
    return {"id": note_id}
