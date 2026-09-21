import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["file"]
    filename = secure_filename(uploaded.filename)
    destination = os.path.join(UPLOAD_DIR, filename)
    with open(destination, "wb") as fh:
        fh.write(uploaded.read())
    return {"stored": filename}
