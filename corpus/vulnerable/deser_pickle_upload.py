import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/models", methods=["POST"])
def upload_model():
    uploaded = request.files["model"]
    model = pickle.load(uploaded)
    return {"type": type(model).__name__}
