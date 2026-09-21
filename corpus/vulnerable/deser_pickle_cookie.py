import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/cart")
def cart():
    blob = request.cookies.get("cart", "")
    items = pickle.loads(base64.b64decode(blob)) if blob else []
    return {"items": items}
