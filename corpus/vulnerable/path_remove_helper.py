import os

from flask import Flask, request

app = Flask(__name__)
UPLOADS = "/srv/uploads"


def delete_upload(filename):
    target = os.path.join(UPLOADS, filename)
    if os.path.exists(target):
        os.remove(target)
        return True
    return False


@app.route("/uploads/delete", methods=["POST"])
def delete():
    return {"deleted": delete_upload(request.json["filename"])}
