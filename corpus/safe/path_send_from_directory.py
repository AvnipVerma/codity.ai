from flask import Flask, request, send_from_directory

app = Flask(__name__)
ASSETS = "/srv/app/assets"


@app.route("/assets")
def assets():
    # send_from_directory joins safely and refuses paths that escape ASSETS.
    return send_from_directory(ASSETS, request.args["path"])
