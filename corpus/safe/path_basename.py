import os

from flask import Flask, request, send_file

app = Flask(__name__)
REPORTS = "/var/reports"


@app.route("/report")
def report():
    requested = request.args.get("name", "latest.pdf")
    name = os.path.basename(requested)
    return send_file(os.path.join(REPORTS, name), mimetype="application/pdf")
