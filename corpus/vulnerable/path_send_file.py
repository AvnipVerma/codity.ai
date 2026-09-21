from flask import Flask, request, send_file

app = Flask(__name__)
EXPORTS = "/var/exports/"


@app.route("/download")
def download():
    name = request.args["file"]
    return send_file(EXPORTS + name, as_attachment=True)
