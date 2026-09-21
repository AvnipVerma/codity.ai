import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/convert", methods=["POST"])
def convert():
    fmt = request.form.get("format", "png")
    # No shell=True, but "sh -c" hands the whole string to a shell anyway.
    subprocess.run(["sh", "-c", "convert input.svg output." + fmt], check=True)
    return {"ok": True}
