import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/lint", methods=["POST"])
def lint():
    args = shlex.split(request.form.get("args", ""))
    # Arguments are passed as a list and no shell is involved.
    result = subprocess.run(["flake8"] + args, shell=False, capture_output=True, text=True)
    return {"report": result.stdout}
