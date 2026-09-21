import os
import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = shlex.quote(request.args.get("host", "127.0.0.1"))
    status = os.system("ping -c 1 " + host)
    out = subprocess.check_output(f"dig +short {host}", shell=True)
    return {"reachable": status == 0, "dns": out.decode()}
