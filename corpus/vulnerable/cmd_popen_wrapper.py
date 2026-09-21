import subprocess

from flask import Flask, request

app = Flask(__name__)


def shell(command, timeout=10):
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    out, _ = proc.communicate(timeout=timeout)
    return out.decode()


class Git:
    def log(self, branch):
        return shell("git log --oneline " + branch)


@app.route("/history")
def history():
    branch = request.args.get("branch", "main")
    return {"log": Git().log(branch)}
