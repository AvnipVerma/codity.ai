import subprocess

from flask import Flask, request

app = Flask(__name__)

ACTIONS = {
    "restart": "systemctl restart app",
    "status": "systemctl status app --no-pager",
    "logs": "journalctl -u app -n 100 --no-pager",
}


@app.route("/admin/service", methods=["POST"])
def service():
    action = request.form.get("action", "status")
    if action not in ACTIONS:
        return {"error": "unknown action"}, 400
    command = ACTIONS[action]
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"output": result.stdout}
