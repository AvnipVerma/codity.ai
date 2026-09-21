import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/archive", methods=["POST"])
def archive():
    folder = request.form["folder"]
    name = request.form.get("name", "backup")
    cmd = f"tar -czf /backups/{name}.tgz {folder}"
    completed = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"ok": completed.returncode == 0}
