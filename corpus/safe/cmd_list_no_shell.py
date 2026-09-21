import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/archive", methods=["POST"])
def archive():
    folder = request.form["folder"]
    name = request.form.get("name", "backup")
    completed = subprocess.run(
        ["tar", "-czf", f"/backups/{name}.tgz", "--", folder],
        capture_output=True,
        check=False,
    )
    listing = subprocess.check_output(["ls", "-l", "/backups"], shell=False)
    return {"ok": completed.returncode == 0, "listing": listing.decode()}
