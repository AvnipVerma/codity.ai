from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
TEMPLATES = Path("/srv/app/email-templates")


@app.route("/preview")
def preview():
    template = request.args.get("template", "welcome.txt")
    body = (TEMPLATES / template).read_text()
    return {"preview": body[:500]}
