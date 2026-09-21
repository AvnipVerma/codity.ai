from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/profile")
def profile():
    # Jinja2 autoescapes variables in .html templates.
    return render_template("profile.html", name=request.args.get("name", ""), bio=request.args.get("bio", ""))
