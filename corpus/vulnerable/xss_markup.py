from flask import Flask, render_template, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/comment", methods=["POST"])
def comment():
    text = request.form["comment"]
    # Marking user text as safe HTML disables autoescaping in the template.
    rendered = Markup("<p class='comment'>{}</p>".format(text))
    return render_template("comment.html", comment=rendered)
