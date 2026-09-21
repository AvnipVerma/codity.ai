from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    page = "<html><body><h1>Hello " + name + "!</h1></body></html>"
    return render_template_string(page)
