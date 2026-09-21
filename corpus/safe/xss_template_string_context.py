from flask import Flask, render_template_string, request

app = Flask(__name__)

PAGE = """
<html>
  <body>
    <h1>Results for {{ query }}</h1>
  </body>
</html>
"""


@app.route("/results")
def results():
    # The template is a constant; user data only enters as an autoescaped variable.
    return render_template_string(PAGE, query=request.args.get("q", ""))
