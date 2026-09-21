from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "1+1")
    # "only arithmetic", says the comment; eval does not care.
    value = eval(expression, {"__builtins__": {}})
    return {"result": value}
