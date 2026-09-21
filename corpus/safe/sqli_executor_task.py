"""`execute` here belongs to a job runner, not a database cursor."""
from flask import Flask, request

from jobs.runtime import get_runner

app = Flask(__name__)
runner = get_runner("default")


@app.route("/jobs/run", methods=["POST"])
def run_job():
    job_name = request.form["job"]
    runner.execute(job_name)
    return {"queued": job_name}
