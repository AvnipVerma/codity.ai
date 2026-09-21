import requests
from flask import Flask, request

app = Flask(__name__)


class Webhook:
    def __init__(self, target):
        self.target = target

    def notify(self, event):
        return requests.post(self.target, json={"event": event}, timeout=3)


@app.route("/webhooks/test", methods=["POST"])
def test_webhook():
    hook = Webhook(request.form["callback_url"])
    hook.notify("ping")
    return {"sent": True}
