import jwt
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "8f42a73054b1749f8f58848be5e6502c"

JWT_SIGNING_SECRET = "q9Xv2LkR8sNw4TzYb6Hc1Jm5Pd7Fg3Ae"


def issue_token(user_id):
    return jwt.encode({"sub": user_id}, JWT_SIGNING_SECRET, algorithm="HS256")
