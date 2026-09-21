import os

API_KEY = os.environ["API_KEY"]
SECRET_KEY = os.getenv("SECRET_KEY", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
JWT_SECRET = f"{os.environ.get('JWT_PREFIX', '')}{os.environ['JWT_SECRET']}"


def auth_header():
    token = os.environ["SERVICE_TOKEN"]
    return {"Authorization": "Bearer " + token}
