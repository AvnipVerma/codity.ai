"""Paths come from the deployment's environment, not from users."""
import os
import shutil

LOG_PATH = os.environ.get("APP_LOG_PATH", "/var/log/app.log")
ARCHIVE_DIR = os.getenv("APP_ARCHIVE_DIR", "/var/archive")


def rotate():
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write("rotating\n")
    shutil.move(LOG_PATH, os.path.join(ARCHIVE_DIR, "app.log.1"))
