import os
import subprocess

UPTIME = "uptime"


def system_report():
    os.system(UPTIME)
    disk = subprocess.run("df -h / | tail -1", shell=True, capture_output=True, text=True).stdout
    branch = subprocess.check_output("git rev-parse --abbrev-ref HEAD", shell=True).decode().strip()
    return {"disk": disk, "branch": branch}


if __name__ == "__main__":
    print(system_report())
