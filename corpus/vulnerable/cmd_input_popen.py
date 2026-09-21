"""Interactive helper that greps log files."""
import os


def search_logs():
    pattern = input("pattern to search for: ")
    stream = os.popen("grep -r '%s' /var/log/app/" % pattern)
    for line in stream:
        print(line.rstrip())


if __name__ == "__main__":
    search_logs()
