"""Command-line downloader: the operator running it chooses the URL."""
import sys
import urllib.request


def main():
    url = sys.argv[1]
    with urllib.request.urlopen(url) as resp, open("download.bin", "wb") as out:
        out.write(resp.read())


if __name__ == "__main__":
    main()
