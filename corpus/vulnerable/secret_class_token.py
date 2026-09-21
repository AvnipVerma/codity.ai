import requests


class GitHubClient:
    api_token = "ghp_R4nd0mT0k3nV4lu3F0rT3st1ngPurp0s3s"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers["Authorization"] = "token " + self.api_token

    def repos(self, org):
        return self.session.get(f"https://api.github.com/orgs/{org}/repos").json()
