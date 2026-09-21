"""The shipped py.hardcoded-secret rule (kind: pattern)."""

import json

import pytest

from scanner import baseline
from scanner.output.sarif import render_sarif
from scanner.output.table import render_table

from .conftest import hits

AWS = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT = "9f8e7d6c5b4a39281706f5e4d3c2b1a0Zq"
DBPW = "Xk9#mQ2$vL7!pR4@tB"

RULE = "py.hardcoded-secret"


@pytest.mark.parametrize(
    "code",
    [
        f'AWS_SECRET_ACCESS_KEY = "{AWS}"\n',
        f'JWT_SECRET = "{JWT}"\n',
        f'db_password: str = "{DBPW}"\n',
        f'class C:\n    def __init__(self):\n        self.api_key = "{AWS}"\n',
        f'import psycopg2\nconn = psycopg2.connect(host="db", password="{DBPW}")\n',
        f'CONFIG = {{"auth_token": "{JWT}"}}\n',
        f'settings = {{}}\nsettings["secret_key"] = "{JWT}"\n',
        f'def login(user, password="{DBPW}"):\n    pass\n',
        f'def check(token):\n    return token == "{JWT}"\n',
        f'if (api_key := "{AWS}"):\n    pass\n',
    ],
)
def test_secret_forms_are_reported(run_scan, code):
    assert len(hits(run_scan(code), RULE)) == 1


@pytest.mark.parametrize(
    "code",
    [
        'API_KEY = ""\n',
        'password = "password"\n',  # low entropy
        'db_password = "hunter2"\n',  # low entropy (documented false negative)
        'SECRET_KEY = "changeme"\n',
        'api_key = "your-api-key-here"\n',
        'token = "<your-token>"\n',
        'AUTH_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxx"\n',
        'import os\nAPI_KEY = os.environ["API_KEY"]\n',
        'import os\nAPI_KEY = os.getenv("API_KEY", "")\n',
        'name = "x"\nAPI_KEY = f"{name}-suffix-8f7a6b5c4d3e"\n',
        'token_url = "https://auth.example.com/oauth2/token"\n',
        'password_field = "user_password_input_box"\n',
        'PASSWORD_HELP = "Your password must contain 12 characters, a digit and a symbol."\n',
        'SESSION_TOKEN_HEADER = "X-Session-Token-Value"\n',
        f'greeting = "{AWS}"\n',  # name does not look like a credential
        'secret_key = 1234567890\n',  # not a string literal
    ],
)
def test_safe_but_tempting_are_not_reported(run_scan, code):
    assert hits(run_scan(code), RULE) == []


def test_secret_is_redacted_everywhere(run_scan):
    result = run_scan(f'AWS_SECRET_ACCESS_KEY = "{AWS}"\n')
    [finding] = result.findings
    assert AWS not in finding.message and AWS not in finding.snippet
    assert "wJal…(40 chars)" in finding.message
    assert AWS not in render_sarif(result)
    assert AWS not in render_table(result)
    assert AWS not in baseline.dumps(baseline.build(result.findings))


def test_secret_fingerprint_uses_hash_of_value_not_value(run_scan):
    [finding] = run_scan(f'API_KEY = "{AWS}"\n').findings
    assert AWS not in "".join(finding.identity)
    assert finding.identity[0] == "API_KEY"


def test_sarif_location_is_the_assignment(run_scan):
    result = run_scan(f'import os\nx = 1\nJWT_SECRET = "{JWT}"\n')
    doc = json.loads(render_sarif(result))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert (region["startLine"], region["startColumn"]) == (3, 1)
