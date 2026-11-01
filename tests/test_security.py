"""
Exploit-replay security tests for MedVault.
Each test performs a real attack from the lab demonstration.
On the vulnerable code (v0-vulnerable) these tests FAIL, which fails the pipeline.
After the fixes they PASS. If anyone reverts a fix, the pipeline goes red again.
"""
import os
import re
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["MEDVAULT_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import app as medvault  # noqa: E402


@pytest.fixture
def client():
    medvault.app.config["TESTING"] = True
    with medvault.app.test_client() as c:
        yield c


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(client, user, pw):
    return client.post("/login", data={"username": user, "password": pw,
                                       "csrf_token": token(client)})


def test_idor_other_patients_report_is_blocked(client):      # T-03
    login(client, "alice", "alice123")
    r = client.get("/report/2")                                 # Bob's report
    assert r.status_code == 404
    assert "CONFIDENTIAL" not in r.get_data(as_text=True)


def test_owner_can_still_view_own_report(client):
    login(client, "alice", "alice123")
    assert client.get("/report/1").status_code == 200


def test_command_injection_is_rejected(client):                # T-02
    login(client, "alice", "alice123")
    leak = os.path.join(ROOT, "static", "pwned.txt")
    if os.path.exists(leak):
        os.remove(leak)
    client.post("/report/1/compress", data={
        "archive_name": "x; id > static/pwned.txt #",
        "csrf_token": token(client, "/report/1")})
    assert not os.path.exists(leak), "injected shell command was executed"


def test_csrf_request_without_token_is_rejected(client):       # T-04
    login(client, "alice", "alice123")
    r = client.post("/report/1/share", data={"doctor": "drevil"})   # no token
    assert r.status_code == 400
    page = client.get("/report/1").get_data(as_text=True)
    assert "drevil" not in page


def test_clickjacking_headers_present(client):                 # T-05
    login(client, "alice", "alice123")
    r = client.get("/report/1")
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")


def test_overflow_cannot_forge_verified_flag():                # T-01
    status, _name = medvault.parse_header("MVLAB|" + "A" * 36 + "|NOT-SIGNED")
    assert status != 1, "overflow forged the verified flag"


def test_valid_signed_header_still_verified():
    status, name = medvault.parse_header("MVLAB|Alice Ahmed|LABSIGNED")
    assert status == 1 and name == "Alice Ahmed"


def test_no_hardcoded_secret_or_debug():                       # T-06, T-07
    src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
    assert "medvault-dev-secret" not in src
    assert "debug=True" not in src
