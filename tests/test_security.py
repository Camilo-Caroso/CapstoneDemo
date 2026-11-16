"""Sign-in demo, lockout, audit log and report tests.

The site needs no login. The sign-in demo page is a real login whose attempts are
fed into the sign-in log, so the flag rules catch password guessing for real.
"""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.audit
import app.main
from app.auth import DEMO_ACCOUNTS
from app.main import app as fastapi_app, state

OWNER_PW = DEMO_ACCOUNTS["owner1"]
EMPLOYEE_PW = DEMO_ACCOUNTS["employee1"]
ROW = re.compile(r'<tr data-id="(\d+)"( class="flagged")?>(.*?)</tr>', re.S)
CSV_COUNT = 51


@pytest.fixture
def audit_file(monkeypatch, tmp_path):
    path = tmp_path / "audit.log"
    monkeypatch.setattr(app.audit, "AUDIT_FILE", path)
    return path


@pytest.fixture
def client(audit_file):
    with TestClient(fastapi_app) as c:  # fresh log, lockouts and audit per test
        yield c


def login(c, username, password):
    return c.post("/login", data={"username": username, "password": password})


def top_row(c):
    m = ROW.search(c.get("/table").text)
    return int(m[1]), bool(m[2]), m[3]


def audit_rows():
    return state.audit.newest_first()


# --- the site is open ------------------------------------------------------------

def test_every_page_opens_without_login(client):
    for path in ["/", "/table", "/login", "/report", "/audit", "/healthz"]:
        assert client.get(path, follow_redirects=False).status_code == 200, path


def test_no_cookies_are_set(client):
    login(client, "owner1", OWNER_PW)
    client.get("/")
    assert not client.cookies


# --- sign-in demo feeds the log --------------------------------------------------

def test_correct_password_adds_unflagged_success(client):
    r = login(client, "owner1", OWNER_PW)
    assert r.status_code == 200 and "Correct password" in r.text
    id_, flagged, row = top_row(client)
    assert id_ == CSV_COUNT + 1 and not flagged
    assert "owner1" in row and "Signed in" in row and "Localhost" in row


def test_wrong_password_adds_failed_row_401_and_audited(client):
    r = login(client, "owner1", "nope")
    assert r.status_code == 401 and "Wrong username or password." in r.text
    a = audit_rows()[0]
    assert (a.username, a.route, a.action, a.result) == ("owner1", "/login", "login", "failure")
    _, flagged, row = top_row(client)
    assert "Failed" in row and not flagged


def test_wrong_username_same_message_as_wrong_password(client):
    bad_user = login(client, "nobody", "nope")
    bad_pw = login(client, "owner1", "nope")
    assert bad_user.status_code == bad_pw.status_code == 401
    msg = lambda r: re.search(r"<strong>(.*?)</strong>", r.text).group(1)
    assert msg(bad_user) == msg(bad_pw)


def test_five_wrong_then_right_password_is_flagged(client):
    for _ in range(5):
        login(client, "owner1", "nope")
    r = login(client, "owner1", OWNER_PW)
    assert r.status_code == 200
    assert "5 failed tries in a row, then success" in r.text  # shown right on the sign-in page
    _, flagged, row = top_row(client)
    assert flagged and "5 failed tries in a row, then success" in row
    assert f"{CSV_COUNT + 6} sign-ins, 7 flagged" in client.get("/").text


def test_four_wrong_then_right_password_not_flagged(client):
    for _ in range(4):
        login(client, "employee1", "nope")
    login(client, "employee1", EMPLOYEE_PW)
    _, flagged, _ = top_row(client)
    assert not flagged


def test_sign_in_attempts_are_ignored_by_the_report(client):
    for _ in range(5):
        login(client, "owner1", "nope")
    login(client, "owner1", OWNER_PW)
    html = client.get("/report").text
    assert re.search(r'id="planted-caught">6 of 6<', html)
    assert re.search(r'id="false-positives">0 of 45<', html)


def test_reset_clears_sign_in_attempts(client):
    login(client, "owner1", "nope")
    html = client.post("/reset").text
    assert f"{CSV_COUNT} sign-ins, 6 flagged" in html


# --- lockout -------------------------------------------------------------------

def test_lockout_after_six_failures_rejects_correct_password(client):
    for _ in range(6):
        assert login(client, "owner1", "nope").status_code == 401
    r = login(client, "owner1", OWNER_PW)
    assert r.status_code == 429 and "Too many failed tries" in r.text
    _, _, row = top_row(client)
    assert "Failed" in row  # the blocked try is logged as a failed sign-in
    actions = [(a.action, a.result) for a in audit_rows()]
    assert ("lockout", "locked for 10 minutes") in actions
    assert ("login", "blocked: locked out") in actions
    assert login(client, "employee1", EMPLOYEE_PW).status_code == 200  # other accounts fine


def test_lockout_lifts_after_ten_minutes(client):
    fake_now = [1000.0]
    state.auth.clock = lambda: fake_now[0]
    for _ in range(6):
        login(client, "owner1", "nope")
    fake_now[0] += 599
    assert login(client, "owner1", OWNER_PW).status_code == 429
    fake_now[0] += 2
    assert login(client, "owner1", OWNER_PW).status_code == 200


def test_failures_spread_over_more_than_ten_minutes_do_not_lock(client):
    fake_now = [1000.0]
    state.auth.clock = lambda: fake_now[0]
    for _ in range(6):
        login(client, "owner1", "nope")
        fake_now[0] += 200
    assert login(client, "owner1", OWNER_PW).status_code == 200


def test_reset_clears_lockouts(client):
    for _ in range(6):
        login(client, "owner1", "nope")
    client.post("/reset")
    assert login(client, "owner1", OWNER_PW).status_code == 200


def test_unknown_username_locks_the_same_way(client):
    for _ in range(6):
        assert login(client, "nobody", "nope").status_code == 401
    assert login(client, "nobody", "nope").status_code == 429


def test_demo_passwords_are_1234_and_shown_on_sign_in_page(client):
    assert DEMO_ACCOUNTS == {"owner1": "1234", "employee1": "1234"}
    html = client.get("/login").text
    for name in DEMO_ACCOUNTS:
        assert f"<code>{name}</code></td><td><code>1234</code>" in html
    assert login(client, "owner1", "1234").status_code == 200
    assert login(client, "employee1", "1234").status_code == 200


# --- docs and audit log --------------------------------------------------------

def test_docs_disabled(client):
    for path in ["/docs", "/redoc", "/openapi.json"]:
        assert client.get(path).status_code == 404, path


def test_no_route_edits_the_audit_log(client):
    for method in ["post", "put", "patch", "delete"]:
        assert getattr(client, method)("/audit").status_code == 405, method
    audit_routes = [r for r in fastapi_app.routes if "audit" in getattr(r, "path", "")]
    assert all(r.methods <= {"GET", "HEAD"} for r in audit_routes)
    before = len(state.audit)
    client.post("/reset")
    client.post("/replay")
    assert len(state.audit) > before  # actions only ever add entries


def test_audit_file_is_one_json_line_per_entry_and_never_has_passwords(client, audit_file):
    login(client, "evil\nfake line", "hunter2-wrong")
    login(client, "owner1", OWNER_PW)
    client.get("/")
    parsed = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert len(parsed) == len(state.audit)
    assert set(parsed[0]) == {"timestamp", "username", "route", "action", "result"}
    assert any(p["username"] == "evil\nfake line" for p in parsed)
    text = audit_file.read_text()
    assert OWNER_PW not in text and "hunter2-wrong" not in text


def test_audit_page_shows_newest_first(client):
    client.get("/report")
    html = client.get("/audit").text
    actions = re.findall(r"<tr data-audit>.*?<td>([^<]*)</td><td>[^<]*</td></tr>", html, re.S)
    assert actions[:2] == ["audit view", "report view"]


# --- report ------------------------------------------------------------------

def test_report_numbers_match_real_data(client):
    html = client.get("/report").text
    assert re.search(r'id="planted-caught">6 of 6<', html)
    assert re.search(r'id="false-positives">0 of 45<', html)
    assert re.search(r'id="decoys-flagged">0 of 3<', html)
    assert "5 or more failed tries in a row, all within 10 minutes" in html


def test_flagging_works_without_planted_json(client, monkeypatch, tmp_path):
    """The log page must not depend on the ground-truth file."""
    monkeypatch.setattr(app.main, "PLANTED_JSON", tmp_path / "missing.json")
    r = client.get("/")
    assert r.status_code == 200 and "51 sign-ins, 6 flagged" in r.text


# --- production guards ------------------------------------------------------------

def test_security_headers_on_every_response(client):
    for path in ["/", "/login", "/static/htmx.min.js", "/healthz"]:
        h = client.get(path).headers
        assert "default-src 'self'" in h["content-security-policy"], path
        assert "frame-ancestors 'none'" in h["content-security-policy"], path
        assert h["x-content-type-options"] == "nosniff", path
        assert h["x-frame-options"] == "DENY", path


def test_pages_have_no_inline_scripts_or_styles(client):
    """The CSP blocks inline code, so the pages must not rely on any."""
    for path in ["/", "/login", "/report", "/audit"]:
        html = client.get(path).text
        assert "<style" not in html and "style=" not in html, path
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), path
        assert "hx-on" not in html, path


def test_oversized_post_rejected(client):
    r = client.post("/login", data={"username": "owner1", "password": "x" * 20_000})
    assert r.status_code == 413


def test_post_without_length_rejected(client):
    def chunks():
        yield b"username=owner1&password=x"
    r = client.post("/login", content=chunks(),
                    headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 411


def test_rate_limit_per_visitor(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "3")
    for _ in range(3):
        assert login(client, "employee1", EMPLOYEE_PW).status_code == 200
    r = login(client, "employee1", EMPLOYEE_PW)
    assert r.status_code == 429 and "Too many tries from your connection" in r.text
    r = client.post("/reset")
    assert r.status_code == 429 and 'id="log-table"' in r.text  # htmx swaps this in
    assert ("rate limited", "429") in [(a.action, a.result) for a in audit_rows()]
    assert client.get("/").status_code == 200  # reading is never limited


def test_demo_rows_are_capped_oldest_dropped_first(client, monkeypatch):
    monkeypatch.setenv("MAX_INJECTED_ENTRIES", "3")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "100")
    for _ in range(5):
        login(client, "owner1", "nope")
    ids = [int(m[1]) for m in ROW.finditer(client.get("/table").text)]
    assert len(ids) == CSV_COUNT + 3
    assert ids[:3] == [CSV_COUNT + 5, CSV_COUNT + 4, CSV_COUNT + 3]  # newest three kept
    assert set(range(1, CSV_COUNT + 1)) <= set(ids)                 # original rows untouched


def test_audit_memory_is_capped(client, monkeypatch):
    monkeypatch.setattr(app.audit, "MAX_MEMORY_ENTRIES", 10)
    with TestClient(fastapi_app) as c:
        for _ in range(25):
            c.get("/healthz")
            c.get("/report")
        assert len(state.audit) == 10


def test_audit_file_rotates(client, audit_file, monkeypatch):
    monkeypatch.setattr(app.audit, "MAX_FILE_BYTES", 500)
    for _ in range(20):
        client.get("/report")
    rotated = audit_file.with_name(audit_file.name + ".1")
    assert rotated.exists()
    assert audit_file.stat().st_size <= 500 + 300
