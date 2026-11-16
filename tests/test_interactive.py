"""Interactive demo tests (Part 4). The site needs no login."""

import csv
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.audit
from app.main import app as fastapi_app

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ROW = re.compile(r'<tr data-id="(\d+)"( class="flagged")?>(.*?)</tr>', re.S)
ANA = "ana.torres@example.com"

with open(DATA / "signins.csv", newline="") as f:
    CSV_IDS = [int(r["id"]) for r in csv.DictReader(f)]
PLANTED = json.loads((DATA / "planted.json").read_text())


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(app.audit, "AUDIT_FILE", tmp_path / "audit.log")
    monkeypatch.setenv("REPLAY_STEP_SECONDS", "0")
    with TestClient(fastapi_app) as c:  # fresh in-memory state per test
        yield c


def rows(html):
    """[(id, flagged, row_html)] in page order (newest first)."""
    return [(int(m[1]), bool(m[2]), m[3]) for m in ROW.finditer(html)]


def post(c, result, time="12:00", user=ANA, city="Miami"):
    r = c.post("/signins", data={"user": user, "city": city, "time": time, "result": result})
    assert r.status_code == 200
    return r.text


def test_index_shows_every_csv_entry(client):
    r = client.get("/")
    assert r.status_code == 200
    found = rows(r.text)
    assert len(found) == len(CSV_IDS)
    assert sorted(i for i, _, _ in found) == sorted(CSV_IDS)
    assert f"{len(CSV_IDS)} sign-ins, 6 flagged" in r.text


def test_flagged_filter_returns_only_flagged_rows(client):
    found = rows(client.get("/table?filter=flagged").text)
    assert found and all(flagged for _, flagged, _ in found)
    assert {i for i, _, _ in found} == set(PLANTED["suspicious"].values())


def test_new_entry_goes_on_top_with_id_above_csv(client):
    top_id, flagged, _ = rows(post(client, "success"))[0]
    assert top_id == max(CSV_IDS) + 1
    assert not flagged


def test_five_fails_then_success_flags_the_success(client):
    for _ in range(5):
        post(client, "fail")
    html = post(client, "success")
    top_id, flagged, row = rows(html)[0]
    assert flagged and "5 failed tries in a row, then success" in row
    assert f"{len(CSV_IDS) + 6} sign-ins, 7 flagged" in html


def test_four_fails_then_success_not_flagged(client):
    for _ in range(4):
        post(client, "fail")
    _, flagged, _ = rows(post(client, "success"))[0]
    assert not flagged


def test_success_at_0300_flagged(client):
    _, flagged, row = rows(post(client, "success", time="03:00"))[0]
    assert flagged and "Signed in at 03:00, outside normal hours (12am to 5am)" in row


def test_success_at_1200_not_flagged(client):
    _, flagged, _ = rows(post(client, "success", time="12:00"))[0]
    assert not flagged


def test_new_city_flagged(client):
    _, flagged, row = rows(post(client, "success", city="Lagos"))[0]
    assert flagged and "Signed in from Lagos, not their usual city (Miami)" in row


def test_bad_form_input_is_rejected(client):
    html = post(client, "success", time="25:99")
    assert "Time must look like" in html
    assert len(rows(html)) == len(CSV_IDS)


def test_replay_ends_with_last_entry_flagged(client):
    html = client.post("/replay").text
    found = rows(html)
    assert len(found) == len(CSV_IDS) + 7
    top_id, flagged, row = found[0]
    assert top_id == max(CSV_IDS) + 7
    assert flagged and "6 failed tries in a row, then success" in row
    # the 6 fails right under it are not flagged
    assert [f for _, f, _ in found[1:7]] == [False] * 6


def test_replay_arrives_one_at_a_time(client, monkeypatch):
    monkeypatch.setenv("REPLAY_STEP_SECONDS", "60")
    html = client.post("/replay").text
    assert len(rows(html)) == len(CSV_IDS) + 1          # only the first fail so far
    assert 'hx-trigger="every 1s"' in html               # page keeps polling
    assert "A replay is already running" in client.post("/replay").text


def test_reset_restores_original_count(client):
    post(client, "success", time="03:00")
    client.post("/replay")
    html = client.post("/reset").text
    assert len(rows(html)) == len(CSV_IDS)
    assert f"{len(CSV_IDS)} sign-ins, 6 flagged" in html
    assert max(i for i, _, _ in rows(html)) == max(CSV_IDS)


def test_report_ignores_injected_entries(client):
    post(client, "success", time="03:00")
    post(client, "success", city="Lagos")
    html = client.get("/report").text
    assert re.search(r'id="planted-caught">6 of 6<', html)
    assert re.search(r'id="false-positives">0 of 45<', html)
