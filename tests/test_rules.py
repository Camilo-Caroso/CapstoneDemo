"""Unit tests for app/rules.py. data/planted.json is the ground truth."""

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.rules import Entry, flag_entries
from scripts.make_log import USERS

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
HOME = {"u@example.com": "Miami"}
NOON = datetime(2026, 11, 2, 12, 0)
MIDNIGHT = datetime(2026, 11, 2)


@pytest.fixture(scope="module")
def planted():
    return json.loads((DATA / "planted.json").read_text())


@pytest.fixture(scope="module")
def flags():
    with open(DATA / "signins.csv", newline="") as f:
        entries = [
            Entry(int(r["id"]), datetime.fromisoformat(r["timestamp"]), r["user"],
                  r["ip"], r["city"], r["device"], r["result"])
            for r in csv.DictReader(f)
        ]
    homes = {user: u["home_city"] for user, u in USERS.items()}
    return flag_entries(sorted(entries, key=lambda e: e.timestamp), homes)


def make(base, minutes, result, id_):
    return Entry(id_, base + timedelta(minutes=minutes), "u@example.com",
                 "203.0.113.1", "Miami", "laptop", result)


def fails_then_success(n_fails, spacing_min):
    out = [make(NOON, i * spacing_min, "fail", i + 1) for i in range(n_fails)]
    out.append(make(NOON, n_fails * spacing_min, "success", n_fails + 1))
    return out


# --- against the generated log ---

def test_every_planted_entry_is_flagged(planted, flags):
    for name, id_ in planted["suspicious"].items():
        assert id_ in flags, f"planted '{name}' (id {id_}) not flagged"


def test_no_decoy_is_flagged(planted, flags):
    assert len(planted["decoys"]) == 3
    for name, ids in planted["decoys"].items():
        for id_ in ids:
            assert id_ not in flags, f"decoy '{name}' (id {id_}) flagged: {flags[id_]}"


def test_nothing_else_is_flagged(planted, flags):
    assert set(flags) == set(planted["suspicious"].values())


def test_combo_has_two_reasons(planted, flags):
    assert flags[planted["suspicious"]["combo"]] == [
        "Signed in at 02:30, outside normal hours (12am to 5am)",
        "Signed in from Denver, not their usual city (Coral Gables)",
    ]


def test_reasons_are_readable(planted, flags):
    s = planted["suspicious"]
    assert flags[s["six_fails_then_success"]] == ["6 failed tries in a row, then success"]
    assert flags[s["five_fails_then_success"]] == ["5 failed tries in a row, then success"]
    assert flags[s["odd_hour_0312"]] == ["Signed in at 03:12, outside normal hours (12am to 5am)"]
    assert flags[s["odd_hour_0440"]] == ["Signed in at 04:40, outside normal hours (12am to 5am)"]
    assert flags[s["new_city"]] == ["Signed in from Lagos, not their usual city (Miami)"]


# --- threshold edges ---

def test_four_fails_then_success_not_flagged():
    assert flag_entries(fails_then_success(4, 1), HOME) == {}


def test_five_fails_then_success_flagged():
    assert flag_entries(fails_then_success(5, 1), HOME) == {6: ["5 failed tries in a row, then success"]}


def test_five_fails_over_more_than_ten_minutes_not_flagged():
    assert flag_entries(fails_then_success(5, 3), HOME) == {}  # first fail 15 min before


def test_fails_that_never_end_in_success_not_flagged():
    assert flag_entries([make(NOON, i, "fail", i + 1) for i in range(8)], HOME) == {}


def test_0459_flagged_0500_not():
    flags = flag_entries([make(MIDNIGHT, 4 * 60 + 59, "success", 1),
                          make(MIDNIGHT, 5 * 60, "success", 2)], HOME)
    assert flags == {1: ["Signed in at 04:59, outside normal hours (12am to 5am)"]}


def test_rules_never_read_planted_json():
    assert "planted" not in (ROOT / "app" / "rules.py").read_text()
