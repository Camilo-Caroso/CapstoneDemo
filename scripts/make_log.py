"""Generate the made-up sign-in log: data/signins.csv and data/planted.json.

Fixed random seed, so every run produces identical files.
Run from the project root:  python -m scripts.make_log
"""

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

# The five fake employees. All emails at example.com. The app reads this too.
USERS = {
    "ana.torres@example.com": {"name": "Ana Torres", "home_city": "Miami", "device": "Windows laptop"},
    "ben.okafor@example.com": {"name": "Ben Okafor", "home_city": "Fort Lauderdale", "device": "MacBook"},
    "carla.nguyen@example.com": {"name": "Carla Nguyen", "home_city": "Hialeah", "device": "iPhone"},
    "dev.patel@example.com": {"name": "Dev Patel", "home_city": "Coral Gables", "device": "Windows desktop"},
    "erin.walsh@example.com": {"name": "Erin Walsh", "home_city": "Homestead", "device": "Android phone"},
}

SEED = 1149
WEEK_START = datetime(2026, 11, 2)  # Monday; the log covers Mon 2 Nov to Sun 8 Nov
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Documentation-only IP ranges (RFC 5737). Never real addresses.
HOME_NET = "203.0.113."    # employees' usual connections
TRAVEL_NET = "198.51.100."  # sign-ins from somewhere new
GUESS_NET = "192.0.2."     # the repeated failed tries

ANA, BEN, CARLA, DEV, ERIN = USERS


def home_ip(user):
    return HOME_NET + str(10 + list(USERS).index(user))


def entry(ts, user, result="success", ip=None, city=None, device=None, tag=None):
    return {
        "timestamp": ts,
        "user": user,
        "ip": ip or home_ip(user),
        "city": city or USERS[user]["home_city"],
        "device": device or USERS[user]["device"],
        "result": result,
        "tag": tag,
    }


def day(n, hh, mm, ss=0):
    return WEEK_START + timedelta(days=n, hours=hh, minutes=mm, seconds=ss)


def normal_entries(rng):
    """Weekday daytime sign-ins from each user's home city, usual device."""
    out = []
    for d in range(5):  # Mon..Fri
        for user in USERS:
            out.append(entry(day(d, rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59)), user))
    for i in range(4):  # a few extra afternoon sign-ins, one with a single typo first
        user = rng.choice(list(USERS))
        ts = day(rng.randint(0, 4), rng.randint(13, 17), rng.randint(0, 59), rng.randint(0, 59))
        if i == 0:
            out.append(entry(ts - timedelta(seconds=25), user, "fail"))
        out.append(entry(ts, user))
    return out


def planted_entries():
    out = []
    # 1. Six fails in a row within 10 minutes, then a success (Dev, Wed evening).
    start = day(2, 19, 40)
    for i in range(6):
        out.append(entry(start + timedelta(seconds=80 * i), DEV, "fail", ip=GUESS_NET + "45"))
    out.append(entry(start + timedelta(seconds=80 * 6 + 10), DEV, ip=GUESS_NET + "45",
                     tag="s:six_fails_then_success"))
    # 2. Five fails then a success, different user (Carla, Fri evening).
    start = day(4, 20, 15)
    for i in range(5):
        out.append(entry(start + timedelta(seconds=90 * i), CARLA, "fail", ip=GUESS_NET + "77"))
    out.append(entry(start + timedelta(seconds=90 * 5), CARLA, ip=GUESS_NET + "77",
                     tag="s:five_fails_then_success"))
    # 3. Success at 03:12 (Ben, Thu), home city.
    out.append(entry(day(3, 3, 12), BEN, tag="s:odd_hour_0312"))
    # 4. Success at 04:40 (Erin, Sat), home city.
    out.append(entry(day(5, 4, 40), ERIN, tag="s:odd_hour_0440"))
    # 5. Success from a city that isn't home (Ana, Tue afternoon, Lagos).
    out.append(entry(day(1, 14, 20), ANA, ip=TRAVEL_NET + "23", city="Lagos",
                     device="Unknown Windows PC", tag="s:new_city"))
    # 6. Combo: 02:30 from a new city (Dev, Sun, Denver) -> two reasons.
    out.append(entry(day(6, 2, 30), DEV, ip=TRAVEL_NET + "88", city="Denver",
                     device="Unknown Mac", tag="s:combo"))
    # Decoys that must NOT be flagged.
    out.append(entry(day(0, 9, 14, 5), BEN, "fail", tag="d:typo"))
    out.append(entry(day(0, 9, 14, 40), BEN, tag="d:typo"))
    out.append(entry(day(1, 6, 5), CARLA, tag="d:early_0605"))
    out.append(entry(day(3, 22, 30), ANA, tag="d:late_2230"))
    return out


def main():
    rng = random.Random(SEED)
    entries = sorted(normal_entries(rng) + planted_entries(), key=lambda e: e["timestamp"])

    planted = {"suspicious": {}, "decoys": {}}
    for i, e in enumerate(entries, start=1):
        e["id"] = i
        if e["tag"]:
            kind, name = e["tag"].split(":")
            if kind == "s":
                planted["suspicious"][name] = i
            else:
                planted["decoys"].setdefault(name, []).append(i)

    DATA_DIR.mkdir(exist_ok=True)
    with open(DATA_DIR / "signins.csv", "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["id", "timestamp", "user", "ip", "city", "device", "result"])
        for e in entries:
            w.writerow([e["id"], e["timestamp"].isoformat(), e["user"], e["ip"],
                        e["city"], e["device"], e["result"]])
    with open(DATA_DIR / "planted.json", "w") as f:
        json.dump(planted, f, indent=2)
        f.write("\n")

    print(f"Wrote {len(entries)} sign-ins, {len(planted['suspicious'])} planted, "
          f"{len(planted['decoys'])} decoys")


if __name__ == "__main__":
    main()
