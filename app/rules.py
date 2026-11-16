"""Flag rules for the sign-in log. Pure functions, no I/O."""

from dataclasses import dataclass
from datetime import datetime, time, timedelta

# Thresholds. Change these, not the logic below.
FAIL_STREAK_MIN = 5                    # this many fails in a row before a success gets flagged
FAIL_WINDOW = timedelta(minutes=10)    # ...all within this long before the success
ODD_HOURS_START = time(0, 0)           # odd hours start (inclusive)
ODD_HOURS_END = time(5, 0)             # odd hours end (exclusive)


@dataclass(frozen=True)
class Entry:
    id: int
    timestamp: datetime
    user: str
    ip: str
    city: str
    device: str
    result: str  # "success" or "fail"


def _fmt_hour(t: time) -> str:
    """time(0, 0) -> '12am', time(5, 0) -> '5am', time(13, 30) -> '1:30pm'."""
    h12 = t.hour % 12 or 12
    suffix = "am" if t.hour < 12 else "pm"
    return f"{h12}{suffix}" if t.minute == 0 else f"{h12}:{t.minute:02d}{suffix}"


def odd_hours_text() -> str:
    return f"{_fmt_hour(ODD_HOURS_START)} to {_fmt_hour(ODD_HOURS_END)}"


def thresholds_plain() -> list[str]:
    """The rules in plain words, built from the constants above."""
    minutes = int(FAIL_WINDOW.total_seconds() // 60)
    return [
        f"A successful sign-in right after {FAIL_STREAK_MIN} or more failed tries in a row, "
        f"all within {minutes} minutes.",
        f"A successful sign-in between {_fmt_hour(ODD_HOURS_START)} and {_fmt_hour(ODD_HOURS_END)}.",
        "A successful sign-in from a city that isn't the person's usual city.",
    ]


def fails_before(success: Entry, earlier_for_user: list[Entry]) -> int:
    """Count the fails in a row immediately before `success` that fall within FAIL_WINDOW.

    `earlier_for_user` is that user's earlier entries, oldest first.
    """
    count = 0
    for e in reversed(earlier_for_user):
        if e.result != "fail" or success.timestamp - e.timestamp > FAIL_WINDOW:
            break
        count += 1
    return count


def is_odd_hour(ts: datetime) -> bool:
    return ODD_HOURS_START <= ts.time() < ODD_HOURS_END


def flag_entries(entries: list[Entry], home_cities: dict[str, str]) -> dict[int, list[str]]:
    """Return {entry id: [reason, ...]} for every flagged entry.

    `entries` must be sorted by timestamp (oldest first).
    `home_cities` maps user -> home city.
    Only `success` entries are ever flagged.
    """
    flags: dict[int, list[str]] = {}
    history: dict[str, list[Entry]] = {}

    for e in entries:
        earlier = history.setdefault(e.user, [])
        if e.result == "success":
            reasons = []

            n = fails_before(e, earlier)
            if n >= FAIL_STREAK_MIN:
                reasons.append(f"{n} failed tries in a row, then success")

            if is_odd_hour(e.timestamp):
                reasons.append(
                    f"Signed in at {e.timestamp:%H:%M}, outside normal hours ({odd_hours_text()})"
                )

            home = home_cities.get(e.user)
            if home is not None and e.city != home:
                reasons.append(f"Signed in from {e.city}, not their usual city ({home})")

            if reasons:
                flags[e.id] = reasons
        earlier.append(e)

    return flags
