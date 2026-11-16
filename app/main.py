"""FastAPI app: routes, the in-memory sign-in log, the sign-in demo and the report."""

import csv
import json
import os
import re
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.audit import AuditLog
from app.auth import DEMO_ACCOUNTS, AuthStore
from app.rules import Entry, flag_entries, thresholds_plain
from scripts.make_log import USERS

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR.parent / "data"
LOG_CSV = DATA_DIR / "signins.csv"
PLANTED_JSON = DATA_DIR / "planted.json"  # read ONLY by the /report route

DEMO_CITY = "Localhost"  # attempts on the sign-in demo page come from here
HOME_CITIES = {user: u["home_city"] for user, u in USERS.items()}
HOME_CITIES.update({"owner1": DEMO_CITY, "employee1": DEMO_CITY})
FORM_IP = "192.0.2.10"
LOGIN_DEVICE = "Web browser (sign-in page)"
REPLAY_USER = "carla.nguyen@example.com"
REPLAY_IP = "198.51.100.66"
REPLAY_FAILS = 6
TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

templates = Jinja2Templates(directory=APP_DIR / "templates")
templates.env.globals["demo_accounts"] = DEMO_ACCOUNTS  # shown on the sign-in page


# Production limits (env-overridable). They keep a public demo from being flooded.
MAX_BODY_BYTES = 16 * 1024


def _env_num(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def replay_step_seconds() -> float:
    return _env_num("REPLAY_STEP_SECONDS", 1)


def max_injected_entries() -> int:
    """Most demo-added rows kept at once; the oldest are dropped first."""
    return int(_env_num("MAX_INJECTED_ENTRIES", 500))


def rate_limit_per_minute() -> int:
    """Most form posts / button presses per visitor IP per minute."""
    return int(_env_num("RATE_LIMIT_PER_MINUTE", 30))


class RateLimiter:
    """Sliding one-minute window per client IP, in memory."""

    MAX_TRACKED = 10_000

    def __init__(self):
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > self.MAX_TRACKED:
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= window]:
                    del self._hits[k]
                while len(self._hits) > self.MAX_TRACKED:  # still too many: drop the oldest keys
                    self._hits.pop(next(iter(self._hits)))
            return True


def read_csv(path: Path) -> list[Entry]:
    with open(path, newline="") as f:
        return [
            Entry(int(r["id"]), datetime.fromisoformat(r["timestamp"]), r["user"],
                  r["ip"], r["city"], r["device"], r["result"])
            for r in csv.DictReader(f)
        ]


class SigninLog:
    """The live log: original CSV entries plus injected ones. Rules rerun on every change."""

    def __init__(self, original: list[Entry]):
        self.original = sorted(original, key=lambda e: (e.timestamp, e.id))
        self.original_flags = flag_entries(self.original, HOME_CITIES)  # for the report
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.entries = list(self.original)
        self.injected_ids: set[int] = set()
        self.pending: list[tuple[float, dict]] = []  # (release time, entry fields)
        self.next_id = max((e.id for e in self.original), default=0) + 1
        self._recompute()

    def _recompute(self) -> None:
        self.entries.sort(key=lambda e: (e.timestamp, e.id))
        self.flags = flag_entries(self.entries, HOME_CITIES)

    def _append(self, **fields) -> Entry:
        e = Entry(id=self.next_id, **fields)
        self.next_id += 1
        self.entries.append(e)
        self.injected_ids.add(e.id)
        excess = len(self.injected_ids) - max_injected_entries()
        if excess > 0:  # drop the oldest demo-added rows; original CSV rows always stay
            dropped = set(sorted(self.injected_ids)[:excess])
            self.injected_ids -= dropped
            self.entries = [x for x in self.entries if x.id not in dropped]
        return e

    def add(self, **fields) -> Entry:
        with self._lock:
            e = self._append(**fields)
            self._recompute()
            return e

    def queue_replay(self, now: datetime) -> bool:
        """Queue 6 fails a minute apart then a success, released one per step. False if busy."""
        with self._lock:
            if self.pending:
                return False
            start = now - timedelta(minutes=REPLAY_FAILS)
            t0, step = time.monotonic(), replay_step_seconds()
            for i in range(REPLAY_FAILS + 1):
                result = "fail" if i < REPLAY_FAILS else "success"
                self.pending.append((t0 + i * step, {
                    "timestamp": start + timedelta(minutes=i), "user": REPLAY_USER,
                    "ip": REPLAY_IP, "city": HOME_CITIES[REPLAY_USER],
                    "device": USERS[REPLAY_USER]["device"], "result": result,
                }))
        self.release_due()
        return True

    def release_due(self) -> None:
        with self._lock:
            now = time.monotonic()
            due = [f for t, f in self.pending if t <= now]
            if not due:
                return
            self.pending = [(t, f) for t, f in self.pending if t > now]
            for fields in due:
                self._append(**fields)
            self._recompute()

    @property
    def replaying(self) -> bool:
        return bool(self.pending)

    def rows(self, only_flagged: bool) -> list[dict]:
        out = []
        for e in reversed(self.entries):  # newest first
            reasons = self.flags.get(e.id, [])
            if only_flagged and not reasons:
                continue
            out.append({
                "id": e.id,
                "time": f"{e.timestamp:%a} {e.timestamp.day} {e.timestamp:%b, %H:%M}",
                "user": USERS.get(e.user, {}).get("name", e.user),
                "city": e.city,
                "device": e.device,
                "result": e.result,
                "reasons": reasons,
            })
        return out


class State:
    log: SigninLog
    auth: AuthStore
    audit: AuditLog
    limiter: RateLimiter


state = State()


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.log = SigninLog(read_csv(LOG_CSV))
    state.auth = AuthStore.demo()
    state.audit = AuditLog()
    state.limiter = RateLimiter()
    yield


app = FastAPI(title="Login-Log Triage", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")


# --- production guards ----------------------------------------------------------

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
                                "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.middleware("http")
async def guards(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        length = request.headers.get("content-length")
        if length is None:
            return PlainTextResponse("Length required", status_code=411)
        if not length.isdigit():
            return PlainTextResponse("Bad request", status_code=400)
        if int(length) > MAX_BODY_BYTES:
            return PlainTextResponse("Request too large", status_code=413)
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


class RateLimited(Exception):
    pass


def client_ip(request: Request) -> str:
    # Behind a reverse proxy, uvicorn fills this from X-Forwarded-For (see FORWARDED_ALLOW_IPS).
    return request.client.host if request.client else "unknown"


def limit_writes(request: Request) -> None:
    if not state.limiter.allow(client_ip(request), rate_limit_per_minute()):
        state.audit.record(None, request.url.path, "rate limited", "429")
        raise RateLimited()


SLOW_DOWN = "Too many tries from your connection. Wait a minute and try again."


@app.exception_handler(RateLimited)
async def rate_limited(request: Request, exc: RateLimited):
    if request.url.path == "/login":
        return templates.TemplateResponse(request, "login.html", {"error": SLOW_DOWN}, status_code=429)
    return templates.TemplateResponse(request, "_table.html", table_context("all", error=SLOW_DOWN),
                                      status_code=429)


# --- log page ----------------------------------------------------------------

def table_context(filter_: str, notice: str = "", error: str = "") -> dict:
    log = state.log
    return {
        "rows": log.rows(only_flagged=filter_ == "flagged"),
        "filter": filter_,
        "total": len(log.entries),
        "flagged_count": len(log.flags),
        "replaying": log.replaying,
        "notice": notice,
        "error": error,
    }


def table_response(request: Request, filter_: str = "all", **kw):
    return templates.TemplateResponse(request, "_table.html", table_context(filter_, **kw))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    state.log.release_due()
    state.audit.record(None, "/", "page view", "200")
    ctx = table_context("all")
    ctx["users"] = USERS
    return templates.TemplateResponse(request, "index.html", ctx)


@app.get("/table", response_class=HTMLResponse)
def table(request: Request, filter: Literal["all", "flagged"] = "all"):
    state.log.release_due()
    polling = request.headers.get("HX-Trigger") == "log-table"
    action = "table refresh" if polling else f"filter click ({filter})"
    state.audit.record(None, "/table", action, "200")
    return table_response(request, filter)


@app.post("/signins", response_class=HTMLResponse)
def add_signin(request: Request, user: str = Form(""), city: str = Form(""),
               time_: str = Form("", alias="time"), result: str = Form(""),
               _: None = Depends(limit_writes)):
    city = city.strip()
    time_ = time_.strip()
    error = ""
    if user not in USERS:
        error = "Pick a user from the list."
    elif not city or len(city) > 60:
        error = "Type a city (up to 60 characters)."
    elif result not in ("success", "fail"):
        error = "Pick success or fail."
    elif time_ and not TIME_RE.match(time_):
        error = "Time must look like 14:05, or be left blank for now."
    if error:
        state.audit.record(None, "/signins", "form submit", f"rejected: {error}")
        return table_response(request, error=error)

    now = datetime.now().replace(microsecond=0)
    if time_:
        hh, mm = map(int, time_.split(":"))
        ts = now.replace(hour=hh, minute=mm, second=0)
    else:
        ts = now
    e = state.log.add(timestamp=ts, user=user, ip=FORM_IP, city=city,
                      device=USERS[user]["device"], result=result)
    state.audit.record(None, "/signins", "form submit", f"added entry {e.id}")
    return table_response(request, notice=f"Added sign-in #{e.id}.")


@app.post("/replay", response_class=HTMLResponse)
def replay(request: Request, _: None = Depends(limit_writes)):
    started = state.log.queue_replay(datetime.now().replace(microsecond=0))
    state.audit.record(None, "/replay", "replay attack",
                       "started" if started else "ignored: already running")
    notice = "Replaying 6 failed tries then a success for Carla Nguyen…" if started \
        else "A replay is already running."
    return table_response(request, notice=notice)


@app.post("/reset", response_class=HTMLResponse)
def reset(request: Request, _: None = Depends(limit_writes)):
    state.log.reset()
    state.auth.clear_lockouts()
    state.audit.record(None, "/reset", "reset log", "200")
    return table_response(request, notice="Log reset to the original data. Sign-in lockouts cleared.")


# --- report and audit ----------------------------------------------------------

def detection_report() -> dict:
    """Score the rules against planted.json, using the ORIGINAL CSV entries only."""
    planted = json.loads(PLANTED_JSON.read_text())
    log = state.log
    flags = log.original_flags
    by_id = {e.id: e for e in log.original}

    suspicious_ids = set(planted["suspicious"].values())
    normal_ids = set(by_id) - suspicious_ids
    caught = [i for i in sorted(suspicious_ids) if i in flags]
    false_pos = [i for i in sorted(normal_ids) if i in flags]
    decoys_flagged = [name for name, ids in planted["decoys"].items() if any(i in flags for i in ids)]

    def describe(i):
        e = by_id[i]
        return {"id": i, "time": f"{e.timestamp:%a} {e.timestamp.day} {e.timestamp:%b, %H:%M}",
                "user": USERS.get(e.user, {}).get("name", e.user), "city": e.city,
                "reasons": flags.get(i, [])}

    return {
        "planted_caught": len(caught), "planted_total": len(suspicious_ids),
        "false_positives": len(false_pos), "normal_total": len(normal_ids),
        "decoys_flagged": len(decoys_flagged), "decoys_total": len(planted["decoys"]),
        "planted_rows": [describe(i) for i in sorted(suspicious_ids)],
        "false_positive_rows": [describe(i) for i in false_pos],
        "thresholds": thresholds_plain(),
    }


@app.get("/report", response_class=HTMLResponse)
def report(request: Request):
    state.audit.record(None, "/report", "report view", "200")
    return templates.TemplateResponse(request, "report.html",
                                      detection_report())


@app.get("/audit", response_class=HTMLResponse)
def audit(request: Request):
    state.audit.record(None, "/audit", "audit view", "200")
    return templates.TemplateResponse(request, "audit.html",
                                      {"entries": state.audit.newest_first()})


# --- sign-in demo ----------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    state.audit.record(None, "/login", "page view", "200")
    return templates.TemplateResponse(request, "login.html", {})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(""), password: str = Form(""),
          _: None = Depends(limit_writes)):
    """A real sign-in attempt. It's checked against the demo accounts AND added to the log."""
    username = username.strip()[:64]
    if not username:
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Type a username."}, status_code=400)

    result = state.auth.login(username, password)
    ok = result.status == "ok"
    entry = state.log.add(timestamp=datetime.now().replace(microsecond=0), user=username,
                          ip=FORM_IP, city=DEMO_CITY, device=LOGIN_DEVICE,
                          result="success" if ok else "fail")

    if ok:
        state.audit.record(username, "/login", "login", "success")
        message, status = f"Correct password. Signed in as {username}.", 200
    elif result.status == "locked":
        state.audit.record(username, "/login", "login", "blocked: locked out")
        message, status = "Too many failed tries for this username. Wait 10 minutes and try again.", 429
    else:
        state.audit.record(username, "/login", "login", "failure")
        if result.locked_now:
            state.audit.record(username, "/login", "lockout", "locked for 10 minutes")
        message, status = "Wrong username or password.", 401

    return templates.TemplateResponse(request, "login.html", {
        "ok": ok, "message": message, "username": username,
        "entry_id": entry.id, "reasons": state.log.flags.get(entry.id, []),
    }, status_code=status)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
