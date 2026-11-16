# CLAUDE.md: Login-Log Triage (FIU Capstone demo)

## What this is
A school demo for a fictional five-person business. The owner gets weird sign-in warnings and can't tell which ones mean someone broke in. The app shows a made-up sign-in log, flags the suspicious entries with a short plain-language reason, lets you add sign-ins live to watch the detection react, and has a real sign-in demo page whose attempts feed the same log, plus an audit log.

All data is fake. Develop on localhost with Podman; deploy to a server with Docker Compose on port 8081 (Part 8). Don't add anything not listed here. Ask first.

## Stack (fixed, don't swap)
- Python 3.12, FastAPI, Jinja2, HTMX (vendored in app/static/, no CDN)
- No database: the log lives in memory, loaded from the CSV at startup
- pytest
- Podman rootless (Fedora host). Containerfile based on python:3.12-slim, runs as a non-root user.
- Pin every version in requirements.txt
- Detection is plain Python rules. No AI/ML.
- Disable FastAPI's /docs, /redoc and /openapi.json.

## Files
```
app/main.py            routes
app/rules.py           flag rules, pure functions, no I/O
app/auth.py            demo accounts, password hashing, lockout
app/audit.py           append-only audit log
app/templates/         base.html, login.html, index.html, _table.html, report.html, audit.html
app/static/            htmx.min.js, style.css
data/signins.csv       the made-up log (generated, committed)
data/planted.json      ground truth ids (only tests and /report read it)
scripts/make_log.py    deterministic generator
tests/test_rules.py, tests/test_interactive.py, tests/test_security.py
Containerfile, requirements.txt, README.md
compose.yaml, .dockerignore   production deploy (Part 8)
```

## Part 1: The log (make_log.py -> data/signins.csv)
- About 50 entries over 7 days, 5 fake users, each with a home city and usual device. Keep a `USERS` dict at the top of make_log.py; rules.py needs the home cities too.
- Fake names, emails at example.com, IPs only from 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24. Fixed random seed so output is identical every run.
- Columns: `id, timestamp, user, ip, city, device, result` (timestamp ISO 8601 local time, result is success or fail)
- Mostly normal: weekday daytime sign-ins from the home city.
- Plant these 6 suspicious entries, record their ids in planted.json:
  1. 6 fails in a row within 10 minutes, then a success (user A)
  2. 5 fails in a row within 10 minutes, then a success (user B)
  3. Success at 03:12
  4. Success at 04:40 (different user)
  5. Success from a city that is not that user's home city
  6. Success at 02:30 from a new city (gets TWO reasons)
- Plant 3 decoys that must NOT be flagged: one fail then a success (typo), a success at 06:05, and a success from the home city at 22:30.

## Part 2: Flag rules (app/rules.py)
Pure functions. Input: entries sorted by timestamp plus users' home cities. Output: dict of entry id -> list of reasons. An entry can have several reasons.
1. A `success` is flagged if the same user had 5 or more `fail` entries in a row right before it, all within 10 minutes of the success.
2. A `success` is flagged if its time is from 00:00 up to (not including) 05:00.
3. A `success` is flagged if its city is not the user's home city.

Thresholds (5 fails, 10 minutes, 00:00 to 05:00) are named constants at the top of rules.py. Fails that never end in a success are not flagged.

Reasons are one plain sentence a non-technical owner can read, built from the real data:
- `6 failed tries in a row, then success`
- `Signed in at 03:12, outside normal hours (12am to 5am)`
- `Signed in from Lagos, not their usual city (Miami)`

No jargon like "brute force" or "anomaly" in anything the user sees.

## Part 3: The page
- `GET /`: title, one-line explanation, summary line "N sign-ins, M flagged", then a table of ALL entries newest first (time, user, city, device, result, Flag column). Flagged rows have a highlighted background plus the word "Flagged", with each reason listed.
- Two HTMX buttons, **All** and **Flagged only**, calling `GET /table?filter=all|flagged` and swapping the table (hx-get, hx-target, hx-swap="outerHTML"). No page reload.
- `GET /healthz` returns {"status": "ok"} (no login needed).
- Style: plain and minimal, system font, one accent color, no gradients, no animation, no cartoon styling.
- Run the rules at startup and again after any change to the log. Cache the result between changes.

## Part 4: Interactive demo
- **Try a sign-in form** on `/`: user (dropdown), city (text), time (HH:MM, blank means now), result (success/fail), submit button. It POSTs via HTMX to `/signins`, appends to the in-memory log, reruns the rules, swaps the table and summary line. The new row shows at the top, flagged with reasons or normal. Submitted entries go through the same rules as CSV data, no special-casing.
- **Replay attack button**: `POST /replay` injects 6 failed sign-ins for one user spaced about a minute apart, then a success. Entries arrive one at a time (HTMX polling every second or a short server-side sequence), so on screen the fails pile up as normal rows and then the success flips to Flagged with "6 failed tries in a row, then success".
- **Reset log button**: `POST /reset` restores the original CSV data.
- The summary line updates after every submit, replay and reset.
- Injected entries get new ids above the CSV ids and are marked as injected so the report can ignore them.

## Part 5: Sign-in demo (changed by the team: the site needs no login)
- The whole site is open: no sessions, cookies, roles or 403s. There is nothing real to protect.
- "Sign-in demo" is a tab in the top bar (`GET /login`, `POST /login`). It's a real login against two fake accounts, `owner1` and `employee1`, both with password `1234` (`DEMO_ACCOUNTS` in auth.py). The passwords are public on purpose: the sign-in page shows them, the README doesn't list them. Hashed with `hashlib.scrypt`. Never log what people type.
- Every attempt, right or wrong, is added to the in-memory sign-in log (user = username typed, city "Localhost", marked injected) and goes through the same rules. owner1 and employee1 have home city "Localhost". The page shows whether that attempt got flagged and why.
- Lockout: after 6 failed tries for one username within 10 minutes, reject all tries for that username for 10 minutes, even with the right password (429). Blocked tries are logged as failed sign-ins. 6, not 5, so that 5 wrong tries plus the right one shows the flag before the lock. Wrong username and wrong password return the same message. Reset log also clears lockouts.

## Part 6: Audit log
- Append-only, in memory, also written line by line to `/tmp/audit.log`. Fields: timestamp, username (or "anonymous"), route, action, result.
- Log every sign-in demo success and failure, lockout, page view, filter click, form submit, replay, reset and report view.
- `GET /audit` shows it newest first in a table.
- No route edits or deletes audit entries.

## Part 7: Detection report
- `GET /report` shows, for the ORIGINAL CSV data only (injected entries ignored): planted entries caught X of Y, normal entries wrongly flagged Z of N, decoys wrongly flagged. Also show the plain-language thresholds the rules use.
- /report reads planted.json. The flagging code in rules.py and the routes that flag entries must NOT read planted.json, otherwise the tests prove nothing.

## Part 8: Production (added by the team)
- Deploy with Docker Compose (`compose.yaml`) on an AlmaLinux server, host port 8081 -> container port 8000. No .env needed; optional settings are commented in compose.yaml.
- Container: read-only root filesystem, tmpfs /tmp, all capabilities dropped, no-new-privileges, 512 MB memory limit, healthcheck on /healthz, restart unless-stopped, rotated json logs. One container only (state is in memory).
- App guards, all in memory and env-tunable:
  - rate limit of 30 POSTs per minute per client IP (`RATE_LIMIT_PER_MINUTE`) on /signins, /replay, /reset, /login; returns 429 and is audited
  - POST bodies capped at 16 KB (413), POST without Content-Length rejected (411)
  - demo-added rows capped at 500, oldest dropped first (`MAX_INJECTED_ENTRIES`); original CSV rows always kept
  - audit memory capped at 5,000 entries; /tmp/audit.log rotates to audit.log.1 at 5 MB
  - at most 4 scrypt hashes at once; lockout tracking pruned past 10,000 usernames
  - security headers on every response: strict CSP (no inline scripts or styles), X-Frame-Options DENY, nosniff, no-referrer
- Behind a reverse proxy on the same host: publish `127.0.0.1:8081:8000` and set `FORWARDED_ALLOW_IPS: "*"` in compose.yaml so the rate limit sees real IPs. Never set it while the port is public.

## Tests
tests/test_rules.py (unit):
- Every id in planted.json is flagged; none of the 3 decoys are.
- Entry 6 (the combo) has 2 reasons.
- 4 fails then success NOT flagged; 5 fails then success flagged.
- 5 fails spread over more than 10 minutes then success NOT flagged.
- 04:59 flagged, 05:00 not.

tests/test_interactive.py (TestClient):
- `/` shows every CSV entry (row count equals the CSV).
- `/table?filter=flagged` returns only flagged rows.
- Posting 5 fails then a success flags the success; 4 fails then a success does not.
- A success posted at 03:00 is flagged; at 12:00 is not.
- Replay ends with the last entry flagged with the failed-tries reason.
- Reset restores the original count.

tests/test_security.py (TestClient):
- Every page opens without a login; no cookies are set.
- A correct password adds an unflagged success; a wrong one adds a failed row, returns 401 and is audited.
- 5 wrong tries then the right password: that success is flagged "5 failed tries in a row, then success". 4 wrong then right is not.
- 6 wrong tries then the correct password is rejected (lockout, 429) and logged as a failed row; it lifts after 10 minutes; Reset clears it.
- Wrong username and wrong password give the same message. The sign-in page shows both demo accounts with password 1234.
- `/docs`, `/redoc`, `/openapi.json` return 404.
- No route allows editing the audit log; audit file lines are JSON and never contain passwords.
- Report numbers match the real data: all planted caught, 0 false positives, 0 decoys flagged; sign-in demo entries are ignored.
- Production guards: security headers, no inline code, 413/411 limits, per-IP rate limit, demo row cap, audit memory cap and file rotation.

IMPORTANT: all tests must pass inside the container before anything is called done.

## Podman / container
- Containerfile from python:3.12-slim, create and run as a non-root user, `pip install --no-cache-dir -r requirements.txt`, expose 8000.
- Command: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- README gives these exact commands:
```
podman build -t login-triage .
podman run --rm -p 8000:8000 login-triage
podman run --rm login-triage pytest -q
```
- Local development: rootless Podman only. No sudo, no --privileged, no host network. If a volume is ever needed, use the `:Z` suffix.
- Server: Docker Compose per Part 8 (Docker's daemon needs sudo there; the container itself still runs as a non-root user with all capabilities dropped).

## README must include
- What it is, how to run it, and that the two fake demo accounts' passwords are shown on the sign-in page (don't list them in the README).
- Demo script for Zoom: (1) show the flagged log, (2) press Replay attack and watch the flag appear, (3) submit a normal sign-in and show it isn't flagged, (4) on the Sign-in demo tab, guess owner1's password 5 times then enter it and show the flag, then show the lockout, (5) show /report and /audit, (6) show the passing tests.
- How to deploy on AlmaLinux with Docker Compose on port 8081.
- Known limits: no login on the site itself (anyone who can reach it can use every page, including Reset), plain HTTP unless a proxy adds HTTPS, everything is lost on restart, one container only, fixed-threshold rules, fake data and fake accounts only, anyone with access to the container can edit the audit file.

## Out of scope (don't build)
Real log ingestion, file upload, email or alerts, blocking IPs, a real database server, charts, dark mode, user management, anything not listed above.

## Build order
1. make_log.py and the data files (everything depends on this)
2. rules.py and test_rules.py
3. basic routes and templates (Part 3)
4. interactive features (Part 4) and test_interactive.py
5. sign-in demo and lockout, then audit log, then report (Parts 5, 6, 7) and test_security.py
6. Containerfile and README, run everything in Podman

## Done means
1. Page shows every log entry; every planted entry is flagged with a readable reason; no decoys flagged.
2. Replay attack and the live form work on screen.
3. Sign-in demo attempts are flagged by the rules; lockout, audit log and report work.
4. `podman build` and `podman run` work with the README commands.
5. All three test files pass inside the container.

## How to work with me
- Build in the order above and show me each step working before moving on.
- If something is ambiguous, ask instead of guessing.
- Don't say anything works unless you ran it. At the end, give me a short list: what works, what you ran to check it, and what isn't tested or doesn't work.

## Implementation decisions (made while building)
- "Now" uses Miami time: the Containerfile sets `TZ=America/New_York` (override with `-e TZ=...`).
- The app imports `USERS` from `scripts/make_log.py` for home cities, names and devices (so `scripts/` is copied into the image). rules.py still only receives home cities as an argument.
- `planted.json`: `{"suspicious": {name: id}, "decoys": {name: [ids]}}`. For the fails-then-success cases the id is the success entry; the typo decoy lists both its fail and its success.
- Form entries: a time in HH:MM is placed on today's date. Device is the user's usual device; IP is 192.0.2.10.
- Replay targets Carla, from her home city, timestamps ending at "now". Entries are released one per `REPLAY_STEP_SECONDS` (default 1; tests set 0) and the table polls every second while a replay is running.
- Lockout applies to any username typed, real or not, so it doesn't reveal which accounts exist.
- Audit lines in /tmp/audit.log are JSON, one per line, so a username with odd characters can't fake extra lines. Table refreshes from replay polling are audited as "table refresh".
