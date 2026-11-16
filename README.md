# Login-Log Triage

An FIU capstone demo. A fictional five-person business gets sign-in warnings and can't tell which ones mean someone broke in. This app shows a made-up week of employee sign-ins and flags the suspicious ones, each with a short plain-language reason.

You can also attack it for real. The **Sign-in demo** tab is a working login form. Every try, right or wrong, lands in the same log and goes through the same rules, so guessing a password gets you flagged.

Everything is fake: the data, the people and the accounts. It runs on localhost only. The site itself has no login, because there's nothing real to protect.

## Run it (rootless Podman)

```
podman build -t login-triage .
podman run --rm -p 8000:8000 login-triage
podman run --rm login-triage pytest -q
```

Then open <http://127.0.0.1:8000>.

> If `curl localhost:8000` gives "connection reset", use `127.0.0.1`. On Fedora, `localhost` tries IPv6 first and the app only listens on IPv4. Browsers fall back to IPv4 on their own.

## The sign-in demo accounts

There are two fake accounts, `owner1` and `employee1`. Their passwords aren't secret: the **Sign-in demo** page shows them so anyone can try it. The app still hashes them with scrypt at startup and never logs what people type.

- After **6 wrong tries in 10 minutes**, that username is locked for 10 minutes, even with the right password.
- **Reset log** clears lockouts, so you don't have to wait mid-demo.
- The lockout kicks in at 6 so that 5 wrong tries plus the right password shows the flag first.

Other settings:
- `REPLAY_STEP_SECONDS`: seconds between Replay entries, default 1
- `TZ`: clock used for "now", default `America/New_York`

## Demo script (Zoom)

1. **Show the log:** "51 sign-ins, 6 flagged". Click **Flagged only** to show the six flagged sign-ins and their reasons, then **All** to show the decoys aren't flagged (Ben's single typo on Monday, Carla at 06:05, Ana at 22:30).
2. **Press Replay attack.** Over about 7 seconds, six failed tries for Carla Nguyen appear one at a time, then the success arrives on top, flagged with "6 failed tries in a row, then success".
3. **Submit a normal sign-in** with the "Try a sign-in" form: pick a user, type their usual city, leave the time blank and choose success. It's not flagged. For contrast, try `03:00` or `Lagos`.
4. **Attack the real login.** Open the **Sign-in demo** tab:
   1. Type `owner1` (password shown on the page) with a wrong password 5 times. Each try says "Added to the log as a failed sign-in".
   2. Type the right password. The page says it was **Flagged: 5 failed tries in a row, then success**. Click "See it in the log".
   3. Now type 6 wrong passwords. On the next try, even the right password is refused: "Too many failed tries".
5. **Show Report** (6 of 6 planted caught, 0 false alarms, plus the rules in plain words) and **Audit** (every sign-in try, lockout and action, newest first). Press **Reset log** to clean up.
6. **Show the passing tests:** `podman run --rm login-triage pytest -q`

## What gets flagged

Only successful sign-ins are flagged. One entry can have several reasons.

- 5 or more failed tries in a row by the same person, all within 10 minutes before the success, e.g. `6 failed tries in a row, then success`
- a sign-in from 00:00 to before 05:00, e.g. `Signed in at 03:12, outside normal hours (12am to 5am)`
- a city that isn't the person's usual city, e.g. `Signed in from Lagos, not their usual city (Miami)`

Sign-in demo tries come from "Localhost", which is owner1's and employee1's usual city, so only the failed-tries and odd-hours rules apply to them. The thresholds are constants at the top of `app/rules.py`.

## Data

`python3.12 -m scripts.make_log` (run from the project root) regenerates `data/signins.csv` and `data/planted.json` with a fixed seed. Names, emails (`@example.com`) and IPs (documentation ranges only) are all made up. `planted.json` is the answer key. Only the tests and the `/report` page read it; the flagging code doesn't.

## Deploy on a server (AlmaLinux 9, Docker Compose, port 8081)

`compose.yaml` runs the app on host port **8081**. Production settings are already in it:
- read-only container, with `/tmp` as the only writable place
- all Linux capabilities dropped, plus no-new-privileges
- 512 MB memory cap
- health check and auto-restart
- log rotation

The app also protects itself:
- 30 form posts or button presses per minute per visitor
- 16 KB request limit
- a cap of 500 demo-added rows, oldest dropped first
- audit history capped and the audit file rotated
- at most 4 password checks running at once
- security headers (CSP, no framing, nosniff)

### 1. Install Docker (once, as a sudo user)

```
sudo dnf -y remove podman buildah runc   # these conflict with Docker on AlmaLinux
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
docker compose version   # check it works (run with sudo if needed)
```

### 2. Copy the project to the server

From your laptop, in the project folder (replace `you@server`):

```
rsync -av --exclude __pycache__ ./ you@server:~/login-triage/
```

### 3. Build and start

On the server:

```
cd ~/login-triage
sudo docker compose up -d --build
sudo docker compose ps                    # STATUS should say "healthy" after ~10 s
curl http://127.0.0.1:8081/healthz        # {"status":"ok"}
sudo docker compose run --rm app pytest -q   # optional: run the tests on the server
```

It's now at `http://<server-ip>:8081`. Docker opens the port itself, so firewalld won't block it, but a cloud provider's firewall or security group may still need TCP 8081 allowed. The container restarts on its own after crashes and reboots.

### Day to day

| Task | Command (in `~/login-triage`) |
|---|---|
| See logs | `sudo docker compose logs -f` |
| See the audit file | `sudo docker compose exec app cat /tmp/audit.log` |
| Restart | `sudo docker compose restart` |
| Stop | `sudo docker compose down` |
| Update after code changes | rsync again, then `sudo docker compose up -d --build` |

### Putting HTTPS or a domain in front

To put a reverse proxy (nginx, Caddy…) on the same server:
1. In `compose.yaml`, change the port line to `"127.0.0.1:8081:8000"` so only the proxy can reach the app.
2. Uncomment `FORWARDED_ALLOW_IPS: "*"` in `compose.yaml` so the rate limit sees real visitor IPs instead of the proxy's.
3. Run `sudo docker compose up -d`.

Don't set `FORWARDED_ALLOW_IPS` while 8081 is open to the internet: visitors could fake their IP and dodge the rate limit. On AlmaLinux with SELinux, nginx also needs `sudo setsebool -P httpd_can_network_connect 1` to reach the app.

## Known limits

- The site has no login. Anyone who can reach it can use every page, including Reset, and everyone shares one log. The rate limit and row cap stop flooding, not mischief.
- Plain HTTP unless you put an HTTPS proxy in front.
- The log, lockouts and audit are all in memory and lost on restart.
- Run one container only. State is in memory, so extra replicas or workers would each have their own log.
- Rules use fixed thresholds and a fixed home city per person.
- Fake data and fake accounts only.
- Anyone with access to the server can read or edit `/tmp/audit.log`. The app only appends to it.
