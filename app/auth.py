"""Demo accounts, password hashing and login lockout for the sign-in demo page.

The site itself needs no login. Every attempt on the sign-in demo page is added to
the sign-in log so the flag rules can catch password guessing for real.
Passwords are never logged or printed.
"""

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

# Fake demo defaults, documented in the README. Override with env vars.
DEFAULT_OWNER_PASSWORD = "owner-demo-pass"
DEFAULT_EMPLOYEE_PASSWORD = "employee-demo-pass"

LOCKOUT_FAILS = 6                    # this many failed tries for one username...
LOCKOUT_WINDOW_SECONDS = 600         # ...within 10 minutes...
LOCKOUT_SECONDS = 600                # ...locks that username for 10 minutes

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}  # ~16 MB of RAM per hash

# At most this many password hashes run at once, so a burst of logins can't eat all RAM.
_HASH_SLOTS = threading.BoundedSemaphore(4)
MAX_TRACKED_USERNAMES = 10_000


def _hash(password: str, salt: bytes) -> bytes:
    with _HASH_SLOTS:
        return hashlib.scrypt(password.encode()[:1024], salt=salt, **_SCRYPT)


@dataclass
class Account:
    username: str
    salt: bytes
    digest: bytes


@dataclass
class LoginResult:
    status: str                  # "ok", "bad" or "locked"
    locked_now: bool = False     # this failure triggered the lockout


@dataclass
class AuthStore:
    accounts: dict[str, Account] = field(default_factory=dict)
    failures: dict[str, list[float]] = field(default_factory=dict)
    locked_until: dict[str, float] = field(default_factory=dict)
    clock: callable = time.monotonic
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _dummy_salt: bytes = field(default_factory=lambda: secrets.token_bytes(16))

    @classmethod
    def from_env(cls) -> "AuthStore":
        store = cls()
        store.add_account("owner1", os.environ.get("OWNER_PASSWORD", DEFAULT_OWNER_PASSWORD))
        store.add_account("employee1", os.environ.get("EMPLOYEE_PASSWORD", DEFAULT_EMPLOYEE_PASSWORD))
        return store

    def add_account(self, username: str, password: str) -> None:
        salt = secrets.token_bytes(16)
        self.accounts[username] = Account(username, salt, _hash(password, salt))

    def clear_lockouts(self) -> None:
        with self._lock:
            self.failures.clear()
            self.locked_until.clear()

    def login(self, username: str, password: str) -> LoginResult:
        now = self.clock()
        with self._lock:
            if self.locked_until.get(username, 0) > now:
                return LoginResult("locked")
            self.locked_until.pop(username, None)

        account = self.accounts.get(username)
        # Hash even for unknown usernames so both cases take about the same time.
        digest = _hash(password, account.salt if account else self._dummy_salt)
        ok = account is not None and hmac.compare_digest(digest, account.digest)

        with self._lock:
            if ok:
                self.failures.pop(username, None)
                return LoginResult("ok")
            recent = [t for t in self.failures.get(username, []) if now - t < LOCKOUT_WINDOW_SECONDS]
            recent.append(now)
            if len(recent) >= LOCKOUT_FAILS:
                self.locked_until[username] = now + LOCKOUT_SECONDS
                self.failures.pop(username, None)
                return LoginResult("bad", locked_now=True)
            self.failures[username] = recent
            self._prune(now)
            return LoginResult("bad")

    def _prune(self, now: float) -> None:
        """Forget usernames whose failures and lockouts have expired (caller holds the lock)."""
        if len(self.failures) + len(self.locked_until) <= MAX_TRACKED_USERNAMES:
            return
        for name in [n for n, ts in self.failures.items() if now - ts[-1] >= LOCKOUT_WINDOW_SECONDS]:
            del self.failures[name]
        for name in [n for n, until in self.locked_until.items() if until <= now]:
            del self.locked_until[name]
        while len(self.failures) > MAX_TRACKED_USERNAMES:  # still too many: drop the oldest
            self.failures.pop(next(iter(self.failures)))
