"""Append-only audit log: kept in memory and written line by line to a file.

There is deliberately no way to edit or delete entries. Memory keeps the newest
MAX_MEMORY_ENTRIES; the file rotates once it passes MAX_FILE_BYTES.
Each file line is one JSON object, so odd characters in a username can't fake extra lines.
"""

import json
import os
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

AUDIT_FILE = Path("/tmp/audit.log")
MAX_MEMORY_ENTRIES = 5_000          # the /audit page shows the newest 5,000
MAX_FILE_BYTES = 5 * 1024 * 1024    # rotate audit.log -> audit.log.1 at 5 MB (one old file kept)


@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    username: str
    route: str
    action: str
    result: str


class AuditLog:
    def __init__(self, path: Path | None = None):
        self._entries: deque[AuditEntry] = deque(maxlen=MAX_MEMORY_ENTRIES)
        self._path = path or AUDIT_FILE
        self._lock = threading.Lock()

    def record(self, username: str | None, route: str, action: str, result: str) -> None:
        entry = AuditEntry(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            username=(username or "anonymous")[:64],
            route=route[:200],
            action=action,
            result=result,
        )
        with self._lock:
            self._entries.append(entry)
            try:
                if self._path.exists() and self._path.stat().st_size > MAX_FILE_BYTES:
                    os.replace(self._path, self._path.with_name(self._path.name + ".1"))
                with open(self._path, "a") as f:
                    f.write(json.dumps(asdict(entry)) + "\n")
            except OSError:
                pass  # the in-memory copy is still kept

    def newest_first(self) -> list[AuditEntry]:
        with self._lock:
            return list(reversed(self._entries))

    def __len__(self) -> int:
        return len(self._entries)
