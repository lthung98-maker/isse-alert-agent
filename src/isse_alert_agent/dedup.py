"""Durable dedup: an alert the agent has filed a request for is never filed again.

By the alert's own identifier, held in a tiny SQLite database, for the same reason
ISSE's own idempotency is durable: a poll every thirty seconds must not file the same
alert twice, and that has to survive a restart. This is the agent's half of the two
independent guards described in the README; ISSE's ``was_handled`` is the other half,
keyed on the request this produced.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts_seen (
    alert_id       TEXT PRIMARY KEY,
    ts             REAL NOT NULL,
    ticket_id      TEXT,
    rule           TEXT,
    vm_name        TEXT
);
"""


class DedupStore:
    def __init__(self, db_path: str) -> None:
        self._path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def seen(self, alert_id: Optional[str]) -> bool:
        if not alert_id:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM alerts_seen WHERE alert_id = ? LIMIT 1", (alert_id,)
            ).fetchone()
        return row is not None

    def record(self, alert_id: Optional[str], ticket_id: Optional[str] = None,
               rule: Optional[str] = None, vm_name: Optional[str] = None) -> None:
        if not alert_id:
            return
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO alerts_seen (alert_id, ts, ticket_id, rule, vm_name) "
                "VALUES (?, ?, ?, ?, ?)",
                (alert_id, time.time(), ticket_id, rule, vm_name),
            )
            self._conn.commit()

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM alerts_seen").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
