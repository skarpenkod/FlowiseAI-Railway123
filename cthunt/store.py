"""SQLite storage: deduplicated hosts plus per-log progress so runs can be resumed."""
from __future__ import annotations

import sqlite3
import time

from .filters import apex

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    name       TEXT PRIMARY KEY,
    apex       TEXT NOT NULL,
    reason     TEXT NOT NULL,
    source     TEXT,
    first_seen INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS hosts_apex ON hosts(apex);
CREATE TABLE IF NOT EXISTS progress (
    log        TEXT PRIMARY KEY,
    next_index INTEGER NOT NULL,
    tree_size  INTEGER,
    updated    INTEGER
);
"""


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)

    def add_hosts(self, rows, source: str) -> int:
        """rows: iterable of (host, reason). Returns number of newly inserted hosts."""
        now = int(time.time())
        before = self.db.total_changes
        self.db.executemany(
            "INSERT OR IGNORE INTO hosts(name, apex, reason, source, first_seen) VALUES (?,?,?,?,?)",
            ((h, apex(h), r, source, now) for h, r in rows),
        )
        return self.db.total_changes - before

    def get_progress(self, log: str) -> int | None:
        row = self.db.execute("SELECT next_index FROM progress WHERE log=?", (log,)).fetchone()
        return row[0] if row else None

    def set_progress(self, log: str, next_index: int, tree_size: int | None = None) -> None:
        self.db.execute(
            "INSERT INTO progress(log, next_index, tree_size, updated) VALUES (?,?,?,?) "
            "ON CONFLICT(log) DO UPDATE SET next_index=excluded.next_index, "
            "tree_size=COALESCE(excluded.tree_size, progress.tree_size), updated=excluded.updated",
            (log, next_index, tree_size, int(time.time())),
        )

    def commit(self) -> None:
        self.db.commit()

    def count(self) -> tuple[int, int]:
        return self.db.execute("SELECT COUNT(*), COUNT(DISTINCT apex) FROM hosts").fetchone()

    def stats(self):
        return self.db.execute("SELECT reason, COUNT(*) FROM hosts GROUP BY reason ORDER BY 2 DESC").fetchall()

    def iter_hosts(self, apex_only: bool = False, reasons=None):
        where, args = "", []
        if reasons:
            where = "WHERE reason IN (%s)" % ",".join("?" * len(reasons))
            args = list(reasons)
        col = "DISTINCT apex" if apex_only else "name"
        yield from (r[0] for r in self.db.execute(f"SELECT {col} FROM hosts {where} ORDER BY 1", args))
