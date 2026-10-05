"""Append-only record of every verified reading and office event.

Readings are keyed by (device, tank time), so a reading the board resends
after a lost receipt is stored once. The gateway reloads recent readings at
start-up, so a restart does not erase the context the leak and physics rules
need, or the audit trail.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from wardlink.record import Reading

SCHEMA = """
CREATE TABLE IF NOT EXISTS readings (
    device_id TEXT NOT NULL,
    tank_time INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    level_pct REAL NOT NULL,
    distance_m REAL NOT NULL,
    turbidity_ntu REAL NOT NULL,
    tds_mgl INTEGER NOT NULL,
    ph REAL NOT NULL,
    water_c REAL NOT NULL,
    air_c REAL NOT NULL,
    flags INTEGER NOT NULL,
    flag TEXT NOT NULL,
    plausible INTEGER NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (device_id, tank_time)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    text TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path | None = None):
        target = str(path) if path else ":memory:"
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(target, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            if path:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)
            self.db.commit()

    def add_reading(
        self,
        device_id: str,
        reading: Reading,
        seq: int,
        session_id: str,
        flag: str,
        plausible: bool,
        received_at: str,
    ) -> bool:
        """Store a reading. False means this tank time was already stored."""
        with self.lock:
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO readings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    device_id,
                    reading.tank_time,
                    seq,
                    session_id,
                    reading.level_pct,
                    reading.distance_m,
                    reading.turbidity_ntu,
                    reading.tds_mgl,
                    reading.ph,
                    reading.water_c,
                    reading.air_c,
                    reading.flags,
                    flag,
                    int(plausible),
                    received_at,
                ),
            )
            self.db.commit()
            return cursor.rowcount == 1

    def recent(self, device_id: str, limit: int) -> list[tuple[Reading, dict]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT tank_time, seq, session_id, level_pct, distance_m, turbidity_ntu, tds_mgl, ph, water_c, air_c,"
                " flags, flag, plausible FROM readings WHERE device_id = ? ORDER BY tank_time DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        out = []
        for row in reversed(rows):
            tank_time, seq, session_id, level, distance, turbidity, tds, ph, water, air, flags, flag, plausible = row
            reading = Reading(level, distance, turbidity, tds, ph, water, air, tank_time, flags)
            out.append((reading, {"seq": seq, "session_id": session_id, "flag": flag, "plausible": bool(plausible)}))
        return out

    def count(self, device_id: str) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM readings WHERE device_id = ?", (device_id,)).fetchone()[0]

    def tank_times(self, device_id: str) -> list[int]:
        with self.lock:
            rows = self.db.execute(
                "SELECT tank_time FROM readings WHERE device_id = ? ORDER BY tank_time", (device_id,)
            ).fetchall()
        return [row[0] for row in rows]

    def mark_suspect(self, device_id: str, session_id: str) -> int:
        """Flag every reading a session delivered, after a clone alarm puts that session in doubt."""
        with self.lock:
            cursor = self.db.execute(
                "UPDATE readings SET flag = 'SUSPECT' WHERE device_id = ? AND session_id = ?", (device_id, session_id)
            )
            self.db.commit()
            return cursor.rowcount

    def flags(self, device_id: str) -> dict[int, str]:
        with self.lock:
            rows = self.db.execute("SELECT tank_time, flag FROM readings WHERE device_id = ?", (device_id,)).fetchall()
        return {tank_time: flag for tank_time, flag in rows}

    def add_event(self, at: str, kind: str, text: str) -> None:
        with self.lock:
            self.db.execute("INSERT INTO events (at, kind, text) VALUES (?,?,?)", (at, kind, text))
            self.db.commit()

    def close(self) -> None:
        with self.lock:
            self.db.close()
