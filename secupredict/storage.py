"""SQLite storage: alerts, metrics (with retention) and response actions."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    severity TEXT NOT NULL,
    host_id TEXT NOT NULL,
    host_name TEXT NOT NULL,
    title TEXT NOT NULL,
    what TEXT NOT NULL,
    did TEXT NOT NULL,
    steps TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    detector TEXT NOT NULL,
    origin TEXT NOT NULL,
    staged INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',
    status_by TEXT NOT NULL DEFAULT '',
    status_ts REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS metrics (
    ts REAL NOT NULL,
    host_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    cpu REAL, ram REAL, disk REAL, net_in REAL, net_out REAL, io REAL
);
CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(ts);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    alert_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    result TEXT NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions(ts);
"""

ALERT_COLUMNS = ("id", "ts", "severity", "host_id", "host_name", "title", "what", "did", "steps",
                 "kind", "source", "detector", "origin", "staged", "status", "status_by", "status_ts")


class Storage:
    """Thread-safe wrapper around one SQLite connection."""

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            if self.path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(SCHEMA)
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # Alerts -----------------------------------------------------------------
    def insert_alert(self, alert: Dict[str, Any]) -> None:
        row = dict(alert)
        row["steps"] = json.dumps(row.get("steps", []), ensure_ascii=False)
        row["staged"] = 1 if row.get("staged") else 0
        values = [row.get(col, "") for col in ALERT_COLUMNS]
        sql = "INSERT OR REPLACE INTO alerts (%s) VALUES (%s)" % (
            ", ".join(ALERT_COLUMNS), ", ".join("?" for _ in ALERT_COLUMNS))
        with self._lock:
            self._db.execute(sql, values)
            self._db.commit()

    def update_alert_status(self, alert_id: str, status: str, by: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE alerts SET status = ?, status_by = ?, status_ts = ? WHERE id = ?",
                (status, by, time.time(), alert_id))
            self._db.commit()
            return cur.rowcount > 0

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        try:
            item["steps"] = json.loads(item["steps"])
        except ValueError:
            item["steps"] = []
        item["staged"] = bool(item["staged"])
        return item

    def alerts_between(self, since: float, until: float) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM alerts WHERE ts >= ? AND ts <= ? ORDER BY ts", (since, until)).fetchall()
        return [self._alert_row(r) for r in rows]

    def export_alerts_jsonl(self, path: Union[str, Path]) -> int:
        """Write every stored alert to a jsonl file (0.2.0 compatible format plus new fields)."""
        items = self.alerts_between(0, time.time() + 1)
        with open(str(path), "w", encoding="utf-8") as fh:
            for item in items:
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        return len(items)

    # Metrics ----------------------------------------------------------------
    def insert_metrics(self, rows: Iterable[Sequence[Any]]) -> None:
        """rows: (ts, host_id, origin, cpu, ram, disk, net_in, net_out, io)."""
        data = list(rows)
        if not data:
            return
        with self._lock:
            self._db.executemany("INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
            self._db.commit()

    def prune_metrics(self, older_than: float) -> int:
        with self._lock:
            cur = self._db.execute("DELETE FROM metrics WHERE ts < ?", (older_than,))
            self._db.commit()
            return cur.rowcount

    def metrics_count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM metrics").fetchone()[0])

    # Actions ----------------------------------------------------------------
    def insert_action(self, action: Dict[str, Any]) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO actions (ts, alert_id, action, target, mode, result, reason, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (action["ts"], action.get("alert_id", ""), action["action"], action["target"],
                 action["mode"], action["result"], action["reason"], action["detail"]))
            self._db.commit()
            return int(cur.lastrowid or 0)

    def actions_between(self, since: float, until: float) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM actions WHERE ts >= ? AND ts <= ? ORDER BY ts", (since, until)).fetchall()
        return [dict(r) for r in rows]

    def recent_actions(self, limit: int = 20, since: Optional[float] = None) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM actions WHERE ts >= ? ORDER BY id DESC LIMIT ?", (since or 0, limit)).fetchall()
        return [dict(r) for r in rows]
