"""Alert model and alert manager."""
from __future__ import annotations

import html
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import ORIGIN_RU, SEV_RU
from .storage import Storage

log = logging.getLogger("secupredict.alerts")

VALID_STATUS = ("open", "ack", "ours")


def new_alert_id() -> str:
    return uuid.uuid4().hex[:8]


@dataclass
class Alert:
    """One alert: what happened, what was really done, what the owner should do.

    origin: "real" when a detector fired on real data of a real machine or log,
            "simulated" for the demo fleet and the scripted scenario.
    staged: True when the detection is real but the cause is a training attack
            started with tools/simulate_attack.py against decoy files.
    """

    severity: str
    host_id: str
    host_name: str
    title: str
    what: str
    did: str
    steps: List[str]
    kind: str = "generic"
    source: str = "rule"  # kept for 0.2.0 compatibility: rule | scenario
    detector: str = "threshold"  # threshold | stat | files | authlog | scenario
    origin: str = "real"
    staged: bool = False
    id: str = field(default_factory=new_alert_id)
    ts: float = field(default_factory=time.time)
    status: str = "open"
    status_by: str = ""
    status_ts: float = 0.0

    @property
    def origin_label(self) -> str:
        label = ORIGIN_RU.get(self.origin, self.origin)
        return label + " (учебная атака)" if self.staged else label

    def to_telegram(self, dashboard_url: str) -> str:
        """Alert text for Telegram (HTML markup, no emoji)."""
        e = html.escape
        lines = [
            "<b>[%s]</b> %s" % (e(SEV_RU[self.severity].upper()), e(self.host_name)),
            "<b>%s</b>" % e(self.title),
            "Источник данных: <b>%s</b>" % e(self.origin_label),
            "",
            "<b>Что случилось:</b> %s" % e(self.what),
            "<b>Что сделано:</b> %s" % e(self.did),
            "<b>Что сделать вам:</b>",
        ]
        lines += ["%d. %s" % (i, e(step)) for i, step in enumerate(self.steps, 1)]
        lines += ["", "%s, дашборд: %s" % (datetime.fromtimestamp(self.ts).strftime("%H:%M:%S"), e(dashboard_url))]
        return "\n".join(lines)


class AlertManager:
    """Keeps session alerts in memory, persists them to SQLite and notifies listeners."""

    def __init__(self, storage: Storage, host_names: Callable[[str], str],
                 jsonl_path: Optional[Path] = None, keep: int = 500) -> None:
        self.storage = storage
        self._host_name = host_names
        self._alerts: List[Alert] = []
        self._lock = threading.Lock()
        self._keep = keep
        self.jsonl_path = jsonl_path
        self.listeners: List[Callable[[Alert], None]] = []
        self.status_listeners: List[Callable[[Alert], None]] = []

    def raise_alert(self, severity: str, host_id: str, title: str, what: str, did: str,
                    steps: List[str], kind: str = "generic", detector: str = "threshold",
                    origin: str = "real", staged: bool = False,
                    alert_id: Optional[str] = None) -> Alert:
        alert = Alert(severity=severity, host_id=host_id, host_name=self._host_name(host_id), title=title,
                      what=what, did=did, steps=list(steps), kind=kind,
                      source="scenario" if origin == "simulated" else "rule",
                      detector=detector, origin=origin, staged=staged)
        if alert_id:
            alert.id = alert_id
        with self._lock:
            self._alerts.append(alert)
            self._alerts = self._alerts[-self._keep:]
        record = asdict(alert)
        try:
            self.storage.insert_alert(record)
        except Exception as exc:  # noqa: BLE001 - storage failure must not stop detection
            log.error("Cannot store alert %s: %s", alert.id, exc)
        if self.jsonl_path is not None:
            try:
                with open(str(self.jsonl_path), "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError as exc:
                log.error("Cannot append to %s: %s", self.jsonl_path, exc)
        log.warning("Alert [%s/%s] %s: %s", severity, origin, alert.host_name, title)
        for listener in self.listeners:
            try:
                listener(alert)
            except Exception as exc:  # noqa: BLE001
                log.error("Alert listener failed: %s", exc)
        return alert

    def set_status(self, alert_id: str, status: str, by: str) -> bool:
        """Change alert status ("ack" or "ours"). Returns False for unknown ids."""
        if status not in VALID_STATUS:
            return False
        found: Optional[Alert] = None
        with self._lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    alert.status, alert.status_by, alert.status_ts = status, by, time.time()
                    found = alert
                    break
        stored = self.storage.update_alert_status(alert_id, status, by)
        if found is not None:
            for listener in self.status_listeners:
                try:
                    listener(found)
                except Exception as exc:  # noqa: BLE001
                    log.error("Status listener failed: %s", exc)
        return bool(found) or stored

    def get(self, alert_id: str) -> Optional[Alert]:
        with self._lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    return alert
        return None

    def recent(self, host_id: str, kind: str, within: float, now: Optional[float] = None) -> bool:
        """True if the same kind of alert was raised for the host recently (deduplication)."""
        current = time.time() if now is None else now
        with self._lock:
            return any(a.host_id == host_id and a.kind == kind and current - a.ts < within
                       for a in self._alerts)

    def open_for(self, host_id: str) -> List[Alert]:
        with self._lock:
            return [a for a in self._alerts if a.host_id == host_id and a.status == "open"]

    def snapshot(self, limit: int = 60) -> List[Dict[str, Any]]:
        with self._lock:
            return [asdict(a) for a in reversed(self._alerts[-limit:])]

    def clear_session(self) -> None:
        """Forget in-memory alerts (the database keeps them for the report)."""
        with self._lock:
            self._alerts = []
