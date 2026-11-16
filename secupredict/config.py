"""Configuration, constants and business profiles.

Secrets (bot token, dashboard token, agent key) are read only from the
environment or from a local .env file. Nothing secret lives in the code.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import __version__

VERSION = __version__

SEV_ORDER: Dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEV_RU: Dict[str, str] = {
    "low": "Низкий риск",
    "medium": "Средний риск",
    "high": "Высокий риск",
    "critical": "Критический риск",
}
ORIGIN_RU: Dict[str, str] = {"real": "РЕАЛЬНО", "simulated": "СИМУЛЯЦИЯ"}
STATUS_RU: Dict[str, str] = {"open": "открыта", "ack": "принята", "ours": "это мы"}
LOCAL_BIND: Tuple[str, ...] = ("127.0.0.1", "localhost", "::1")

# Marker files written by tools/simulate_attack.py. The monitor never deletes
# anything in a folder that does not carry DEMO_DIR_SENTINEL.
DEMO_DIR_SENTINEL = ".secupredict_demo_dir"
SIM_MARKER = ".secupredict_sim.json"
DEMO_LOG_HEADER = "# secupredict demo auth log"


@dataclass
class Config:
    """Monitor settings. Every threshold can be changed here or via CLI flags."""

    profile: str = "clinic"
    bind_host: str = "127.0.0.1"
    port: int = 8080
    sample_interval: float = 2.0
    history_points: int = 150
    data_dir: Path = field(default_factory=Path.cwd)
    demo: bool = False

    # Threshold rules: value above the limit for sustain_sec in a row.
    cpu_alert: float = 90.0
    ram_alert: float = 92.0
    disk_alert: float = 90.0
    sustain_sec: float = 20.0
    rule_cooldown_sec: float = 600.0

    # Statistical anomaly detector (EWMA mean and deviation per host).
    stat_alpha: float = 0.05
    stat_sigma: float = 3.0
    stat_min_samples: int = 30
    stat_sustain_samples: int = 3
    stat_min_std: float = 1.5
    stat_min_delta: float = 8.0

    # Mass file change detector.
    watch_dir: Optional[Path] = None
    file_window_sec: float = 10.0
    file_change_threshold: int = 8
    file_ext_threshold: int = 5
    file_poll_sec: float = 1.0
    file_cooldown_sec: float = 30.0
    file_max_entries: int = 5000

    # Failed login detector.
    auth_log: Optional[Path] = None
    auth_window_sec: float = 120.0
    auth_fail_threshold: int = 10
    auth_cooldown_sec: float = 600.0

    # Scripted scenario (always labelled as simulation).
    scenario: bool = True
    scenario_loop_sec: float = 0.0

    # Response module.
    enforce: bool = False

    # Telegram.
    tg_token: str = ""
    tg_min_severity: str = "medium"
    tg_allowed_chats: Tuple[int, ...] = ()

    # Storage.
    metrics_retention_hours: float = 24.0

    # Web security.
    dashboard_token: str = ""
    agent_key: str = ""
    max_body_bytes: int = 64 * 1024
    max_agent_hosts: int = 20
    agent_stale_sec: float = 10.0

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        if self.watch_dir is None:
            self.watch_dir = self.data_dir / "demo_files"
        if self.auth_log is None:
            self.auth_log = self.data_dir / "demo_logs" / "auth.log"
        self.watch_dir = Path(self.watch_dir)
        self.auth_log = Path(self.auth_log)

    @property
    def is_local_bind(self) -> bool:
        return self.bind_host in LOCAL_BIND

    @property
    def dashboard_url(self) -> str:
        host = "127.0.0.1" if self.bind_host in ("0.0.0.0", "", "::") else self.bind_host
        return "http://%s:%d" % (host, self.port)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "secupredict.db"

    @property
    def response_mode(self) -> str:
        return "enforce" if self.enforce else "dry-run"


def load_dotenv(path: Path) -> int:
    """Load KEY=VALUE pairs from a .env file without overriding real environment.

    Returns the number of variables that were set.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return 0
    loaded = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and value and key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded


def parse_chat_ids(raw: str) -> Tuple[int, ...]:
    """Parse TG_CHAT_ID: one id or a comma-separated list."""
    ids = []
    for part in (raw or "").replace(";", ",").split(","):
        part = part.strip()
        if part.lstrip("-").isdigit():
            ids.append(int(part))
    return tuple(ids)


# Simulated fleets. Tuple: id, display name, baseline (cpu, ram, disk, net KB/s, io KB/s).
PROFILES: Dict[str, Dict[str, Any]] = {
    "clinic": {
        "company": "Клиника «Демо-Мед»",
        "system": "медицинскую систему",
        "data": "карты пациентов",
        "fleet": [
            ("reception-pc", "Ресепшн", (18, 52, 47, 40, 120)),
            ("doctor-pc-02", "Кабинет терапевта", (14, 48, 55, 25, 90)),
            ("lab-pc", "Лаборатория", (22, 58, 63, 30, 150)),
            ("mis-server", "Сервер МИС", (34, 67, 61, 420, 900)),
            ("backup-nas", "Хранилище копий", (7, 31, 78, 60, 300)),
        ],
        "roles": {"front": "reception-pc", "victim": "doctor-pc-02", "server": "mis-server",
                  "storage": "backup-nas", "misc": "lab-pc"},
        "front_user": "reception",
    },
    "online_shop": {
        "company": "Интернет-магазин «Демо-Шоп»",
        "system": "админ-панель магазина",
        "data": "заказы и данные покупателей",
        "fleet": [
            ("manager-pc", "Менеджер заказов", (20, 55, 44, 60, 110)),
            ("warehouse-pc", "Склад", (12, 46, 52, 20, 70)),
            ("web-server", "Сайт магазина", (38, 64, 57, 900, 700)),
            ("db-server", "База данных", (29, 71, 66, 300, 1400)),
            ("backup-nas", "Хранилище копий", (7, 31, 78, 60, 300)),
        ],
        "roles": {"front": "manager-pc", "victim": "warehouse-pc", "server": "web-server",
                  "storage": "backup-nas", "misc": "db-server"},
        "front_user": "manager",
    },
}
