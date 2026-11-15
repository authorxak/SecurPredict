#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuPredict Monitor — метрики хостов, тревоги, локальный дашборд и Telegram-бот.

Что делает:
  * Собирает реальные метрики этого компьютера (CPU, память, диск, сеть, I/O)
    и метрики демо-парка устройств клиники или магазина.
  * Показывает всё на дашборде: http://127.0.0.1:8080 (обновление каждые 2 с).
  * Создаёт тревоги:
      - по реальным порогам (перегрузка CPU, память, место на диске);
      - по демо-сценарию, который запускается сам: через 10 с — средняя,
        через 25 с — критическая, дальше — высокая, средняя и низкая.
  * Telegram-бот присылает ТОЛЬКО тревоги (от «средней» и выше), без метрик.
    Чтобы подписаться, напишите боту /start. Команды: /status, /stop.

Запуск:
  python secupredict_monitor.py                      # клиника, порт 8080
  python secupredict_monitor.py --profile online_shop
  python secupredict_monitor.py --loop               # повторять сценарий каждые 5 минут
  python secupredict_monitor.py --host 0.0.0.0       # открыть дашборд для локальной сети

Токен бота берётся из TG_BOT_TOKEN, иначе из DEFAULT_TG_TOKEN ниже.
Только стандартная библиотека; psutil используется, если установлен (точнее метрики на Windows).
"""
from __future__ import annotations

import argparse
import html
import json
import logging
import os
import platform
import queue
import random
import re
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover
    psutil = None

VERSION = "0.2.0"
log = logging.getLogger("secupredict")

# Токен из переписки. Надёжнее хранить его в переменной окружения TG_BOT_TOKEN.
DEFAULT_TG_TOKEN = "5530792167:AAF9PCSUtX5qPP-KEnVbLAwnT0-Bb8fnp78"

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEV_RU = {"low": "Низкий риск", "medium": "Средний риск", "high": "Высокий риск", "critical": "Критический риск"}
SEV_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


# ═════════════════════════════════════════════════════════════════════════════
# Конфигурация и профили
# ═════════════════════════════════════════════════════════════════════════════
@dataclass
class Config:
    """Настройки монитора. Пороги объяснены в комментариях."""

    profile: str = "clinic"
    bind_host: str = "127.0.0.1"  # 0.0.0.0 — открыть дашборд для всей локальной сети
    port: int = 8080
    sample_interval: float = 2.0  # как часто снимаем метрики, сек
    history_points: int = 150  # 150 × 2 с = 5 минут истории на графиках
    cpu_alert: float = 90.0  # CPU выше этого ...
    ram_alert: float = 92.0  # память выше этого ...
    disk_alert: float = 90.0  # заполненность диска выше этого ...
    sustain_sec: float = 20.0  # ... дольше 20 с подряд = тревога (короткие всплески не считаем)
    rule_cooldown_sec: float = 600.0  # одну и ту же тревогу по порогу повторяем не чаще раза в 10 мин
    tg_token: str = ""
    tg_min_severity: str = "medium"  # в Telegram уходят тревоги от этого уровня и выше
    scenario: bool = True
    scenario_loop_sec: float = 0.0  # 0 — сценарий один раз; >0 — повторять с этим периодом
    data_dir: Path = field(default_factory=Path.cwd)

    @property
    def dashboard_url(self) -> str:
        host = "127.0.0.1" if self.bind_host in ("0.0.0.0", "") else self.bind_host
        return f"http://{host}:{self.port}"


PROFILES: Dict[str, Dict[str, Any]] = {
    "clinic": {
        "company": "Клиника «Демо-Мед»",
        "system": "медицинскую систему",
        "data": "карты пациентов",
        "fleet": [
            # id, название, база: cpu, ram, disk, net(КБ/с), io(КБ/с)
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


# ═════════════════════════════════════════════════════════════════════════════
# Метрики
# ═════════════════════════════════════════════════════════════════════════════
class LocalMetrics:
    """Реальные метрики этого компьютера: psutil, а без него — /proc (Linux)."""

    _DISK_RE = re.compile(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+)$")

    def __init__(self) -> None:
        self._cpu_prev: Optional[Tuple[int, int]] = None
        self._prev: Dict[str, Tuple[float, float]] = {}
        if os.name == "nt":
            self.disk_root = os.environ.get("SystemDrive", "C:") + "\\"
        else:
            self.disk_root = "/"
        if psutil:
            psutil.cpu_percent(None)

    def _cpu(self) -> float:
        if psutil:
            return float(psutil.cpu_percent(None))
        try:
            with open("/proc/stat") as fh:
                vals = list(map(int, fh.readline().split()[1:]))
        except OSError:
            return 0.0
        idle, total = vals[3] + (vals[4] if len(vals) > 4 else 0), sum(vals)
        prev, self._cpu_prev = self._cpu_prev, (idle, total)
        if not prev or total <= prev[1]:
            return 0.0
        return 100.0 * (1 - (idle - prev[0]) / (total - prev[1]))

    def _ram(self) -> float:
        if psutil:
            return float(psutil.virtual_memory().percent)
        try:
            info = {}
            with open("/proc/meminfo") as fh:
                for line in fh:
                    k, v = line.split(":", 1)
                    info[k] = int(v.split()[0])
            return 100.0 * (1 - info["MemAvailable"] / info["MemTotal"])
        except (OSError, KeyError, ValueError):
            return 0.0

    def _disk(self) -> float:
        try:
            u = shutil.disk_usage(self.disk_root)
            return 100.0 * u.used / u.total
        except OSError:
            return 0.0

    def _counters(self) -> Dict[str, float]:
        """Накопительные счётчики байтов: сеть (вход/выход) и диск (чтение+запись)."""
        out: Dict[str, float] = {}
        if psutil:
            n = psutil.net_io_counters()
            out["net_in"], out["net_out"] = n.bytes_recv, n.bytes_sent
            try:
                d = psutil.disk_io_counters()
                if d:
                    out["io"] = d.read_bytes + d.write_bytes
            except Exception:
                pass
            return out
        try:
            rx = tx = 0
            with open("/proc/net/dev") as fh:
                for line in fh.readlines()[2:]:
                    name, data = line.split(":", 1)
                    if name.strip() == "lo":
                        continue
                    cols = data.split()
                    rx, tx = rx + int(cols[0]), tx + int(cols[8])
            out["net_in"], out["net_out"] = rx, tx
        except OSError:
            pass
        try:
            sectors = 0
            with open("/proc/diskstats") as fh:
                for line in fh:
                    cols = line.split()
                    if len(cols) > 9 and self._DISK_RE.match(cols[2]):
                        sectors += int(cols[5]) + int(cols[9])
            out["io"] = sectors * 512
        except OSError:
            pass
        return out

    def sample(self) -> Dict[str, float]:
        """Снимок: проценты и скорости в КБ/с."""
        now = time.time()
        result = {"cpu": self._cpu(), "ram": self._ram(), "disk": self._disk(),
                  "net_in": 0.0, "net_out": 0.0, "io": 0.0}
        for key, value in self._counters().items():
            prev = self._prev.get(key)
            self._prev[key] = (now, value)
            if prev and now > prev[0] and value >= prev[1]:
                result[key] = (value - prev[1]) / (now - prev[0]) / 1024
        return {k: round(v, 1) for k, v in result.items()}


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


class Host:
    """Устройство на дашборде: реальное (этот ПК) или демо."""

    METRICS = ("cpu", "ram", "disk", "net_in", "net_out", "io")

    def __init__(self, host_id: str, name: str, role: str, history: int,
                 base: Optional[Tuple[float, ...]] = None, real: bool = False) -> None:
        self.id, self.name, self.role, self.real = host_id, name, role, real
        self.base = dict(zip(("cpu", "ram", "disk", "net", "io"), base or (0, 0, 0, 0, 0)))
        self.isolated = False
        self._overrides: Dict[str, float] = {}
        self._override_until = 0.0
        self.latest: Dict[str, float] = {}
        self.history: Dict[str, Deque[float]] = {m: deque(maxlen=history) for m in self.METRICS}
        if not real:
            b = self.base
            self.latest = {"cpu": b["cpu"], "ram": b["ram"], "disk": b["disk"],
                           "net_in": b["net"], "net_out": b["net"] * 0.6, "io": b["io"]}

    def set_override(self, seconds: float, **targets: float) -> None:
        """Временно сдвигает «норму» демо-хоста (для сценария)."""
        self._overrides.update(targets)
        self._override_until = time.time() + seconds

    def reset(self) -> None:
        self.isolated = False
        self._overrides.clear()

    def simulate(self) -> Dict[str, float]:
        """Случайное блуждание вокруг нормы демо-хоста."""
        if self._overrides and time.time() > self._override_until:
            self._overrides.clear()
        b, cur, o = self.base, self.latest, self._overrides
        targets = {
            "cpu": o.get("cpu", b["cpu"]), "ram": o.get("ram", b["ram"]), "disk": o.get("disk", b["disk"]),
            "net_in": o.get("net_in", b["net"]), "net_out": o.get("net_out", b["net"] * 0.6),
            "io": o.get("io", b["io"]),
        }
        noise = {"cpu": 4.0, "ram": 0.8, "disk": 0.03, "net_in": b["net"] * 0.15 + 3,
                 "net_out": b["net"] * 0.1 + 2, "io": b["io"] * 0.2 + 5}
        new = {}
        for k, t in targets.items():
            speed = 0.5 if k in o else 0.3
            v = cur.get(k, t) + (t - cur.get(k, t)) * speed + random.gauss(0, noise[k])
            new[k] = _clamp(v, 0, 100 if k in ("cpu", "ram", "disk") else 10**7)
        if self.isolated:
            new["net_in"] = new["net_out"] = 0.0
        return {k: round(v, 1) for k, v in new.items()}

    def push(self, sample: Dict[str, float]) -> None:
        self.latest = sample
        for m in self.METRICS:
            self.history[m].append(sample.get(m, 0.0))


# ═════════════════════════════════════════════════════════════════════════════
# Тревоги
# ═════════════════════════════════════════════════════════════════════════════
@dataclass
class Alert:
    """Тревога: что случилось, что сделано, что делать владельцу."""

    severity: str
    host_id: str
    host_name: str
    title: str
    what: str
    did: str
    steps: List[str]
    kind: str = "generic"
    source: str = "rule"  # rule — реальные пороги; scenario — демо-сценарий
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    ts: float = field(default_factory=time.time)
    status: str = "open"  # open | ack

    def to_telegram(self, dashboard_url: str) -> str:
        """Текст для Telegram (HTML-разметка)."""
        e = html.escape
        lines = [
            f"{SEV_EMOJI[self.severity]} <b>{SEV_RU[self.severity]}</b> · {e(self.host_name)}",
            f"<b>{e(self.title)}</b>",
            "",
            f"<b>Что случилось:</b> {e(self.what)}",
            f"<b>Что мы сделали:</b> {e(self.did)}",
            "<b>Что сделать вам:</b>",
        ]
        lines += [f"{i}. {e(s)}" for i, s in enumerate(self.steps, 1)]
        lines += ["", f"🕒 {datetime.fromtimestamp(self.ts):%H:%M:%S} · дашборд: {e(dashboard_url)}"]
        if self.source == "scenario":
            lines.append("🧪 демо-сценарий")
        return "\n".join(lines)


class AlertManager:
    """Хранит тревоги, пишет их в alerts.jsonl и передаёт в Telegram."""

    def __init__(self, cfg: Config, hosts: Dict[str, Host]) -> None:
        self.cfg = cfg
        self.hosts = hosts
        self._alerts: List[Alert] = []
        self._lock = threading.Lock()
        self.listeners: List[Callable[[Alert], None]] = []
        self.path = cfg.data_dir / "alerts.jsonl"

    def raise_alert(self, severity: str, host_id: str, title: str, what: str, did: str,
                    steps: List[str], kind: str = "generic", source: str = "rule") -> Alert:
        host = self.hosts.get(host_id)
        alert = Alert(severity, host_id, host.name if host else host_id, title, what, did, steps, kind, source)
        with self._lock:
            self._alerts.append(alert)
            self._alerts = self._alerts[-500:]
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(alert), ensure_ascii=False) + "\n")
        except OSError as exc:
            log.error("Не удалось записать тревогу: %s", exc)
        log.warning("Тревога [%s] %s: %s", severity, alert.host_name, title)
        for listener in self.listeners:
            try:
                listener(alert)
            except Exception as exc:
                log.error("Ошибка обработчика тревоги: %s", exc)
        return alert

    def ack(self, alert_id: str) -> bool:
        with self._lock:
            for a in self._alerts:
                if a.id == alert_id:
                    a.status = "ack"
                    return True
        return False

    def recent(self, host_id: str, kind: str, within: float) -> bool:
        """Была ли такая же тревога недавно (защита от дублей)."""
        now = time.time()
        with self._lock:
            return any(a.host_id == host_id and a.kind == kind and now - a.ts < within for a in self._alerts)

    def open_for(self, host_id: str) -> List[Alert]:
        with self._lock:
            return [a for a in self._alerts if a.host_id == host_id and a.status == "open"]

    def snapshot(self, limit: int = 60) -> List[Dict[str, Any]]:
        with self._lock:
            return [asdict(a) for a in reversed(self._alerts[-limit:])]


class ThresholdRules:
    """Тревоги по реальным порогам: перегрузка CPU, память, место на диске."""

    def __init__(self, cfg: Config, alerts: AlertManager) -> None:
        self.cfg = cfg
        self.alerts = alerts
        self._since: Dict[Tuple[str, str], float] = {}

    def check(self, host: Host) -> None:
        now = time.time()
        rules = [
            ("cpu", self.cfg.cpu_alert, "Компьютер перегружен",
             "процессор загружен на {v:.0f}% уже больше {s:.0f} сек.",
             ["Закройте программы, которые сейчас не нужны.",
              "Если нагрузка держится без видимой причины, напишите нам: так проявляются майнеры и вирусы."]),
            ("ram", self.cfg.ram_alert, "Не хватает оперативной памяти",
             "память занята на {v:.0f}% уже больше {s:.0f} сек. Программы могут зависать.",
             ["Перезапустите браузер и тяжёлые программы.",
              "Если повторяется каждый день, компьютеру нужна дополнительная память."]),
            ("disk", self.cfg.disk_alert, "Заканчивается место на диске",
             "диск заполнен на {v:.0f}%. Когда место кончится, перестанут сохраняться файлы и копии.",
             ["Удалите старые загрузки и ненужные файлы.",
              "Проверьте, что резервные копии продолжают создаваться."]),
        ]
        for metric, limit, title, what, steps in rules:
            key = (host.id, metric)
            value = host.latest.get(metric, 0.0)
            if value < limit:
                self._since.pop(key, None)
                continue
            start = self._since.setdefault(key, now)
            if now - start < self.cfg.sustain_sec or self.alerts.recent(host.id, metric, self.cfg.rule_cooldown_sec):
                continue
            self.alerts.raise_alert(
                "medium", host.id, title, what.format(v=value, s=now - start),
                "ничего не меняли — только сообщаем и следим дальше.", steps, kind=metric,
                source="rule" if host.real else "scenario")


# ═════════════════════════════════════════════════════════════════════════════
# Демо-сценарий: тревоги приходят сами по таймеру
# ═════════════════════════════════════════════════════════════════════════════
class ScenarioRunner:
    """Через 10 с — средняя, через 25 с — критическая, затем высокая, средняя и низкая."""

    def __init__(self, cfg: Config, hosts: Dict[str, Host], alerts: AlertManager) -> None:
        self.cfg = cfg
        self.hosts = hosts
        self.alerts = alerts
        self.p = PROFILES[cfg.profile]
        self.r = self.p["roles"]
        self.started = time.time()
        self.next_label = ""
        self.stop_event = threading.Event()

    def _h(self, role: str) -> Host:
        return self.hosts[self.r[role]]

    def _suspicious_login(self) -> None:
        user = self.p["front_user"]
        self.alerts.raise_alert(
            "medium", self.r["front"], "Вход с незнакомого адреса",
            f"учётная запись «{user}» вошла в {self.p['system']} с адреса 92.46.118.4 в "
            f"{datetime.now():%H:%M}. Раньше с этого адреса никто не входил.",
            "ничего не блокировали, чтобы не мешать работе. Вход записан в журнал.",
            [f"Спросите сотрудника «{user}», входил ли он сейчас сам.",
             "Если нет, смените пароль и ответьте нам «это не мы»."],
            kind="login", source="scenario")

    def _ransomware_signs(self) -> None:
        self._h("victim").set_override(30, cpu=94, io=52000, net_out=900)

    def _ransomware(self) -> None:
        host = self._h("victim")
        host.isolated = True
        host.set_override(600, cpu=9, io=60)
        self.alerts.raise_alert(
            "critical", host.id, "Похоже на вирус-шифровальщик",
            f"на компьютере «{host.name}» программа svc_update.exe за 4 секунды переписала 14 файлов "
            f"и сменила им расширение на .locked. Под угрозой {self.p['data']}.",
            "изолировали компьютер от сети и остановили программу. Остальные файлы и копии целы.",
            ["Не выключайте компьютер и не платите выкуп, даже если появится требование.",
             "Попросите сотрудника перейти за другой компьютер.",
             "Напишите нам: проверим остальные устройства и восстановим 14 файлов из копии."],
            kind="ransomware", source="scenario")

    def _bruteforce_signs(self) -> None:
        self._h("server").set_override(20, cpu=72, net_in=2600)

    def _bruteforce(self) -> None:
        self.alerts.raise_alert(
            "high", self.r["server"], "Кто-то подбирает пароль",
            f"с адреса 185.220.101.7 за 2 минуты было 38 неудачных попыток войти в "
            f"{self.p['system']} под именем «admin».",
            "заблокировали адрес 185.220.101.7 на 24 часа. Пароль не подобран.",
            ["Убедитесь, что у «admin» длинный пароль (от 12 символов), который нигде не повторяется.",
             "Включите вход с подтверждением по SMS или в приложении."],
            kind="bruteforce", source="scenario")

    def _storage_fill(self) -> None:
        self._h("storage").set_override(900, disk=94)

    def _storage(self) -> None:
        self.alerts.raise_alert(
            "medium", self.r["storage"], "Почти закончилось место для резервных копий",
            "хранилище копий заполнено на 94%. Примерно через 3 дня новые копии перестанут сохраняться.",
            "ничего не удаляли, копии пока создаются.",
            ["Удалите копии старше 90 дней или подключите дополнительный диск.",
             "Проверьте, что сегодняшняя копия создана."],
            kind="disk", source="scenario")

    def _updates(self) -> None:
        self.alerts.raise_alert(
            "low", self.r["misc"], "Давно не ставились обновления",
            "на этом компьютере обновления системы не устанавливались 41 день.",
            "только напоминаем.",
            ["Установите обновления в конце рабочего дня и перезагрузите компьютер."],
            kind="updates", source="scenario")

    def steps(self) -> List[Tuple[float, str, Callable[[], None]]]:
        return [
            (10, "средняя тревога", self._suspicious_login),
            (21, "признаки атаки", self._ransomware_signs),
            (25, "критическая тревога", self._ransomware),
            (40, "признаки атаки", self._bruteforce_signs),
            (45, "высокая тревога", self._bruteforce),
            (65, "рост заполнения", self._storage_fill),
            (70, "средняя тревога", self._storage),
            (95, "низкая тревога", self._updates),
        ]

    def run(self) -> None:
        while not self.stop_event.is_set():
            self.started = time.time()
            for at, label, action in self.steps():
                self.next_label = f"{label} через {{left}} с"
                self._next_at = self.started + at
                if self.stop_event.wait(max(0.0, self.started + at - time.time())):
                    return
                try:
                    action()
                except Exception as exc:
                    log.error("Ошибка шага сценария: %s", exc)
            self.next_label = ""
            if self.cfg.scenario_loop_sec <= 0:
                return
            if self.stop_event.wait(max(0.0, self.started + self.cfg.scenario_loop_sec - time.time())):
                return
            for host in self.hosts.values():
                host.reset()

    def status(self) -> Dict[str, Any]:
        if not self.next_label:
            return {"elapsed": int(time.time() - self.started), "next": ""}
        left = max(0, int(getattr(self, "_next_at", time.time()) - time.time()))
        return {"elapsed": int(time.time() - self.started), "next": self.next_label.format(left=left)}


# ═════════════════════════════════════════════════════════════════════════════
# Telegram-бот: только тревоги
# ═════════════════════════════════════════════════════════════════════════════
class TelegramBot:
    """Отправляет тревоги подписчикам. Подписка — командой /start в чате с ботом."""

    def __init__(self, cfg: Config, status_text: Callable[[], str]) -> None:
        self.cfg = cfg
        self.token = cfg.tg_token
        self.status_text = status_text
        self.subs_path = cfg.data_dir / "tg_subscribers.json"
        self.subscribers: set = set()
        self.username = ""
        self.enabled = bool(self.token)
        self.online = False
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._pending: Deque[str] = deque(maxlen=10)  # тревоги до первой подписки
        self._stop = threading.Event()
        self._load_subs()
        env_chat = os.environ.get("TG_CHAT_ID")
        if env_chat:
            self.subscribers.add(int(env_chat))

    def _load_subs(self) -> None:
        try:
            self.subscribers = set(json.loads(self.subs_path.read_text("utf-8")))
        except (OSError, ValueError):
            self.subscribers = set()

    def _save_subs(self) -> None:
        try:
            self.subs_path.write_text(json.dumps(sorted(self.subscribers)), "utf-8")
        except OSError as exc:
            log.error("Не удалось сохранить подписчиков: %s", exc)

    def _call(self, method: str, payload: Dict[str, Any], timeout: float = 15) -> Optional[Any]:
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self.online = True
            return data.get("result") if data.get("ok") else None
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                log.error("Telegram: неверный токен бота. Бот отключён.")
                self.enabled = False
            elif exc.code == 409:
                log.error("Telegram: у бота настроен webhook или запущена вторая копия. "
                          "Остановите её или удалите webhook.")
            else:
                log.warning("Telegram %s: HTTP %s", method, exc.code)
        except Exception as exc:
            if self.online:
                log.warning("Telegram недоступен: %s", exc)
            self.online = False
        return None

    def start(self) -> None:
        if not self.enabled:
            log.warning("Токен Telegram не задан — тревоги только на дашборде.")
            return
        me = self._call("getMe", {})
        if me:
            self.username = me.get("username", "")
        threading.Thread(target=self._poll_loop, name="tg-poll", daemon=True).start()
        threading.Thread(target=self._send_loop, name="tg-send", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def notify(self, alert: Alert) -> None:
        """Ставит тревогу в очередь, если её уровень не ниже порога для Telegram."""
        if not self.enabled or SEV_ORDER[alert.severity] < SEV_ORDER[self.cfg.tg_min_severity]:
            return
        self._queue.put(alert.to_telegram(self.cfg.dashboard_url))

    def _send(self, chat_id: int, text: str) -> None:
        self._call("sendMessage", {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                                   "disable_web_page_preview": True})
        time.sleep(0.05)

    def _send_loop(self) -> None:
        while not self._stop.is_set():
            try:
                text = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            if not self.subscribers:
                self._pending.append(text)
                log.warning("Нет подписчиков в Telegram: напишите боту @%s /start", self.username or "?")
                continue
            for chat_id in list(self.subscribers):
                self._send(chat_id, text)

    def _poll_loop(self) -> None:
        offset = 0
        backoff = 3.0
        while not self._stop.is_set() and self.enabled:
            updates = self._call("getUpdates", {"offset": offset, "timeout": 25}, timeout=35)
            if updates is None:
                self._stop.wait(backoff)
                backoff = min(60.0, backoff * 2)
                continue
            backoff = 3.0
            for upd in updates:
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                chat_id = (msg.get("chat") or {}).get("id")
                text = (msg.get("text") or "").strip().lower()
                if chat_id is None:
                    continue
                if text.startswith("/start"):
                    self.subscribers.add(chat_id)
                    self._save_subs()
                    self._send(chat_id, "🛡 Вы подписаны на тревоги SecuPredict.\n"
                                        "Пришлю сообщение, только когда что-то случится.\n"
                                        "Команды: /status — сводка, /stop — отписаться.")
                    while self._pending:
                        self._send(chat_id, self._pending.popleft())
                elif text.startswith("/stop"):
                    self.subscribers.discard(chat_id)
                    self._save_subs()
                    self._send(chat_id, "Вы отписаны от тревог. Вернуться — /start.")
                elif text.startswith("/status"):
                    self._send(chat_id, self.status_text())


# ═════════════════════════════════════════════════════════════════════════════
# Приложение и веб-сервер
# ═════════════════════════════════════════════════════════════════════════════
class App:
    """Собирает всё вместе: хосты, сбор метрик, тревоги, сценарий, бот, дашборд."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.profile = PROFILES[cfg.profile]
        self.started = time.time()
        self.local = LocalMetrics()
        self.hosts: Dict[str, Host] = {}
        me = platform.node() or "этот-компьютер"
        self.hosts["local"] = Host("local", me, "Этот компьютер · реальные метрики", cfg.history_points, real=True)
        for hid, name, base in self.profile["fleet"]:
            self.hosts[hid] = Host(hid, name, hid, cfg.history_points, base)
        self.alerts = AlertManager(cfg, self.hosts)
        self.rules = ThresholdRules(cfg, self.alerts)
        self.scenario = ScenarioRunner(cfg, self.hosts, self.alerts) if cfg.scenario else None
        self.bot = TelegramBot(cfg, self.status_text)
        self.alerts.listeners.append(self.bot.notify)
        self._stop = threading.Event()

    def host_status(self, host: Host) -> str:
        if host.isolated:
            return "isolated"
        worst = max((SEV_ORDER[a.severity] for a in self.alerts.open_for(host.id)), default=-1)
        if worst >= SEV_ORDER["high"]:
            return "alert"
        if worst >= SEV_ORDER["medium"] or max(host.latest.get("cpu", 0), host.latest.get("ram", 0)) > 85:
            return "warning"
        return "ok"

    def _sampler(self) -> None:
        while not self._stop.is_set():
            for host in self.hosts.values():
                try:
                    host.push(self.local.sample() if host.real else host.simulate())
                    self.rules.check(host)
                except Exception as exc:
                    log.error("Ошибка сбора метрик %s: %s", host.id, exc)
            self._stop.wait(self.cfg.sample_interval)

    def state(self) -> Dict[str, Any]:
        """Всё, что нужно дашборду."""
        hosts = []
        for h in self.hosts.values():
            hosts.append({
                "id": h.id, "name": h.name, "role": h.role, "real": h.real, "status": self.host_status(h),
                "latest": h.latest,
                "history": {m: list(h.history[m]) for m in ("cpu", "ram", "net_in", "net_out", "io")},
            })
        return {
            "company": self.profile["company"], "profile": self.cfg.profile, "version": VERSION,
            "now": time.time(), "interval": self.cfg.sample_interval,
            "hosts": hosts, "alerts": self.alerts.snapshot(),
            "scenario": self.scenario.status() if self.scenario else None,
            "telegram": {"enabled": self.bot.enabled, "online": self.bot.online,
                         "bot": self.bot.username, "subscribers": len(self.bot.subscribers),
                         "min_severity": self.cfg.tg_min_severity},
        }

    def status_text(self) -> str:
        """Сводка для команды /status."""
        names = {"ok": "в норме", "warning": "внимание", "alert": "угроза", "isolated": "изолирован"}
        lines = [f"🛡 <b>{html.escape(self.profile['company'])}</b>", ""]
        for h in self.hosts.values():
            st = self.host_status(h)
            mark = {"ok": "🟢", "warning": "🟡", "alert": "🔴", "isolated": "🟣"}[st]
            lines.append(f"{mark} {html.escape(h.name)} — {names[st]}, CPU {h.latest.get('cpu', 0):.0f}%")
        open_alerts = [a for a in self.alerts.snapshot() if a["status"] == "open"]
        lines += ["", f"Открытых тревог: {len(open_alerts)}", f"Дашборд: {self.cfg.dashboard_url}"]
        return "\n".join(lines)

    def run(self) -> None:
        self.cfg.data_dir.mkdir(parents=True, exist_ok=True)
        threading.Thread(target=self._sampler, name="sampler", daemon=True).start()
        if self.scenario:
            threading.Thread(target=self.scenario.run, name="scenario", daemon=True).start()
        self.bot.start()
        server = ThreadingHTTPServer((self.cfg.bind_host, self.cfg.port), make_handler(self))
        print(f"SecuPredict Monitor {VERSION} · {self.profile['company']}")
        print(f"  Дашборд:   {self.cfg.dashboard_url}")
        if self.bot.enabled:
            who = f"@{self.bot.username}" if self.bot.username else "ваш бот (Telegram пока недоступен)"
            print(f"  Telegram:  {who} — напишите ему /start, чтобы получать тревоги")
        if self.scenario:
            print("  Сценарий:  первая тревога через 10 с, критическая через 25 с")
        print("  Остановить: Ctrl+C")
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            print("\nОстановлено.")
        finally:
            self._stop.set()
            if self.scenario:
                self.scenario.stop_event.set()
            self.bot.stop()
            server.server_close()


def make_handler(app: App) -> type:
    """HTTP-обработчик дашборда и API."""

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path in ("/", "/index.html"):
                self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path.startswith("/api/state"):
                body = json.dumps(app.state(), ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:  # noqa: N802
            m = re.fullmatch(r"/api/alerts/([0-9a-f]{8})/ack", self.path)
            if m and app.alerts.ack(m.group(1)):
                self._send(200, b'{"ok":true}', "application/json")
            else:
                self._send(404, b'{"ok":false}', "application/json")

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("http: " + fmt, *args)

    return Handler


# ═════════════════════════════════════════════════════════════════════════════
# Дашборд (один HTML без внешних библиотек — работает без интернета)
# ═════════════════════════════════════════════════════════════════════════════
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecuPredict · мониторинг</title>
<style>
:root{
  --paper:#EDF1F3; --surface:#FFFFFF; --ink:#172634; --muted:#5B6B79; --line:#D6DDE3; --sky:#1F7FB8;
  --low:#4F8A5E; --medium:#B98310; --high:#CF5A24; --critical:#B3263D; --isolated:#6650A8; --ok:#4F8A5E;
  --band-ink:#FFFFFF; color-scheme:light;
}
@media (prefers-color-scheme: dark){
  :root{ --paper:#0E1822; --surface:#15222E; --ink:#E2E9EF; --muted:#8C9EAE; --line:#243646; --sky:#52A8DE;
    --low:#6DB17F; --medium:#E0AA35; --high:#EE7A44; --critical:#E5506A; --isolated:#9A85E0; --ok:#6DB17F;
    color-scheme:dark; }
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--paper);color:var(--ink);
  font:15px/1.45 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",sans-serif;
  font-variant-numeric:tabular-nums}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 24px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}
.brand h1{font-size:17px;margin:0;font-weight:650}
.brand p{margin:0;color:var(--muted);font-size:13px}
.meta{display:flex;gap:18px;color:var(--muted);font-size:13px;align-items:center;flex-wrap:wrap}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted);margin-right:6px;vertical-align:1px}
.dot.on{background:var(--ok)} .dot.off{background:var(--critical)}

.band{margin:0 24px;padding:22px 26px;border-radius:14px;background:var(--ok);color:var(--band-ink);
  display:flex;justify-content:space-between;align-items:flex-end;gap:20px;flex-wrap:wrap;
  transition:background-color .6s ease}
.band.sev-low{background:var(--low)} .band.sev-medium{background:var(--medium)}
.band.sev-high{background:var(--high)} .band.sev-critical{background:var(--critical)}
.band strong{display:block;font-size:30px;line-height:1.15;font-weight:700;letter-spacing:-.01em}
.band span{display:block;margin-top:6px;font-size:16px;opacity:.92;max-width:60ch}
.counts{display:flex;gap:18px;font-size:14px}
.counts b{display:block;font-size:22px}

.layout{display:grid;grid-template-columns:minmax(0,1fr) 380px;gap:20px;padding:20px 24px 40px}
@media (max-width:1000px){.layout{grid-template-columns:1fr}}
h2{font-size:15px;font-weight:650;margin:0 0 10px}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:640px}
th{font-weight:500;color:var(--muted);font-size:13px;text-align:left;padding:0 10px 8px}
td{padding:10px;border-top:1px solid var(--line);vertical-align:middle}
tr.host{cursor:pointer}
tr.host:hover td{background:color-mix(in srgb,var(--sky) 6%,transparent)}
tr.host.sel td{background:color-mix(in srgb,var(--sky) 11%,transparent)}
tr.host:focus-visible{outline:2px solid var(--sky);outline-offset:-2px}
.hname{font-weight:600}
.hrole{color:var(--muted);font-size:12.5px}
.st{font-size:13px;font-weight:600;white-space:nowrap}
.st::before{content:"";display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;background:currentColor;vertical-align:0}
.st-ok{color:var(--ok)} .st-warning{color:var(--medium)} .st-alert{color:var(--critical)} .st-isolated{color:var(--isolated)}
.meter{display:flex;align-items:center;gap:8px;white-space:nowrap}
.track{width:56px;height:6px;border-radius:3px;background:var(--line);overflow:hidden}
.fill{height:100%;background:var(--sky)}
.fill.hot{background:var(--high)}
.net{font-size:13px;color:var(--muted);white-space:nowrap}
.spark{display:block}

.detail{margin-top:20px}
.detail-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
.legend{display:flex;gap:16px;font-size:13px;color:var(--muted)}
.legend i{display:inline-block;width:14px;height:3px;margin-right:6px;vertical-align:3px;border-radius:2px}
#chart{width:100%;height:auto;display:block;margin-top:8px}
#chart text{fill:var(--muted);font-size:11px}
.facts{display:flex;gap:24px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-top:8px}
.facts b{color:var(--ink);font-weight:600}

.alerts ol{list-style:none;margin:0;padding:0}
.alert{border-left:4px solid var(--muted);padding:10px 12px;margin-bottom:10px;background:var(--surface);
  border-radius:0 8px 8px 0;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.alert.low{border-left-color:var(--low)} .alert.medium{border-left-color:var(--medium)}
.alert.high{border-left-color:var(--high)} .alert.critical{border-left-color:var(--critical)}
.alert.ack{opacity:.6}
.alert.fresh{animation:flash 2.4s ease-out}
@keyframes flash{0%{background:color-mix(in srgb,var(--critical) 18%,var(--surface))}100%{background:var(--surface)}}
.ah{display:flex;justify-content:space-between;gap:8px;font-size:12.5px;color:var(--muted)}
.sev{font-weight:650}
.sev.low{color:var(--low)} .sev.medium{color:var(--medium)} .sev.high{color:var(--high)} .sev.critical{color:var(--critical)}
.at{font-weight:650;margin:3px 0 2px}
.alert details{font-size:13.5px;color:var(--ink)}
.alert summary{cursor:pointer;color:var(--sky);font-size:13px;margin-top:4px}
.alert p{margin:6px 0}
.alert ol.steps{list-style:decimal;padding-left:20px;margin:4px 0}
.row{display:flex;justify-content:space-between;align-items:center;margin-top:6px;gap:8px}
.tag{font-size:12px;color:var(--muted)}
button{font:inherit;font-size:13px;padding:4px 12px;border-radius:6px;border:1px solid var(--line);
  background:var(--surface);color:var(--ink);cursor:pointer}
button:hover{border-color:var(--sky)}
button:focus-visible{outline:2px solid var(--sky);outline-offset:2px}
.empty{color:var(--muted);font-size:14px;padding:8px 0}
.note{color:var(--muted);font-size:12.5px;margin-top:10px}
@media (prefers-reduced-motion: reduce){.band{transition:none}.alert.fresh{animation:none}}
</style></head>
<body>
<header class="top">
  <div class="brand">
    <svg width="30" height="34" viewBox="0 0 30 34" aria-hidden="true"><path d="M15 1 28 6v10c0 8.5-5.6 14.4-13 17C7.6 30.4 2 24.5 2 16V6z" fill="var(--sky)"/><path d="m9 17 4.2 4.2L21.5 12.5" stroke="#fff" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <div><h1 id="company">SecuPredict</h1><p>Защита компьютеров и данных</p></div>
  </div>
  <div class="meta">
    <span id="tg"><span class="dot"></span>Telegram</span>
    <span id="conn"><span class="dot"></span>Связь с агентом</span>
    <span id="clock"></span>
  </div>
</header>

<section id="band" class="band" aria-live="polite">
  <div><strong id="bandTitle">Подключаемся…</strong><span id="bandText"></span></div>
  <div class="counts" id="counts"></div>
</section>

<main class="layout">
  <section>
    <div class="panel">
      <h2>Компьютеры и серверы</h2>
      <div class="scroll"><table>
        <thead><tr><th>Устройство</th><th>Состояние</th><th>Процессор</th><th>Память</th><th>Диск</th><th>Сеть, вход / выход</th></tr></thead>
        <tbody id="hosts"></tbody>
      </table></div>
    </div>
    <div class="panel detail">
      <div class="detail-head">
        <h2 id="detailTitle">Нагрузка</h2>
        <div class="legend"><span><i style="background:var(--sky)"></i>Процессор</span><span><i style="background:var(--isolated)"></i>Память</span></div>
      </div>
      <svg id="chart" viewBox="0 0 720 200" role="img" aria-label="График нагрузки за 5 минут"></svg>
      <div class="facts" id="facts"></div>
    </div>
  </section>
  <aside class="alerts">
    <div class="panel">
      <h2>Тревоги</h2>
      <ol id="alerts"></ol>
      <p class="note" id="tgnote"></p>
    </div>
  </aside>
</main>

<script>
const ORDER={low:0,medium:1,high:2,critical:3};
const SEV={low:'Низкий',medium:'Средний',high:'Высокий',critical:'Критический'};
const STATUS={ok:'В норме',warning:'Внимание',alert:'Угроза',isolated:'Изолирован'};
const BAND={critical:'Критическая угроза',high:'Серьёзная угроза',medium:'Нужно проверить',low:'Есть рекомендации'};
let selected=null, seen=new Set(), firstRender=true, lastState=null;

const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const kb=v=>v>=1024?(v/1024).toFixed(1)+' МБ/с':Math.round(v)+' КБ/с';
const hm=ts=>new Date(ts*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit'});

function meter(v){const p=Math.max(0,Math.min(100,v||0));
  return `<div class="meter"><div class="track"><div class="fill${p>=85?' hot':''}" style="width:${p}%"></div></div>${Math.round(p)}%</div>`;}
function spark(arr){const a=arr.slice(-40);if(a.length<2)return '';const w=90,h=24;
  const pts=a.map((v,i)=>`${(i/(a.length-1)*w).toFixed(1)},${(h-2-(v/100)*(h-4)).toFixed(1)}`).join(' ');
  return `<svg class="spark" width="${w}" height="${h}" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="var(--sky)" stroke-width="1.5"/></svg>`;}

function renderHosts(hosts){
  if(!selected||!hosts.find(h=>h.id===selected)) selected=hosts[0]?.id;
  document.getElementById('hosts').innerHTML=hosts.map(h=>{const l=h.latest||{};return `
  <tr class="host${h.id===selected?' sel':''}" data-id="${esc(h.id)}" tabindex="0">
    <td><div class="hname">${esc(h.name)}</div><div class="hrole">${esc(h.role)}</div></td>
    <td><span class="st st-${h.status}">${STATUS[h.status]}</span></td>
    <td><div style="display:flex;gap:10px;align-items:center">${meter(l.cpu)}${spark(h.history.cpu)}</div></td>
    <td>${meter(l.ram)}</td><td>${meter(l.disk)}</td>
    <td class="net">${h.status==='isolated'?'отключена':kb(l.net_in||0)+' / '+kb(l.net_out||0)}</td>
  </tr>`}).join('');
  document.querySelectorAll('tr.host').forEach(tr=>{
    const pick=()=>{selected=tr.dataset.id;render(lastState)};
    tr.onclick=pick; tr.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick()}};
  });
}

function renderChart(s){
  const h=s.hosts.find(x=>x.id===selected); if(!h)return;
  document.getElementById('detailTitle').textContent=`Нагрузка: ${h.name}, последние 5 минут`;
  const W=720,H=200,L=36,R=8,T=10,B=22, n=Math.max(2,h.history.cpu.length);
  const x=i=>L+(W-L-R)*(i/(n-1)), y=v=>T+(H-T-B)*(1-v/100);
  let g='';
  for(const v of [0,50,85,100]){g+=`<line x1="${L}" x2="${W-R}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)" ${v===85?'stroke-dasharray="5 4"':''}/><text x="${L-6}" y="${y(v)+4}" text-anchor="end">${v}%</text>`;}
  const line=(arr,c)=>arr.length<2?'':`<polyline points="${arr.map((v,i)=>`${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')}" fill="none" stroke="${c}" stroke-width="2" stroke-linejoin="round"/>`;
  g+=`<text x="${L}" y="${H-5}">−5 мин</text><text x="${W-R}" y="${H-5}" text-anchor="end">сейчас</text>`;
  document.getElementById('chart').innerHTML=g+line(h.history.ram,'var(--isolated)')+line(h.history.cpu,'var(--sky)');
  const l=h.latest||{};
  document.getElementById('facts').innerHTML=
    `<span>Процессор <b>${Math.round(l.cpu||0)}%</b></span><span>Память <b>${Math.round(l.ram||0)}%</b></span>`+
    `<span>Диск занят <b>${Math.round(l.disk||0)}%</b></span><span>Чтение и запись диска <b>${kb(l.io||0)}</b></span>`+
    `<span>Сеть <b>${h.status==='isolated'?'отключена':kb(l.net_in||0)+' / '+kb(l.net_out||0)}</b></span>`;
}

function renderBand(s){
  const open=s.alerts.filter(a=>a.status==='open');
  const band=document.getElementById('band');
  const worst=open.reduce((w,a)=>!w||ORDER[a.severity]>ORDER[w.severity]?a:w,null);
  band.className='band'+(worst?' sev-'+worst.severity:'');
  document.getElementById('bandTitle').textContent=worst?BAND[worst.severity]:'Всё спокойно';
  document.getElementById('bandText').textContent=worst?`${worst.host_name}: ${worst.title.toLowerCase()}`:
    `Под наблюдением ${s.hosts.length} устройств. Открытых тревог нет.`;
  const c={critical:0,high:0,medium:0,low:0}; open.forEach(a=>c[a.severity]++);
  document.getElementById('counts').innerHTML=['critical','high','medium','low']
    .map(k=>`<div><b>${c[k]}</b>${SEV[k].toLowerCase()}</div>`).join('');
}

function renderAlerts(s){
  const list=document.getElementById('alerts');
  if(!s.alerts.length){list.innerHTML='<li class="empty">Тревог пока нет. Как только что-то случится, оно появится здесь и в Telegram.</li>';return;}
  list.innerHTML=s.alerts.map(a=>{const fresh=!firstRender&&!seen.has(a.id);seen.add(a.id);return `
  <li class="alert ${a.severity}${a.status==='ack'?' ack':''}${fresh?' fresh':''}">
    <div class="ah"><span class="sev ${a.severity}">${SEV[a.severity]}</span><span>${hm(a.ts)} · ${esc(a.host_name)}</span></div>
    <div class="at">${esc(a.title)}</div>
    <details${fresh&&ORDER[a.severity]>=2?' open':''}><summary>Подробнее и что делать</summary>
      <p><b>Что случилось:</b> ${esc(a.what)}</p><p><b>Что мы сделали:</b> ${esc(a.did)}</p>
      <ol class="steps">${a.steps.map(x=>`<li>${esc(x)}</li>`).join('')}</ol></details>
    <div class="row"><span class="tag">${a.source==='scenario'?'демо-сценарий':'реальные метрики'}${ORDER[a.severity]>=ORDER[s.telegram.min_severity]&&s.telegram.enabled?' · в Telegram':''}</span>
      ${a.status==='open'?`<button data-ack="${a.id}">Принять</button>`:'<span class="tag">Принято</span>'}</div>
  </li>`}).join('');
  list.querySelectorAll('button[data-ack]').forEach(b=>b.onclick=async()=>{
    b.disabled=true; await fetch(`/api/alerts/${b.dataset.ack}/ack`,{method:'POST'}); tick();});
  firstRender=false;
}

function renderMeta(s){
  document.getElementById('company').textContent='SecuPredict · '+s.company;
  const t=s.telegram, tg=document.getElementById('tg');
  tg.innerHTML=`<span class="dot ${t.enabled&&t.online?'on':'off'}"></span>Telegram${t.bot?' @'+esc(t.bot):''}: ${t.subscribers} подписч.`;
  document.getElementById('tgnote').textContent=!t.enabled?'Telegram не настроен: тревоги видны только здесь.':
    t.subscribers?`Тревоги от уровня «${SEV[t.min_severity].toLowerCase()}» и выше уходят в Telegram.`:
    `Чтобы получать тревоги в Telegram, напишите боту ${t.bot?'@'+t.bot:''} команду /start.`;
}

function render(s){ if(!s)return; lastState=s; renderMeta(s); renderBand(s); renderHosts(s.hosts); renderChart(s); renderAlerts(s); }

async function tick(){
  const conn=document.querySelector('#conn .dot');
  try{const r=await fetch('/api/state',{cache:'no-store'}); render(await r.json()); conn.className='dot on';}
  catch(e){conn.className='dot off';}
}
setInterval(()=>document.getElementById('clock').textContent=new Date().toLocaleTimeString('ru-RU'),1000);
setInterval(tick,2000); tick();
</script>
</body></html>
"""


# ═════════════════════════════════════════════════════════════════════════════
def main(argv: Optional[List[str]] = None) -> int:
    """Точка входа."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    p = argparse.ArgumentParser(description="SecuPredict Monitor: метрики, тревоги, дашборд, Telegram")
    p.add_argument("--profile", choices=tuple(PROFILES), default="clinic")
    p.add_argument("--host", default="127.0.0.1", help="адрес дашборда (0.0.0.0 — вся локальная сеть)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--no-scenario", action="store_true", help="без демо-сценария, только реальные метрики")
    p.add_argument("--loop", action="store_true", help="повторять демо-сценарий каждые 5 минут")
    p.add_argument("--tg-min", choices=tuple(SEV_ORDER), default="medium", help="с какого уровня слать в Telegram")
    p.add_argument("--no-telegram", action="store_true")
    p.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    p.add_argument("--data-dir", default=".")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO if a.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    token = "" if a.no_telegram else os.environ.get("TG_BOT_TOKEN", DEFAULT_TG_TOKEN)
    cfg = Config(profile=a.profile, bind_host=a.host, port=a.port, tg_token=token, tg_min_severity=a.tg_min,
                 scenario=not a.no_scenario, scenario_loop_sec=300.0 if a.loop else 0.0,
                 data_dir=Path(a.data_dir))
    app = App(cfg)
    if not a.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(cfg.dashboard_url)).start()
    try:
        app.run()
    except OSError as exc:
        print(f"Не удалось запустить дашборд на порту {cfg.port}: {exc}. Попробуйте --port 8081", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
