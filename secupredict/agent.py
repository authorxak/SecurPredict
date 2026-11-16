"""Agent mode: push real metrics of this computer to a SecuPredict server."""
from __future__ import annotations

import json
import logging
import platform
import re
import time
import urllib.error
import urllib.request
from typing import Optional

from .metrics import LocalMetrics

log = logging.getLogger("secupredict.agent")


def host_id_from_name(name: str) -> str:
    """Safe host id: letters, digits, dot, dash and underscore, at most 48 characters."""
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name)[:48] or "agent"


def run_agent(server: str, key: str, interval: float = 2.0, name: Optional[str] = None,
              max_cycles: Optional[int] = None) -> int:
    """Send one metrics sample every `interval` seconds to POST /api/ingest.

    Returns a process exit code. Runs until interrupted unless max_cycles is set.
    """
    if not server.lower().startswith(("http://", "https://")):
        print("Ошибка: адрес сервера должен начинаться с http:// или https://")
        return 2
    if not key:
        print("Ошибка: не задан ключ агента (--agent-key или SECUPREDICT_AGENT_KEY).")
        return 2
    url = server.rstrip("/") + "/api/ingest"
    display = name or platform.node() or "agent"
    host_id = host_id_from_name(display)
    metrics = LocalMetrics()
    if metrics.source == "none":
        print("Внимание: на этой ОС без psutil процессор и память не измеряются. "
              "Установите psutil: pip install psutil")
    print("SecuPredict agent: %s -> %s, каждые %.0f с. Остановить: Ctrl+C" % (display, url, interval))
    metrics.sample()
    sent = 0
    failing = False
    try:
        while max_cycles is None or sent < max_cycles:
            time.sleep(interval)
            payload = {"host_id": host_id, "name": display, "os": platform.system(),
                       "ts": time.time(), "metrics": metrics.sample()}
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-Agent-Key": key})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
                if failing:
                    print("Связь с сервером восстановлена.")
                failing = False
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    print("Сервер отклонил ключ агента (HTTP %d). Проверьте --agent-key." % exc.code)
                    return 3
                if not failing:
                    print("Сервер ответил ошибкой HTTP %d, повторяю попытки." % exc.code)
                failing = True
            except Exception as exc:  # noqa: BLE001 - network errors
                if not failing:
                    print("Нет связи с сервером (%s), повторяю попытки." % exc.__class__.__name__)
                failing = True
            sent += 1
    except KeyboardInterrupt:
        print("\nАгент остановлен.")
    return 0
