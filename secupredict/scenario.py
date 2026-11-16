"""Scripted demo scenario for the simulated fleet.

Everything raised here is labelled as simulation: no real machine is touched,
and alert texts say so explicitly.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .alerts import AlertManager
from .config import PROFILES
from .metrics import Host

log = logging.getLogger("secupredict.scenario")

SIM_NOTE = "СИМУЛЯЦИЯ: реальных действий не выполнялось."

# Offsets in seconds for the eight steps: login, ransomware signs, ransomware,
# brute-force signs, brute force, storage fill, storage alert, updates.
TIMELINE_NORMAL: Tuple[float, ...] = (10, 21, 25, 40, 45, 65, 70, 95)
TIMELINE_DEMO: Tuple[float, ...] = (5, 12, 20, 30, 36, 44, 48, 56)


class ScenarioRunner:
    """Runs the scripted story on a timer. Can be started, stopped and restarted."""

    def __init__(self, hosts: Dict[str, Host], alerts: AlertManager, profile: str,
                 demo: bool = False, loop_sec: float = 0.0) -> None:
        self.hosts = hosts
        self.alerts = alerts
        self.demo = demo
        self.loop_sec = loop_sec
        self.profile_name = profile
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.started = 0.0
        self.running = False
        self.finished = False
        self._next_label = ""
        self._next_at = 0.0

    # Profile helpers --------------------------------------------------------
    @property
    def p(self) -> Dict[str, Any]:
        return PROFILES[self.profile_name]

    def _host(self, role: str) -> Host:
        return self.hosts[self.p["roles"][role]]

    def _raise(self, severity: str, role: str, title: str, what: str, did: str,
               steps: List[str], kind: str) -> None:
        self.alerts.raise_alert(severity, self.p["roles"][role], title, what, did, steps,
                                kind=kind, detector="scenario", origin="simulated")

    # Steps ------------------------------------------------------------------
    def _suspicious_login(self) -> None:
        user = self.p["front_user"]
        self._raise(
            "medium", "front", "Вход с незнакомого адреса",
            "демо-сценарий: учётная запись «%s» вошла в %s с адреса 198.51.100.4. "
            "Раньше с этого адреса никто не входил." % (user, self.p["system"]),
            SIM_NOTE + " В настоящей системе вход был бы только записан в журнал.",
            ["Спросите сотрудника «%s», входил ли он сейчас сам." % user,
             "Если нет, смените пароль."],
            "login")

    def _ransomware_signs(self) -> None:
        self._host("victim").set_override(30, cpu=94, io=52000, net_out=900)

    def _ransomware(self) -> None:
        host = self._host("victim")
        host.isolated = True
        host.set_override(600, cpu=9, io=60)
        self._raise(
            "critical", "victim", "Похоже на вирус-шифровальщик",
            "демо-сценарий: на компьютере «%s» программа svc_update.exe за 4 секунды переписала 14 файлов "
            "и сменила им расширение на .locked. Под угрозой %s." % (host.name, self.p["data"]),
            SIM_NOTE + " На дашборде показано, как выглядела бы изоляция компьютера от сети.",
            ["Не выключайте компьютер и не платите выкуп, даже если появится требование.",
             "Попросите сотрудника перейти за другой компьютер.",
             "Проверьте остальные устройства и восстановите файлы из резервной копии."],
            "ransomware")

    def _bruteforce_signs(self) -> None:
        self._host("server").set_override(20, cpu=72, net_in=2600)

    def _bruteforce(self) -> None:
        self._raise(
            "high", "server", "Кто-то подбирает пароль",
            "демо-сценарий: с адреса 198.51.100.77 за 2 минуты было 38 неудачных попыток войти в "
            "%s под именем «admin»." % self.p["system"],
            SIM_NOTE + " В настоящей системе адрес был бы заблокирован только в режиме --enforce.",
            ["Убедитесь, что у «admin» длинный пароль (от 12 символов), который нигде не повторяется.",
             "Включите вход с подтверждением по SMS или в приложении."],
            "bruteforce")

    def _storage_fill(self) -> None:
        self._host("storage").set_override(900, disk=94)

    def _storage(self) -> None:
        self._raise(
            "medium", "storage", "Почти закончилось место для резервных копий",
            "демо-сценарий: хранилище копий заполнено на 94%. Новые копии скоро перестанут сохраняться.",
            SIM_NOTE,
            ["Удалите копии старше 90 дней или подключите дополнительный диск.",
             "Проверьте, что сегодняшняя копия создана."],
            "disk")

    def _updates(self) -> None:
        self._raise(
            "low", "misc", "Давно не ставились обновления",
            "демо-сценарий: на этом компьютере обновления системы не устанавливались 41 день.",
            SIM_NOTE,
            ["Установите обновления в конце рабочего дня и перезагрузите компьютер."],
            "updates")

    def steps(self) -> List[Tuple[float, str, Callable[[], None]]]:
        timeline = TIMELINE_DEMO if self.demo else TIMELINE_NORMAL
        actions: List[Tuple[str, Callable[[], None]]] = [
            ("средняя тревога", self._suspicious_login),
            ("признаки атаки", self._ransomware_signs),
            ("критическая тревога", self._ransomware),
            ("признаки атаки", self._bruteforce_signs),
            ("высокая тревога", self._bruteforce),
            ("рост заполнения", self._storage_fill),
            ("средняя тревога", self._storage),
            ("низкая тревога", self._updates),
        ]
        return [(at, label, fn) for at, (label, fn) in zip(timeline, actions)]

    # Control ----------------------------------------------------------------
    def start(self) -> None:
        """Start (or restart) the story from the beginning."""
        self.stop()
        with self._lock:
            self._stop = threading.Event()
            self.running, self.finished = True, False
            self._thread = threading.Thread(target=self._run, args=(self._stop,), name="scenario", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            thread, self._thread = self._thread, None
            self.running = False
            self._next_label = ""
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

    def _run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.started = time.time()
            for at, label, action in self.steps():
                self._next_label, self._next_at = label, self.started + at
                if stop.wait(max(0.0, self.started + at - time.time())):
                    return
                try:
                    action()
                except Exception as exc:  # noqa: BLE001
                    log.error("Scenario step failed: %s", exc)
            self._next_label = ""
            if self.loop_sec <= 0:
                break
            if stop.wait(max(0.0, self.started + self.loop_sec - time.time())):
                return
            for host in self.hosts.values():
                if host.kind == "simulated":
                    host.isolated = False
                    host._overrides.clear()
        if not stop.is_set():
            self.running, self.finished = False, True

    def status(self) -> Dict[str, Any]:
        text = ""
        if self.running and self._next_label:
            left = max(0, int(self._next_at - time.time()))
            text = "%s через %d с" % (self._next_label, left)
        return {"running": self.running, "finished": self.finished, "next": text,
                "elapsed": int(time.time() - self.started) if self.running else 0,
                "duration": int((TIMELINE_DEMO if self.demo else TIMELINE_NORMAL)[-1])}
