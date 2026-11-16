"""Application wiring and command line interface."""
from __future__ import annotations

import argparse
import html
import logging
import math
import os
import platform
import re
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .agent import run_agent
from .alerts import AlertManager, new_alert_id
from .config import (DEMO_DIR_SENTINEL, DEMO_LOG_HEADER, PROFILES, SEV_ORDER, VERSION, Config, load_dotenv,
                     parse_chat_ids)
from .detectors import (Anomaly, AuthLogDetector, BruteForce, FileBurst, FileChangeDetector,
                        StatAnomalyDetector, ThresholdHit, ThresholdRules)
from .metrics import METRIC_KEYS, PERCENT_KEYS, Host, LocalMetrics, clamp, stable_seed
from .report import build_report
from .response import Responder
from .scenario import ScenarioRunner
from .storage import Storage
from .telegram import TelegramBot
from .web import make_handler

log = logging.getLogger("secupredict")

TOOL_PATH = Path(__file__).resolve().parent.parent / "tools" / "simulate_attack.py"
STAT_METRICS = ("cpu", "ram")
_AGENT_ID = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")

THRESHOLD_TEXT: Dict[str, Tuple[str, str, List[str]]] = {
    "cpu": ("Компьютер перегружен",
            "процессор загружен на {v:.0f}% уже больше {s:.0f} с (порог {limit:.0f}%).",
            ["Закройте программы, которые сейчас не нужны.",
             "Если нагрузка держится без видимой причины, проверьте компьютер: так проявляются майнеры и вирусы."]),
    "ram": ("Не хватает оперативной памяти",
            "память занята на {v:.0f}% уже больше {s:.0f} с (порог {limit:.0f}%). Программы могут зависать.",
            ["Перезапустите браузер и тяжёлые программы.",
             "Если повторяется каждый день, компьютеру нужна дополнительная память."]),
    "disk": ("Заканчивается место на диске",
             "диск заполнен на {v:.0f}% (порог {limit:.0f}%). Когда место кончится, перестанут сохраняться "
             "файлы и копии.",
             ["Удалите старые загрузки и ненужные файлы.",
              "Проверьте, что резервные копии продолжают создаваться."]),
}
METRIC_RU = {"cpu": "Процессор", "ram": "Память"}
NOTHING_DONE = "Ничего не меняли: только сообщаем и следим дальше."


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def demo_dir_is_safe(directory: Path) -> bool:
    """The simulator may only use a folder that is absent, empty or marked as its own."""
    if not directory.exists():
        return True
    if not directory.is_dir():
        return False
    if (directory / DEMO_DIR_SENTINEL).is_file():
        return True
    return not any(directory.iterdir())


def demo_log_is_safe(path: Path) -> bool:
    """The simulator may only append to a log that is absent, empty or started with its header."""
    if not path.exists():
        return True
    try:
        with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
    except OSError:
        return False
    return first == "" or first.startswith(DEMO_LOG_HEADER)


class App:
    """Hosts, sampling, detectors, alerts, response, scenario, bot and dashboard."""

    def __init__(self, cfg: Config, storage: Optional[Storage] = None,
                 local: Optional[LocalMetrics] = None) -> None:
        self.cfg = cfg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        self.storage = storage or Storage(cfg.db_path)
        self.local = local or LocalMetrics()
        self.session_start = time.time()
        self._hosts_lock = threading.RLock()
        self._eval_lock = threading.RLock()
        self._demo_lock = threading.Lock()
        self._stop = threading.Event()
        self._ticks = 0

        self.stat = StatAnomalyDetector(cfg.stat_alpha, cfg.stat_sigma, cfg.stat_min_samples,
                                        cfg.stat_sustain_samples, cfg.stat_min_std, cfg.stat_min_delta)
        self.rules = ThresholdRules({"cpu": cfg.cpu_alert, "ram": cfg.ram_alert, "disk": cfg.disk_alert},
                                    cfg.sustain_sec)
        self.filedet = FileChangeDetector(cfg.watch_dir, cfg.file_window_sec, cfg.file_change_threshold,
                                          cfg.file_ext_threshold, cfg.file_cooldown_sec, cfg.file_max_entries)
        self.authdet = AuthLogDetector(cfg.auth_log, cfg.auth_window_sec, cfg.auth_fail_threshold,
                                       cfg.auth_cooldown_sec)

        self.hosts: Dict[str, Host] = {}
        name = platform.node() or "этот-компьютер"
        self.hosts["local"] = Host("local", name, "Этот компьютер", cfg.history_points, kind="local")
        self._install_fleet(cfg.profile)

        self.alerts = AlertManager(self.storage, self._host_name, cfg.data_dir / "alerts.jsonl")
        self.responder = Responder(self.storage, cfg.enforce)
        self.scenario = ScenarioRunner(self.hosts, self.alerts, cfg.profile, cfg.demo, cfg.scenario_loop_sec)
        self.bot = TelegramBot(cfg.tg_token, cfg.data_dir, cfg.dashboard_url, cfg.tg_min_severity,
                               self.status_text, self.set_alert_status, cfg.tg_allowed_chats, quiet=cfg.demo)
        self.alerts.listeners.append(self.bot.notify)

    # Hosts --------------------------------------------------------------------
    def _host_name(self, host_id: str) -> str:
        host = self.hosts.get(host_id)
        return host.name if host else host_id

    @property
    def profile(self) -> Dict[str, Any]:
        return PROFILES[self.cfg.profile]

    def _install_fleet(self, profile: str) -> None:
        """Replace simulated hosts with the fleet of the given profile and warm them up."""
        with self._hosts_lock, self._eval_lock:
            for hid in [h.id for h in self.hosts.values() if h.kind == "simulated"]:
                self.stat.forget(hid)
                self.rules.reset(hid)
                del self.hosts[hid]
            for hid, name, base in PROFILES[profile]["fleet"]:
                seed = stable_seed(profile + ":" + hid) if self.cfg.demo else None
                host = Host(hid, name, hid, self.cfg.history_points, kind="simulated", base=base, seed=seed)
                self.hosts[hid] = host
                self._prefill(host)

    def _prefill(self, host: Host) -> None:
        """Generate simulated history so the statistical detector knows the usual level at once."""
        for _ in range(max(self.cfg.stat_min_samples, 40)):
            sample = host.simulate()
            host.push(sample)
            for metric in STAT_METRICS:
                self.stat.observe(host.id, metric, sample[metric])

    def host_status(self, host: Host) -> str:
        if host.isolated:
            return "isolated"
        if host.kind == "agent" and time.time() - host.last_seen > self.cfg.agent_stale_sec:
            return "offline"
        worst = max((SEV_ORDER[a.severity] for a in self.alerts.open_for(host.id)), default=-1)
        if worst >= SEV_ORDER["high"]:
            return "alert"
        if worst >= SEV_ORDER["medium"] or max(host.latest.get("cpu", 0), host.latest.get("ram", 0)) > 85:
            return "warning"
        return "ok"

    # Sampling and metric detectors ----------------------------------------------
    @staticmethod
    def _metric_row(ts: float, host: Host) -> Tuple[Any, ...]:
        m = host.latest
        return (ts, host.id, "real" if host.real else "simulated", m.get("cpu"), m.get("ram"), m.get("disk"),
                m.get("net_in"), m.get("net_out"), m.get("io"))

    def sample_once(self) -> None:
        now = time.time()
        rows = []
        with self._hosts_lock:
            hosts = list(self.hosts.values())
        for host in hosts:
            try:
                if host.kind == "local":
                    host.push(self.local.sample())
                elif host.kind == "simulated":
                    host.push(host.simulate())
                else:
                    continue  # agents push their own samples through /api/ingest
                self.evaluate(host)
                rows.append(self._metric_row(now, host))
            except Exception as exc:  # noqa: BLE001
                log.error("Sampling failed for %s: %s", host.id, exc)
        try:
            self.storage.insert_metrics(rows)
            self._ticks += 1
            if self._ticks % 300 == 1:
                self.storage.prune_metrics(now - self.cfg.metrics_retention_hours * 3600)
        except Exception as exc:  # noqa: BLE001
            log.error("Cannot store metrics: %s", exc)

    def evaluate(self, host: Host) -> None:
        """Run the statistical detector and threshold rules on the latest sample of a host."""
        origin = "real" if host.real else "simulated"
        with self._eval_lock:
            for metric in STAT_METRICS:
                anomaly = self.stat.observe(host.id, metric, host.latest.get(metric, 0.0))
                if anomaly and not self.alerts.recent(host.id, metric, self.cfg.rule_cooldown_sec):
                    self._raise_anomaly(host, anomaly, origin)
            for hit in self.rules.check(host.id, host.latest):
                if not self.alerts.recent(host.id, hit.metric, self.cfg.rule_cooldown_sec):
                    self._raise_threshold(host, hit, origin)

    def _raise_anomaly(self, host: Host, a: Anomaly, origin: str) -> None:
        name = METRIC_RU[a.metric]
        what = ("%s: %.0f%% при обычных для этого устройства %.0f%% (разброс %.1f). Отклонение %.1f сигмы, "
                "держится %d замера подряд." % (name.lower(), a.value, a.mean, a.std, a.zscore, a.samples))
        self.alerts.raise_alert(
            "medium", host.id, "%s заметно выше обычного уровня" % name, what, NOTHING_DONE,
            ["Посмотрите, какая программа создаёт нагрузку.",
             "Если причина неизвестна, проверьте компьютер антивирусом."],
            kind=a.metric, detector="stat", origin=origin)

    def _raise_threshold(self, host: Host, hit: ThresholdHit, origin: str) -> None:
        title, what, steps = THRESHOLD_TEXT[hit.metric]
        text = what.format(v=hit.value, s=hit.duration, limit=hit.limit)
        severity = "medium"
        if hit.metric in STAT_METRICS and self.stat.is_usual(host.id, hit.metric, hit.value):
            base = self.stat.baseline(host.id, hit.metric)
            severity = "low"
            text += " Для этого устройства это обычный уровень (в среднем %.0f%%), поэтому риск понижен." % (
                base.mean if base else hit.value)
        self.alerts.raise_alert(severity, host.id, title, text, NOTHING_DONE, steps,
                                kind=hit.metric, detector="threshold", origin=origin)

    def _sampler(self) -> None:
        while not self._stop.is_set():
            self.sample_once()
            self._stop.wait(self.cfg.sample_interval)

    # File and log detectors -----------------------------------------------------
    def poll_detectors(self) -> None:
        with self._demo_lock:
            burst = self.filedet.scan()
            if burst:
                self._on_file_burst(burst)
            for finding in self.authdet.poll():
                self._on_bruteforce(finding)

    def _watcher(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_detectors()
            except Exception as exc:  # noqa: BLE001
                log.error("Detector poll failed: %s", exc)
            self._stop.wait(self.cfg.file_poll_sec)

    def _on_file_burst(self, burst: FileBurst) -> None:
        alert_id = new_alert_id()
        directory = Path(burst.directory)
        staged = (directory / DEMO_DIR_SENTINEL).is_file()
        names = []
        for event in burst.events:
            label = event.path if event.kind != "renamed" else "%s -> %s" % (event.path, event.new_path)
            if label not in names:
                names.append(label)
        shown = ", ".join(names[:8]) + (" и ещё %d" % (len(names) - 8) if len(names) > 8 else "")
        span = max(burst.last_ts - burst.first_ts, self.cfg.file_poll_sec)
        what = ("в папке «%s» за %.0f с изменено или переименовано файлов: %d (порог: больше %d за %.0f с)."
                % (burst.directory, span, burst.changed, self.cfg.file_change_threshold, burst.window_sec))
        if burst.suspicious:
            what += " Подозрительное расширение (%s) получили файлов: %d." % (
                ", ".join(burst.extensions) or "новое", burst.suspicious)
        what += " Файлы: %s. Замечено с %s по %s." % (shown, _clock(burst.first_ts), _clock(burst.last_ts))
        if staged:
            what += (" Это папка с файлами-приманками: изменения внесла учебная имитация "
                     "tools/simulate_attack.py, настоящие файлы не затронуты.")
        records = self.responder.handle_file_burst(
            alert_id, burst.directory, "mass file change: %d files, %d suspicious" % (burst.changed, burst.suspicious))
        self.alerts.raise_alert(
            "critical", "local", "Массовое изменение файлов: похоже на шифровальщик", what,
            Responder.describe(records),
            ["Не выключайте компьютер и не платите выкуп.",
             "Отключите компьютер от сети (кабель или Wi-Fi).",
             "Проверьте остальные устройства и восстановите файлы из резервной копии."],
            kind="ransomware", detector="files", origin="real", staged=staged, alert_id=alert_id)

    def _on_bruteforce(self, finding: BruteForce) -> None:
        alert_id = new_alert_id()
        staged = demo_log_is_safe(Path(finding.log_path)) and Path(finding.log_path).exists()
        span = max(finding.last_ts - finding.first_ts, 1.0)
        what = ("с адреса %s за %.0f с было %d неудачных попыток входа (порог: %d за %.0f с). Логины: %s. "
                "Журнал: %s, записи с %s по %s." % (
                    finding.ip, span, finding.attempts, self.cfg.auth_fail_threshold, finding.window_sec,
                    ", ".join(finding.users), finding.log_path, _clock(finding.first_ts), _clock(finding.last_ts)))
        if staged:
            what += " Это учебный журнал: записи добавила имитация tools/simulate_attack.py."
        records = self.responder.handle_bruteforce(
            alert_id, finding.ip, "brute force: %d failed logins from %s" % (finding.attempts, finding.ip))
        self.alerts.raise_alert(
            "high", "local", "Кто-то подбирает пароль", what, Responder.describe(records),
            ["Убедитесь, что у этих учётных записей длинные пароли (от 12 символов), которые нигде не повторяются.",
             "Включите вход с подтверждением (двухфакторную аутентификацию)."],
            kind="bruteforce", detector="authlog", origin="real", staged=staged, alert_id=alert_id)

    # Agents ---------------------------------------------------------------------
    def ingest(self, payload: Dict[str, Any], remote: str = "") -> Tuple[bool, str]:
        """Accept one metrics sample from an agent (the key is checked by the web layer)."""
        raw_id = payload.get("host_id")
        metrics = payload.get("metrics")
        if not isinstance(raw_id, str) or not _AGENT_ID.match(raw_id) or not isinstance(metrics, dict):
            return False, "некорректные данные агента"
        sample: Dict[str, float] = {}
        for key in METRIC_KEYS:
            value = metrics.get(key, 0.0)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                return False, "некорректное значение метрики %s" % key
            sample[key] = round(clamp(float(value), 0.0, 100.0 if key in PERCENT_KEYS else 1e7), 1)
        host_id = "agent:" + raw_id
        with self._hosts_lock:
            host = self.hosts.get(host_id)
            if host is None:
                if sum(1 for h in self.hosts.values() if h.kind == "agent") >= self.cfg.max_agent_hosts:
                    return False, "достигнут предел числа агентов"
                name = str(payload.get("name") or raw_id)[:64]
                role = "Агент, %s" % remote if remote else "Агент"
                host = Host(host_id, name, role, self.cfg.history_points, kind="agent")
                self.hosts[host_id] = host
                log.info("New agent host %s from %s", host_id, remote)
        host.push(sample)
        self.evaluate(host)
        try:
            self.storage.insert_metrics([self._metric_row(time.time(), host)])
        except Exception as exc:  # noqa: BLE001
            log.error("Cannot store agent metrics: %s", exc)
        return True, "ok"

    # Demo controls ----------------------------------------------------------------
    def set_alert_status(self, alert_id: str, status: str, by: str) -> bool:
        return self.alerts.set_status(alert_id, status, by)

    def start_scenario(self) -> None:
        for host in list(self.hosts.values()):
            if host.kind == "simulated":
                host.isolated = False
                host._overrides.clear()
        self.scenario.start()

    def _run_tool(self, *args: str, wait: bool) -> Optional["subprocess.Popen[bytes]"]:
        cmd = [sys.executable, str(TOOL_PATH)] + list(args) + [
            "--files-dir", str(self.cfg.watch_dir), "--log", str(self.cfg.auth_log)]
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if wait:
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
            return None
        return proc

    def launch_attack(self) -> Tuple[bool, str]:
        """Start tools/simulate_attack.py against the decoy folder and the demo log."""
        if self.responder.child_running():
            return False, "Имитация атаки уже выполняется."
        if not TOOL_PATH.is_file():
            return False, "Не найден tools/simulate_attack.py."
        if not demo_dir_is_safe(self.cfg.watch_dir) or not demo_log_is_safe(self.cfg.auth_log):
            return False, ("Имитация не запущена: наблюдаемая папка или журнал не являются учебными. "
                           "Имитация работает только с собственной папкой demo_files и журналом demo_logs.")
        self.filedet.clear_cooldown()
        self.authdet.clear_cooldown()
        try:
            proc = self._run_tool("all", "--hold", "25", wait=False)
        except OSError as exc:
            return False, "Не удалось запустить имитацию: %s" % exc
        if proc is not None:
            self.responder.register_child(proc)
        return True, "Имитация атаки запущена: тревоги создадут детекторы, когда заметят изменения."

    def demo_reset(self) -> None:
        """Stop the scenario and the simulator, clean decoys, clear session alerts and detector state."""
        self.scenario.stop()
        self.responder.stop_child()
        with self._demo_lock:
            if TOOL_PATH.is_file() and (self.cfg.watch_dir / DEMO_DIR_SENTINEL).is_file():
                try:
                    self._run_tool("cleanup", wait=True)
                except OSError as exc:
                    log.error("Cleanup failed: %s", exc)
            self.filedet.reset()
            self.authdet.reset()
        with self._eval_lock:
            self.rules.reset()
        self._install_fleet(self.cfg.profile)
        self.alerts.clear_session()
        self.session_start = time.time()

    def set_profile(self, profile: str) -> Tuple[bool, str]:
        if profile not in PROFILES:
            return False, "Неизвестный профиль."
        self.scenario.stop()
        self.cfg.profile = profile
        self.scenario.profile_name = profile
        self.demo_reset()
        return True, "Профиль: %s." % PROFILES[profile]["company"]

    # State for the dashboard, Telegram and report -----------------------------------
    def state(self) -> Dict[str, Any]:
        hosts = []
        with self._hosts_lock:
            current = list(self.hosts.values())
        for h in current:
            base = self.stat.baseline(h.id, "cpu")
            hosts.append({
                "id": h.id, "name": h.name, "role": h.role, "real": h.real, "kind": h.kind,
                "status": self.host_status(h), "latest": h.latest,
                "history": {m: list(h.history[m]) for m in ("cpu", "ram")},
                "baseline": {"cpu": {"mean": round(base.mean, 1), "std": round(base.std, 1), "n": base.n,
                                     "need": self.cfg.stat_min_samples,
                                     "ready": base.n >= self.cfg.stat_min_samples}} if base else None,
            })
        local_n, need = self.stat.progress("local")
        return {
            "company": self.profile["company"], "profile": self.cfg.profile, "version": VERSION,
            "profiles": [{"id": pid, "company": p["company"]} for pid, p in PROFILES.items()],
            "now": time.time(), "interval": self.cfg.sample_interval, "history_points": self.cfg.history_points,
            "mode": {"demo": self.cfg.demo, "response": self.responder.mode},
            "local_source": self.local.source,
            "limits": {"cpu": self.cfg.cpu_alert, "ram": self.cfg.ram_alert, "disk": self.cfg.disk_alert,
                       "sustain": self.cfg.sustain_sec},
            "hosts": hosts, "alerts": self.alerts.snapshot(),
            "scenario": self.scenario.status(),
            "attack": {"running": self.responder.child_running()},
            "detectors": {
                "files": self.filedet.status(), "authlog": self.authdet.status(),
                "stat": {"local_ready": local_n >= need, "local_n": local_n, "need": need,
                         "sigma": self.cfg.stat_sigma, "sustain": self.cfg.stat_sustain_samples},
            },
            "actions": self.responder.recent(20, self.session_start),
            "telegram": {"enabled": self.bot.enabled, "online": self.bot.online, "bot": self.bot.username,
                         "subscribers": len(self.bot.subscribers), "min_severity": self.cfg.tg_min_severity},
        }

    def status_text(self) -> str:
        """Summary for the /status bot command."""
        names = {"ok": "в норме", "warning": "внимание", "alert": "угроза",
                 "isolated": "изолирован (симуляция)", "offline": "нет связи"}
        lines = ["<b>%s</b>" % html.escape(self.profile["company"]), ""]
        for h in list(self.hosts.values()):
            lines.append("%s [%s]: %s, CPU %.0f%%" % (
                html.escape(h.name), "РЕАЛЬНО" if h.real else "СИМУЛЯЦИЯ",
                names[self.host_status(h)], h.latest.get("cpu", 0)))
        open_alerts = [a for a in self.alerts.snapshot() if a["status"] == "open"]
        lines += ["", "Открытых тревог: %d" % len(open_alerts),
                  "Режим реагирования: %s" % self.responder.mode, "Дашборд: %s" % self.cfg.dashboard_url]
        return "\n".join(lines)

    def report_html(self, hours: float = 24.0) -> str:
        return build_report(self.storage, self.cfg, self.profile["company"], hours)

    # Lifecycle --------------------------------------------------------------------
    def start_background(self) -> None:
        threading.Thread(target=self._sampler, name="sampler", daemon=True).start()
        threading.Thread(target=self._watcher, name="watcher", daemon=True).start()
        if self.cfg.scenario:
            self.scenario.start()
        self.bot.start()

    def shutdown(self) -> None:
        self._stop.set()
        self.scenario.stop()
        self.responder.stop_child()
        self.bot.stop()
        try:
            self.storage.export_alerts_jsonl(self.cfg.data_dir / "alerts.jsonl")
        except Exception as exc:  # noqa: BLE001
            log.error("Cannot export alerts.jsonl: %s", exc)

    def run(self) -> None:
        server = ThreadingHTTPServer((self.cfg.bind_host, self.cfg.port), make_handler(self))
        server.daemon_threads = True
        self.start_background()
        print("SecuPredict Monitor %s, %s" % (VERSION, self.profile["company"]))
        print("  Дашборд:      %s%s" % (self.cfg.dashboard_url,
                                        " (нужен токен доступа)" if self.cfg.dashboard_token else ""))
        print("  Реагирование: %s" % self.responder.mode)
        print("  Файлы:        наблюдаем папку %s" % self.cfg.watch_dir)
        print("  Журнал входов: %s" % self.cfg.auth_log)
        if self.bot.enabled:
            who = "@" + self.bot.username if self.bot.username else "бот (Telegram пока недоступен)"
            print("  Telegram:     %s, напишите ему /start" % who)
        else:
            print("  Telegram:     отключён")
        if self.cfg.agent_key:
            print("  Агенты:       приём включён, POST /api/ingest")
        if self.cfg.demo:
            print("  Режим демо:   сценарий запускается кнопкой на дашборде и идёт 60 с")
        elif self.cfg.scenario:
            print("  Сценарий:     симуляция, первая тревога через 10 с")
        if self.local.source == "none":
            print("  Внимание:     без psutil на этой ОС процессор и память не измеряются (pip install psutil)")
        print("  Остановить:   Ctrl+C")
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            print("\nОстановлено.")
        finally:
            self.shutdown()
            server.server_close()


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SecuPredict Monitor: метрики, детекторы, тревоги, дашборд, Telegram")
    # Flags that existed in 0.2.0 (unchanged).
    p.add_argument("--profile", choices=tuple(PROFILES), default="clinic")
    p.add_argument("--host", default="127.0.0.1", help="адрес дашборда (0.0.0.0: вся локальная сеть, нужен токен)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--no-scenario", action="store_true", help="не запускать сценарий-симуляцию автоматически")
    p.add_argument("--loop", action="store_true", help="повторять сценарий каждые 5 минут")
    p.add_argument("--tg-min", choices=tuple(SEV_ORDER), default="medium", help="с какого уровня слать в Telegram")
    p.add_argument("--no-telegram", action="store_true")
    p.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    p.add_argument("--data-dir", default=".")
    p.add_argument("-v", "--verbose", action="store_true")
    # New in 0.3.0.
    p.add_argument("--demo", action="store_true",
                   help="режим показа: фиксированный сценарий на 60 с по кнопке, без интернета и Telegram")
    p.add_argument("--telegram", action="store_true", help="оставить Telegram включённым в режиме --demo")
    p.add_argument("--enforce", action="store_true",
                   help="реально выполнять меры реагирования (по умолчанию dry-run: только описание)")
    p.add_argument("--watch-dir", help="папка для детектора массового изменения файлов (по умолчанию ./demo_files)")
    p.add_argument("--auth-log", help="журнал входов (по умолчанию ./demo_logs/auth.log; Linux: /var/log/auth.log)")
    p.add_argument("--file-threshold", type=int, help="сколько изменённых файлов считать атакой (по умолчанию 8)")
    p.add_argument("--file-window", type=float, help="окно детектора файлов, с (по умолчанию 10)")
    p.add_argument("--auth-threshold", type=int, help="сколько неудачных входов с одного IP (по умолчанию 10)")
    p.add_argument("--auth-window", type=float, help="окно детектора входов, с (по умолчанию 120)")
    p.add_argument("--agent", action="store_true", help="режим агента: отправлять метрики этого ПК на сервер")
    p.add_argument("--server", help="адрес сервера для агента, например http://192.168.1.10:8080")
    p.add_argument("--agent-key", help="ключ агента (или переменная SECUPREDICT_AGENT_KEY)")
    p.add_argument("--agent-name", help="имя этого компьютера на дашборде сервера")
    p.add_argument("--report", nargs="?", const="report.html", metavar="FILE",
                   help="сформировать HTML-отчёт из базы и выйти")
    p.add_argument("--report-hours", type=float, default=24.0, help="период отчёта в часах")
    p.add_argument("--export-jsonl", action="store_true", help="выгрузить все тревоги из базы в alerts.jsonl и выйти")
    p.add_argument("--version", action="version", version="SecuPredict Monitor " + VERSION)
    return p


def config_from_args(a: argparse.Namespace) -> Config:
    data_dir = Path(a.data_dir)
    load_dotenv(Path(".env"))
    load_dotenv(data_dir / ".env")
    telegram_on = not a.no_telegram and (not a.demo or a.telegram)
    cfg = Config(
        profile=a.profile, bind_host=a.host, port=a.port, data_dir=data_dir, demo=a.demo,
        scenario=not a.no_scenario and not a.demo,
        scenario_loop_sec=300.0 if a.loop and not a.demo else 0.0,
        enforce=a.enforce,
        tg_token=os.environ.get("TG_BOT_TOKEN", "").strip() if telegram_on else "",
        tg_min_severity=a.tg_min,
        tg_allowed_chats=parse_chat_ids(os.environ.get("TG_CHAT_ID", "")),
        dashboard_token=os.environ.get("SECUPREDICT_DASHBOARD_TOKEN", "").strip(),
        agent_key=(a.agent_key or os.environ.get("SECUPREDICT_AGENT_KEY", "")).strip(),
        watch_dir=Path(a.watch_dir) if a.watch_dir else None,
        auth_log=Path(a.auth_log) if a.auth_log else None,
    )
    if a.file_threshold is not None:
        cfg.file_change_threshold = max(1, a.file_threshold)
    if a.file_window is not None:
        cfg.file_window_sec = max(1.0, a.file_window)
    if a.auth_threshold is not None:
        cfg.auth_fail_threshold = max(1, a.auth_threshold)
    if a.auth_window is not None:
        cfg.auth_window_sec = max(1.0, a.auth_window)
    if a.demo:
        cfg.sample_interval = 1.0
        cfg.stat_min_samples = 20
        cfg.file_cooldown_sec = 20.0
        cfg.auth_cooldown_sec = 20.0
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if a.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%H:%M:%S")
    cfg = config_from_args(a)

    if a.agent:
        if not a.server:
            print("Ошибка: для --agent укажите --server http://IP:8080", file=sys.stderr)
            return 2
        return run_agent(a.server, cfg.agent_key, interval=2.0, name=a.agent_name)

    if a.report or a.export_jsonl:
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        storage = Storage(cfg.db_path)
        if a.export_jsonl:
            count = storage.export_alerts_jsonl(cfg.data_dir / "alerts.jsonl")
            print("Выгружено тревог в alerts.jsonl: %d" % count)
        if a.report:
            target = Path(a.report)
            target.write_text(build_report(storage, cfg, PROFILES[cfg.profile]["company"], a.report_hours),
                              encoding="utf-8")
            print("Отчёт сохранён: %s. Откройте его в браузере и напечатайте в PDF." % target)
        storage.close()
        return 0

    if not cfg.is_local_bind and not cfg.dashboard_token:
        print("Ошибка: дашборд открывается в сеть (--host %s), поэтому нужен токен доступа.\n"
              "Задайте переменную SECUPREDICT_DASHBOARD_TOKEN (в окружении или в файле .env) и запустите снова."
              % cfg.bind_host, file=sys.stderr)
        return 2
    try:
        app = App(cfg)
    except Exception as exc:  # noqa: BLE001
        print("Не удалось запустить монитор: %s" % exc, file=sys.stderr)
        return 1
    if not a.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(cfg.dashboard_url)).start()
    try:
        app.run()
    except OSError as exc:
        print("Не удалось запустить дашборд на порту %d: %s. Попробуйте --port 8081" % (cfg.port, exc),
              file=sys.stderr)
        return 1
    return 0
