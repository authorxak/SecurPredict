"""Response module with two modes.

dry-run (default): an action is only described and written to the journal.
enforce (--enforce): the action is really attempted, with strict limits:

- a process is terminated only if it was started by tools/simulate_attack.py
  (either launched by this monitor, or announced through the marker file and
  confirmed by its command line) and is not known to hold no decoy files;
- an IP address is blocked in the system firewall only with administrator
  rights; otherwise the journal and the alert say that nothing was blocked.

Every action, in both modes, is stored with its reason, time and result.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import SIM_MARKER
from .storage import Storage

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    psutil = None

log = logging.getLogger("secupredict.response")

_LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


@dataclass
class ActionRecord:
    action: str  # terminate_process | block_ip
    target: str
    mode: str  # dry-run | enforce
    result: str  # described | done | failed | refused | not_found
    reason: str
    detail: str  # human readable, Russian, shown in alerts and on the dashboard
    ts: float
    alert_id: str = ""
    id: int = 0


def _is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _cmdline(pid: int) -> Optional[str]:
    """Command line of a process, or None when it cannot be read (or the pid is dead)."""
    if psutil:
        try:
            return " ".join(psutil.Process(pid).cmdline())
        except Exception:  # noqa: BLE001 - NoSuchProcess, AccessDenied
            return None
    proc = "/proc/%d/cmdline" % pid
    if os.path.exists("/proc/self/cmdline"):
        try:
            with open(proc, "rb") as fh:
                return fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            return None
    if os.name == "posix":
        try:
            out = subprocess.run(["ps", "-p", str(pid), "-o", "command="], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=5)
            text = out.stdout.decode("utf-8", "replace").strip()
            return text or None
        except (OSError, subprocess.SubprocessError):
            return None
    return None  # Windows without psutil: cannot verify, so the caller refuses


def _holds_files_in(pid: int, directory: str) -> Optional[bool]:
    """True/False if we can tell whether the process has open files in directory, else None."""
    root = os.path.realpath(directory) + os.sep
    if psutil:
        try:
            return any(os.path.realpath(f.path).startswith(root) for f in psutil.Process(pid).open_files())
        except Exception:  # noqa: BLE001
            return None
    fd_dir = "/proc/%d/fd" % pid
    if os.path.isdir(fd_dir):
        try:
            for name in os.listdir(fd_dir):
                try:
                    if os.path.realpath(os.readlink(os.path.join(fd_dir, name))).startswith(root):
                        return True
                except OSError:
                    continue
            return False
        except OSError:
            return None
    return None


class Responder:
    """Decides, performs (or describes) and journals response actions."""

    def __init__(self, storage: Storage, enforce: bool = False) -> None:
        self.storage = storage
        self.enforce = enforce
        self._child: Optional["subprocess.Popen[bytes]"] = None
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        return "enforce" if self.enforce else "dry-run"

    def register_child(self, proc: "subprocess.Popen[bytes]") -> None:
        """Remember a simulator process that the monitor itself started."""
        with self._lock:
            self._child = proc

    def child_running(self) -> bool:
        with self._lock:
            return self._child is not None and self._child.poll() is None

    def stop_child(self) -> None:
        """Stop the simulator started from the dashboard (used by the reset button)."""
        with self._lock:
            child, self._child = self._child, None
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()

    def _record(self, action: str, target: str, result: str, reason: str, detail: str,
                alert_id: str) -> ActionRecord:
        rec = ActionRecord(action, target, self.mode, result, reason, detail, time.time(), alert_id)
        try:
            rec.id = self.storage.insert_action(asdict(rec))
        except Exception as exc:  # noqa: BLE001
            log.error("Cannot store action: %s", exc)
        log.warning("Action [%s] %s %s -> %s: %s", rec.mode, action, target, result, detail)
        return rec

    # Process termination ------------------------------------------------------
    def _find_simulator(self, directory: str) -> Tuple[Optional[int], str]:
        """Locate a simulate_attack process. Returns (pid, how) or (None, why not)."""
        with self._lock:
            child = self._child
        if child is not None and child.poll() is None:
            return child.pid, "child"
        marker = Path(directory) / SIM_MARKER
        try:
            info = json.loads(marker.read_text(encoding="utf-8"))
            pid = int(info["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            return None, "процесс-источник изменений не найден (нет отметки simulate_attack)"
        if pid <= 1 or pid == os.getpid():
            return None, "некорректный PID в отметке simulate_attack"
        cmd = _cmdline(pid)
        if cmd is None:
            return None, ("процесс PID %d уже завершён или его нельзя проверить "
                          "(на Windows для проверки нужен psutil)" % pid)
        if "simulate_attack" not in cmd:
            return None, "процесс PID %d не является simulate_attack, его трогать нельзя" % pid
        return pid, "marker"

    def handle_file_burst(self, alert_id: str, directory: str, reason: str) -> List[ActionRecord]:
        pid, how = self._find_simulator(directory)
        if pid is None:
            return [self._record("terminate_process", "-", "not_found", reason,
                                 "Процесс не остановлен: %s." % how, alert_id)]
        target = "PID %d (tools/simulate_attack.py)" % pid
        holds = _holds_files_in(pid, directory)
        if holds is False:
            return [self._record("terminate_process", target, "refused", reason,
                                 "Процесс %s не остановлен: он не держит открытыми файлы-приманки." % target,
                                 alert_id)]
        note = "" if holds else " Проверить открытые файлы процесса не удалось."
        if not self.enforce:
            return [self._record("terminate_process", target, "described", reason,
                                 "Режим dry-run: ничего не остановлено. В режиме --enforce был бы завершён "
                                 "процесс %s, который держит открытыми файлы-приманки.%s" % (target, note),
                                 alert_id)]
        try:
            if how == "child":
                self.stop_child()
            elif os.name == "nt":
                psutil.Process(pid).terminate()  # reachable only with psutil (see _cmdline)
            else:
                os.kill(pid, signal.SIGTERM)
        except Exception as exc:  # noqa: BLE001
            return [self._record("terminate_process", target, "failed", reason,
                                 "Не удалось завершить процесс %s: %s." % (target, exc), alert_id)]
        return [self._record("terminate_process", target, "done", reason,
                             "Режим enforce: процесс %s реально завершён.%s" % (target, note), alert_id)]

    # IP blocking ----------------------------------------------------------------
    @staticmethod
    def _firewall_command(ip: "ipaddress._BaseAddress") -> Tuple[Optional[List[str]], str, str]:
        """Returns (command, undo hint, problem). command is None when blocking is impossible."""
        text = str(ip)
        if sys.platform.startswith("linux"):
            tool = "ip6tables" if ip.version == 6 else "iptables"
            if not shutil.which(tool):
                return None, "", "в системе не найден %s" % tool
            return ([tool, "-I", "INPUT", "-s", text, "-j", "DROP"],
                    "%s -D INPUT -s %s -j DROP" % (tool, text), "")
        if os.name == "nt":
            name = "SecuPredict block %s" % text
            return (["netsh", "advfirewall", "firewall", "add", "rule", "name=%s" % name, "dir=in",
                     "action=block", "remoteip=%s" % text],
                    'netsh advfirewall firewall delete rule name="%s"' % name, "")
        return None, "", "блокировка через firewall на этой ОС не реализована"

    def handle_bruteforce(self, alert_id: str, ip_text: str, reason: str) -> List[ActionRecord]:
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return [self._record("block_ip", ip_text[:64], "refused", reason,
                                 "Адрес не заблокирован: некорректный IP.", alert_id)]
        target = str(ip)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified \
                or any(ip in net for net in _LAN_NETS):
            return [self._record("block_ip", target, "refused", reason,
                                 "Адрес %s не заблокирован: это локальный адрес, автоматически такие "
                                 "адреса не блокируются." % target, alert_id)]
        command, undo, problem = self._firewall_command(ip)
        if not self.enforce:
            planned = " ".join(command) if command else "нет (%s)" % problem
            return [self._record("block_ip", target, "described", reason,
                                 "Режим dry-run: адрес %s не заблокирован. В режиме --enforce с правами "
                                 "администратора была бы выполнена команда: %s" % (target, planned), alert_id)]
        if command is None:
            return [self._record("block_ip", target, "refused", reason,
                                 "Адрес %s не заблокирован: %s." % (target, problem), alert_id)]
        if not _is_admin():
            return [self._record("block_ip", target, "refused", reason,
                                 "Адрес %s не заблокирован: нет прав администратора. Запустите монитор от "
                                 "имени администратора (root), чтобы блокировка работала." % target, alert_id)]
        try:
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            return [self._record("block_ip", target, "failed", reason,
                                 "Не удалось заблокировать %s: %s." % (target, exc), alert_id)]
        if done.returncode != 0:
            err = done.stderr.decode("utf-8", "replace").strip()[:200]
            return [self._record("block_ip", target, "failed", reason,
                                 "Не удалось заблокировать %s: firewall вернул код %d. %s"
                                 % (target, done.returncode, err), alert_id)]
        return [self._record("block_ip", target, "done", reason,
                             "Режим enforce: адрес %s реально заблокирован в системном firewall. Правило "
                             "бессрочное, снять: %s" % (target, undo), alert_id)]

    @staticmethod
    def describe(records: List[ActionRecord]) -> str:
        """Text for the "what was done" part of an alert: exactly what the journal says."""
        if not records:
            return "Ничего не меняли: только сообщаем."
        return " ".join(r.detail for r in records)

    def recent(self, limit: int = 20, since: Optional[float] = None) -> List[Dict[str, Any]]:
        return self.storage.recent_actions(limit, since)
