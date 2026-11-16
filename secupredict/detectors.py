"""Detectors. Each one works on real observations and returns plain findings.

- ThresholdRules: value above a fixed limit for a sustained time.
- StatAnomalyDetector: statistical detector (EWMA mean and deviation per host
  and metric). This is plain statistics, not a neural network.
- FileChangeDetector: mass modification or renaming of files in one folder.
- AuthLogDetector: failed logins per IP address in an sshd-style log.

Turning findings into alerts and response actions happens in app.py, so the
classes here are easy to test on synthetic data.
"""
from __future__ import annotations

import ipaddress
import math
import os
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------
# Threshold rules
# --------------------------------------------------------------------------


@dataclass
class ThresholdHit:
    host_id: str
    metric: str
    value: float
    limit: float
    duration: float


class ThresholdRules:
    """Reports a metric that stays above its limit for sustain_sec seconds."""

    def __init__(self, limits: Dict[str, float], sustain_sec: float) -> None:
        self.limits = dict(limits)
        self.sustain_sec = sustain_sec
        self._since: Dict[Tuple[str, str], float] = {}

    def check(self, host_id: str, latest: Dict[str, float], now: Optional[float] = None) -> List[ThresholdHit]:
        current = time.time() if now is None else now
        hits: List[ThresholdHit] = []
        for metric, limit in self.limits.items():
            key = (host_id, metric)
            value = float(latest.get(metric, 0.0))
            if value < limit:
                self._since.pop(key, None)
                continue
            start = self._since.setdefault(key, current)
            if current - start >= self.sustain_sec:
                hits.append(ThresholdHit(host_id, metric, value, limit, current - start))
        return hits

    def reset(self, host_id: Optional[str] = None) -> None:
        if host_id is None:
            self._since.clear()
        else:
            for key in [k for k in self._since if k[0] == host_id]:
                del self._since[key]


# --------------------------------------------------------------------------
# Statistical anomaly detector
# --------------------------------------------------------------------------


@dataclass
class Baseline:
    n: int = 0
    mean: float = 0.0
    var: float = 0.0
    streak: int = 0

    @property
    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))


@dataclass
class Anomaly:
    host_id: str
    metric: str
    value: float
    mean: float
    std: float
    zscore: float
    samples: int


class StatAnomalyDetector:
    """Per-host usual level via exponentially weighted mean and variance.

    An anomaly is reported once, when a value stays more than `sigma` standard
    deviations (and at least `min_delta` points) above the usual level for
    `sustain` samples in a row. Only upward deviations are reported. While a
    value is anomalous the baseline learns ten times slower, so a short attack
    does not become "normal", but a permanent level shift is learned eventually.
    """

    def __init__(self, alpha: float = 0.05, sigma: float = 3.0, min_samples: int = 30,
                 sustain: int = 3, min_std: float = 1.5, min_delta: float = 8.0) -> None:
        self.alpha, self.sigma = alpha, sigma
        self.min_samples, self.sustain = min_samples, sustain
        self.min_std, self.min_delta = min_std, min_delta
        self._baselines: Dict[Tuple[str, str], Baseline] = {}

    @staticmethod
    def _update(b: Baseline, value: float, alpha: float) -> None:
        diff = value - b.mean
        incr = alpha * diff
        b.mean += incr
        b.var = (1 - alpha) * (b.var + diff * incr)
        b.n += 1

    def observe(self, host_id: str, metric: str, value: float) -> Optional[Anomaly]:
        b = self._baselines.setdefault((host_id, metric), Baseline())
        if b.n < self.min_samples:
            # Warm-up: plain running statistics until there is enough history.
            self._update(b, value, max(self.alpha, 1.0 / (b.n + 1)))
            return None
        std = max(b.std, self.min_std)
        delta = value - b.mean
        zscore = delta / std
        if zscore >= self.sigma and delta >= self.min_delta:
            b.streak += 1
            mean_before = b.mean
            self._update(b, value, self.alpha * 0.1)
            if b.streak == self.sustain:
                return Anomaly(host_id, metric, value, mean_before, std, zscore, b.streak)
            return None
        b.streak = 0
        self._update(b, value, self.alpha)
        return None

    def baseline(self, host_id: str, metric: str) -> Optional[Baseline]:
        return self._baselines.get((host_id, metric))

    def ready(self, host_id: str, metric: str) -> bool:
        b = self._baselines.get((host_id, metric))
        return b is not None and b.n >= self.min_samples

    def is_usual(self, host_id: str, metric: str, value: float, tolerance: float = 2.0) -> bool:
        """True when the baseline is ready and the value is within the usual range."""
        b = self._baselines.get((host_id, metric))
        if b is None or b.n < self.min_samples:
            return False
        return abs(value - b.mean) / max(b.std, self.min_std) < tolerance

    def progress(self, host_id: str, metric: str = "cpu") -> Tuple[int, int]:
        b = self._baselines.get((host_id, metric))
        return (min(b.n, self.min_samples) if b else 0, self.min_samples)

    def forget(self, host_id: str) -> None:
        for key in [k for k in self._baselines if k[0] == host_id]:
            del self._baselines[key]


# --------------------------------------------------------------------------
# Mass file change detector
# --------------------------------------------------------------------------

SUSPICIOUS_EXTENSIONS: Set[str] = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".lock", ".cry",
    ".wncry", ".wcry", ".locky", ".cerber", ".ryk", ".conti", ".lockbit", ".pay",
}


@dataclass
class FileEvent:
    ts: float
    kind: str  # modified | renamed | suspicious_new
    path: str
    new_path: str = ""
    suspicious: bool = False


@dataclass
class FileBurst:
    directory: str
    events: List[FileEvent]
    changed: int
    suspicious: int
    extensions: List[str]
    first_ts: float
    last_ts: float
    window_sec: float
    reasons: List[str] = field(default_factory=list)


def _suffix(name: str) -> str:
    return os.path.splitext(name)[1].lower()


class FileChangeDetector:
    """Periodic directory walk; compares names, mtime and size with the previous walk.

    Counted: content changes of existing files, renames, and new files with a
    ransomware-style extension. Plain creation and deletion are not counted.
    A burst is reported when, inside `window_sec`, more than `change_threshold`
    distinct files were changed or renamed, or at least `ext_threshold` files
    received a suspicious extension. No external dependencies.
    """

    def __init__(self, directory: Path, window_sec: float = 10.0, change_threshold: int = 8,
                 ext_threshold: int = 5, cooldown_sec: float = 120.0, max_entries: int = 5000,
                 settle_sec: float = 2.0) -> None:
        self.directory = Path(directory)
        self.window_sec, self.change_threshold = window_sec, change_threshold
        self.ext_threshold, self.cooldown_sec = ext_threshold, cooldown_sec
        self.max_entries, self.settle_sec = max_entries, settle_sec
        self.lock = threading.RLock()
        self._prev: Optional[Dict[str, Tuple[int, int]]] = None
        self._events: Deque[FileEvent] = deque()
        self._pending_since: Optional[float] = None
        self._cooldown_until = 0.0
        self.truncated = False
        self.last_scan = 0.0
        self.file_count = 0
        self.exists = False

    def _snapshot(self) -> Dict[str, Tuple[int, int]]:
        snap: Dict[str, Tuple[int, int]] = {}
        self.truncated = False
        self.exists = self.directory.is_dir()
        if not self.exists:
            return snap
        root = str(self.directory)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for name in filenames:
                if name.startswith("."):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                snap[rel] = (st.st_mtime_ns, st.st_size)
                if len(snap) >= self.max_entries:
                    self.truncated = True
                    return snap
        return snap

    @staticmethod
    def _diff(prev: Dict[str, Tuple[int, int]], cur: Dict[str, Tuple[int, int]], now: float) -> List[FileEvent]:
        events: List[FileEvent] = []
        gone = set(prev) - set(cur)
        new = set(cur) - set(prev)
        for path in sorted(set(prev) & set(cur)):
            if prev[path] != cur[path]:
                events.append(FileEvent(now, "modified", path))
        by_stem: Dict[str, str] = {os.path.splitext(g)[0]: g for g in gone}
        for path in sorted(new):
            ext = _suffix(path)
            base = os.path.splitext(path)[0]
            if base in gone:
                # "report.docx" -> "report.docx.locked": extension appended to an existing file.
                events.append(FileEvent(now, "renamed", base, path, True))
                gone.discard(base)
            elif base in by_stem and by_stem[base] in gone:
                # "report.docx" -> "report.locked": extension replaced.
                old = by_stem[base]
                events.append(FileEvent(now, "renamed", old, path, ext in SUSPICIOUS_EXTENSIONS))
                gone.discard(old)
            elif ext in SUSPICIOUS_EXTENSIONS:
                events.append(FileEvent(now, "suspicious_new", path, path, True))
        return events

    def scan(self, now: Optional[float] = None) -> Optional[FileBurst]:
        """Walk the folder once. Returns a FileBurst when the thresholds are exceeded."""
        current = time.time() if now is None else now
        with self.lock:
            snap = self._snapshot()
            self.last_scan, self.file_count = current, len(snap)
            if self._prev is None:
                self._prev = snap
                return None
            fresh = self._diff(self._prev, snap, current)
            self._prev = snap
            self._events.extend(fresh)
            while self._events and current - self._events[0].ts > self.window_sec:
                self._events.popleft()
            if current < self._cooldown_until:
                return None
            changed = {e.path for e in self._events}
            suspicious = {e.path for e in self._events if e.suspicious}
            reasons: List[str] = []
            if len(changed) > self.change_threshold:
                reasons.append("changes")
            if len(suspicious) >= self.ext_threshold:
                reasons.append("extensions")
            if not reasons:
                self._pending_since = None
                return None
            if self._pending_since is None:
                self._pending_since = current
            # Wait until the burst stops growing (or settle_sec passes) so that
            # the alert reports the full list of files.
            if fresh and current - self._pending_since < self.settle_sec:
                return None
            events = list(self._events)
            extensions = sorted({_suffix(e.new_path) for e in events if e.suspicious and e.new_path})
            burst = FileBurst(str(self.directory), events, len(changed), len(suspicious), extensions,
                              min(e.ts for e in events), max(e.ts for e in events), self.window_sec, reasons)
            self._events.clear()
            self._pending_since = None
            self._cooldown_until = current + self.cooldown_sec
            return burst

    def clear_cooldown(self) -> None:
        """Allow the next burst to be reported immediately (used before a demo attack)."""
        with self.lock:
            self._cooldown_until = 0.0
            self._events.clear()
            self._pending_since = None

    def reset(self) -> None:
        """Forget history and take a new baseline on the next scan."""
        with self.lock:
            self._prev = None
            self._events.clear()
            self._pending_since = None
            self._cooldown_until = 0.0

    def status(self) -> Dict[str, Any]:
        return {"directory": str(self.directory), "exists": self.exists, "files": self.file_count,
                "last_scan": self.last_scan, "truncated": self.truncated,
                "window_sec": self.window_sec, "change_threshold": self.change_threshold,
                "ext_threshold": self.ext_threshold}


# --------------------------------------------------------------------------
# Failed login detector
# --------------------------------------------------------------------------

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s")
_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\s")
_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
    r"(?:invalid user |illegal user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)")
_REPEATED = re.compile(r"message repeated (\d+) times")


@dataclass
class AuthFailure:
    ts: float
    ip: str
    user: str
    count: int = 1


@dataclass
class BruteForce:
    ip: str
    attempts: int
    users: List[str]
    first_ts: float
    last_ts: float
    window_sec: float
    log_path: str


def parse_log_time(line: str, now: float) -> float:
    """Timestamp of a log line: ISO 8601 or classic syslog. Falls back to `now`."""
    m = _ISO_TS.match(line)
    if m:
        try:
            base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
            frac = float(m.group(2)) if m.group(2) else 0.0
            zone = m.group(3)
            if zone and zone != "Z":
                sign = 1 if zone[0] == "+" else -1
                digits = zone[1:].replace(":", "")
                offset = sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
                epoch = (base - datetime(1970, 1, 1)).total_seconds() - offset
            elif zone == "Z":
                epoch = (base - datetime(1970, 1, 1)).total_seconds()
            else:
                epoch = time.mktime(base.timetuple())
            return epoch + frac
        except (ValueError, OverflowError):
            return now
    m = _SYSLOG_TS.match(line)
    if m and m.group(1) in _MONTHS:
        try:
            ref = datetime.fromtimestamp(now)
            stamp = datetime(ref.year, _MONTHS[m.group(1)], int(m.group(2)),
                             int(m.group(3)), int(m.group(4)), int(m.group(5)))
            if stamp - ref > timedelta(days=1):  # December line read in January
                stamp = stamp.replace(year=ref.year - 1)
            return time.mktime(stamp.timetuple())
        except (ValueError, OverflowError):
            return now
    return now


def parse_auth_line(line: str, now: float) -> Optional[AuthFailure]:
    """Parse one sshd line. Returns None unless it is a failed login with a valid IP."""
    m = _FAILED.search(line)
    if not m:
        return None
    try:
        ip = str(ipaddress.ip_address(m.group("ip")))
    except ValueError:
        return None
    rep = _REPEATED.search(line)
    count = min(int(rep.group(1)), 1000) if rep else 1
    return AuthFailure(parse_log_time(line, now), ip, m.group("user")[:64], count)


class AuthLogDetector:
    """Counts failed logins per IP inside a sliding time window."""

    MAX_READ = 1024 * 1024

    def __init__(self, path: Path, window_sec: float = 120.0, threshold: int = 10,
                 cooldown_sec: float = 600.0, from_start: bool = False) -> None:
        self.path = Path(path)
        self.window_sec, self.threshold, self.cooldown_sec = window_sec, threshold, cooldown_sec
        self.lock = threading.RLock()
        self._failures: Dict[str, Deque[Tuple[float, str]]] = {}
        self._cooldown: Dict[str, float] = {}
        self._tail = b""
        self.lines_read = 0
        self.failures_seen = 0
        self.error = ""
        self._offset = 0
        if not from_start:
            try:
                self._offset = self.path.stat().st_size
            except OSError:
                self._offset = 0

    def feed(self, lines: List[str], now: Optional[float] = None) -> List[BruteForce]:
        """Process log lines. Returns one finding per IP that crossed the threshold."""
        current = time.time() if now is None else now
        found: List[BruteForce] = []
        with self.lock:
            for line in lines:
                self.lines_read += 1
                failure = parse_auth_line(line, current)
                if failure is None:
                    continue
                self.failures_seen += failure.count
                series = self._failures.setdefault(failure.ip, deque(maxlen=5000))
                for _ in range(failure.count):
                    series.append((failure.ts, failure.user))
                newest = max(ts for ts, _ in series)
                while series and newest - series[0][0] > self.window_sec:
                    series.popleft()
                if len(series) < self.threshold or current < self._cooldown.get(failure.ip, 0.0):
                    continue
                users = sorted({user for _, user in series})
                found.append(BruteForce(failure.ip, len(series), users[:5], series[0][0], newest,
                                        self.window_sec, str(self.path)))
                self._cooldown[failure.ip] = current + self.cooldown_sec
                series.clear()
            if len(self._failures) > 2000:  # bound memory under address spraying
                for ip in [ip for ip, s in self._failures.items() if not s]:
                    del self._failures[ip]
        return found

    def poll(self, now: Optional[float] = None) -> List[BruteForce]:
        """Read lines appended to the log since the previous call."""
        with self.lock:
            try:
                size = self.path.stat().st_size
            except OSError:
                self.error = "журнал пока не создан"
                self._offset, self._tail = 0, b""
                return []
            if size < self._offset:  # truncated or rotated
                self._offset, self._tail = 0, b""
            if size == self._offset:
                self.error = ""
                return []
            try:
                with open(str(self.path), "rb") as fh:
                    fh.seek(self._offset)
                    chunk = fh.read(self.MAX_READ)
            except OSError as exc:
                self.error = "нет доступа к журналу: %s" % exc.__class__.__name__
                return []
            self.error = ""
            self._offset += len(chunk)
            data = self._tail + chunk
            parts = data.split(b"\n")
            self._tail = parts.pop()[-4096:]
            lines = [p.decode("utf-8", "replace") for p in parts if p.strip()]
            return self.feed(lines, now)

    def clear_cooldown(self) -> None:
        with self.lock:
            self._cooldown.clear()
            self._failures.clear()

    def reset(self) -> None:
        with self.lock:
            self._failures.clear()
            self._cooldown.clear()
            self._tail = b""
            try:
                self._offset = self.path.stat().st_size
            except OSError:
                self._offset = 0

    def status(self) -> Dict[str, Any]:
        return {"path": str(self.path), "exists": self.path.is_file(), "lines_read": self.lines_read,
                "failures_seen": self.failures_seen, "error": self.error,
                "window_sec": self.window_sec, "threshold": self.threshold}
