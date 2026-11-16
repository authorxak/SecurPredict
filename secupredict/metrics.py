"""Metric sources: the local machine (real) and simulated fleet hosts."""
from __future__ import annotations

import os
import random
import re
import shutil
import time
import zlib
from collections import deque
from typing import Deque, Dict, Optional, Tuple

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    psutil = None

METRIC_KEYS: Tuple[str, ...] = ("cpu", "ram", "disk", "net_in", "net_out", "io")
PERCENT_KEYS: Tuple[str, ...] = ("cpu", "ram", "disk")


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


class LocalMetrics:
    """Real metrics of this computer: psutil when installed, /proc on Linux otherwise."""

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

    @property
    def source(self) -> str:
        """Where CPU and memory numbers come from: psutil, procfs or none."""
        if psutil:
            return "psutil"
        if os.path.exists("/proc/stat"):
            return "procfs"
        return "none"

    def _cpu(self) -> float:
        if psutil:
            return float(psutil.cpu_percent(None))
        try:
            with open("/proc/stat") as fh:
                vals = list(map(int, fh.readline().split()[1:]))
        except (OSError, ValueError):
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
            info: Dict[str, int] = {}
            with open("/proc/meminfo") as fh:
                for line in fh:
                    key, value = line.split(":", 1)
                    info[key] = int(value.split()[0])
            return 100.0 * (1 - info["MemAvailable"] / info["MemTotal"])
        except (OSError, KeyError, ValueError, ZeroDivisionError):
            return 0.0

    def _disk(self) -> float:
        try:
            usage = shutil.disk_usage(self.disk_root)
            return 100.0 * usage.used / usage.total
        except (OSError, ZeroDivisionError):
            return 0.0

    def _counters(self) -> Dict[str, float]:
        """Cumulative byte counters: network in/out and disk read+write."""
        out: Dict[str, float] = {}
        if psutil:
            net = psutil.net_io_counters()
            out["net_in"], out["net_out"] = net.bytes_recv, net.bytes_sent
            try:
                disk = psutil.disk_io_counters()
                if disk:
                    out["io"] = disk.read_bytes + disk.write_bytes
            except Exception:  # noqa: BLE001 - platform specific failures
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
        except (OSError, ValueError, IndexError):
            pass
        try:
            sectors = 0
            with open("/proc/diskstats") as fh:
                for line in fh:
                    cols = line.split()
                    if len(cols) > 9 and self._DISK_RE.match(cols[2]):
                        sectors += int(cols[5]) + int(cols[9])
            out["io"] = sectors * 512
        except (OSError, ValueError):
            pass
        return out

    def sample(self) -> Dict[str, float]:
        """One snapshot: percentages and rates in KB/s."""
        now = time.time()
        result = {"cpu": self._cpu(), "ram": self._ram(), "disk": self._disk(),
                  "net_in": 0.0, "net_out": 0.0, "io": 0.0}
        for key, value in self._counters().items():
            prev = self._prev.get(key)
            self._prev[key] = (now, value)
            if prev and now > prev[0] and value >= prev[1]:
                result[key] = (value - prev[1]) / (now - prev[0]) / 1024
        return {k: round(v, 1) for k, v in result.items()}


def stable_seed(text: str) -> int:
    """Seed that is identical across runs and Python versions."""
    return zlib.crc32(text.encode("utf-8")) & 0xFFFFFFFF


class Host:
    """A device on the dashboard.

    kind: "local" (this computer), "agent" (another real computer that pushes
    metrics through /api/ingest) or "simulated" (demo fleet).
    """

    def __init__(self, host_id: str, name: str, role: str, history: int, kind: str = "simulated",
                 base: Optional[Tuple[float, ...]] = None, seed: Optional[int] = None) -> None:
        self.id, self.name, self.role, self.kind = host_id, name, role, kind
        self.base = dict(zip(("cpu", "ram", "disk", "net", "io"), base or (0, 0, 0, 0, 0)))
        self.isolated = False  # only ever set by the simulated scenario
        self.last_seen = time.time()
        self._seed = seed
        self._rng = random.Random(seed)
        self._overrides: Dict[str, float] = {}
        self._override_until = 0.0
        self.latest: Dict[str, float] = {}
        self.history: Dict[str, Deque[float]] = {m: deque(maxlen=history) for m in METRIC_KEYS}
        if kind == "simulated":
            self._to_base()

    @property
    def real(self) -> bool:
        return self.kind in ("local", "agent")

    def _to_base(self) -> None:
        b = self.base
        self.latest = {"cpu": b["cpu"], "ram": b["ram"], "disk": b["disk"],
                       "net_in": b["net"], "net_out": b["net"] * 0.6, "io": b["io"]}

    def set_override(self, seconds: float, **targets: float) -> None:
        """Temporarily shift the baseline of a simulated host (used by the scenario)."""
        self._overrides.update(targets)
        self._override_until = time.time() + seconds

    def reset(self) -> None:
        """Return a simulated host to its initial state and reseed its generator."""
        self.isolated = False
        self._overrides.clear()
        self._rng = random.Random(self._seed)
        for series in self.history.values():
            series.clear()
        if self.kind == "simulated":
            self._to_base()

    def simulate(self) -> Dict[str, float]:
        """Random walk around the baseline of a simulated host."""
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
        new: Dict[str, float] = {}
        for key, target in targets.items():
            speed = 0.5 if key in o else 0.3
            value = cur.get(key, target) + (target - cur.get(key, target)) * speed + self._rng.gauss(0, noise[key])
            new[key] = clamp(value, 0, 100 if key in PERCENT_KEYS else 10 ** 7)
        if self.isolated:
            new["net_in"] = new["net_out"] = 0.0
        return {k: round(v, 1) for k, v in new.items()}

    def push(self, sample: Dict[str, float]) -> None:
        self.latest = sample
        self.last_seen = time.time()
        for key in METRIC_KEYS:
            self.history[key].append(sample.get(key, 0.0))
