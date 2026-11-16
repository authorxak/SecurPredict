#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safe attack simulation for the live demo. Standard library only.

What it does, and nothing else:
  1. creates decoy files in its own folder (default ./demo_files);
  2. "encrypts" them: overwrites each decoy with harmless text and renames it
     to <name>.locked;
  3. appends a series of failed logins to its own test log
     (default ./demo_logs/auth.log);
  4. keeps the .locked decoys open for --hold seconds, so the monitor's
     response module has a real process to describe (dry-run) or terminate
     (--enforce).

Safety rules:
  - the folder must be absent, empty or already marked with the sentinel file
    written by this script; any other folder is refused;
  - the log must be absent, empty or start with this script's header line;
  - only files created by this script (listed in the sentinel) are touched.

Usage:
  python tools/simulate_attack.py              # all steps
  python tools/simulate_attack.py prepare      # only create decoys
  python tools/simulate_attack.py encrypt      # only the file part
  python tools/simulate_attack.py bruteforce   # only the failed logins
  python tools/simulate_attack.py cleanup      # remove decoys, reset the log
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import IO, List, NoReturn, Optional

SENTINEL = ".secupredict_demo_dir"
MARKER = ".secupredict_sim.json"
LOG_HEADER = "# secupredict demo auth log"
LOCKED_EXT = ".locked"
DECOY_NAMES = ("patient_card", "invoice", "contract", "price_list", "orders")
DECOY_EXTS = (".docx", ".xlsx", ".pdf", ".txt")
HARMLESS = ("This decoy file was overwritten by the SecuPredict attack simulation.\n"
            "No real data was touched.\n")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
USERS = ("admin", "root", "administrator", "user", "test")


def fail(message: str) -> NoReturn:
    print("simulate_attack: " + message, file=sys.stderr)
    sys.exit(2)


def check_dir(directory: Path) -> None:
    """Refuse any folder that is not ours."""
    if directory.exists():
        if not directory.is_dir():
            fail("%s is not a folder" % directory)
        if not (directory / SENTINEL).is_file() and any(directory.iterdir()):
            fail("%s is not empty and was not created by this script; refusing to touch it" % directory)


def check_log(path: Path) -> None:
    """Refuse any log file that is not ours."""
    if path.exists():
        with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
        if first and not first.startswith(LOG_HEADER):
            fail("%s is not a demo log created by this script; refusing to write to it" % path)


def decoy_names(count: int) -> List[str]:
    names = []
    for i in range(count):
        base = DECOY_NAMES[i % len(DECOY_NAMES)]
        names.append("%s_%02d%s" % (base, i + 1, DECOY_EXTS[i % len(DECOY_EXTS)]))
    return names


def read_sentinel(directory: Path) -> List[str]:
    try:
        data = json.loads((directory / SENTINEL).read_text(encoding="utf-8"))
        return [str(n) for n in data.get("files", []) if "/" not in str(n) and "\\" not in str(n)]
    except (OSError, ValueError):
        return []


def remove_decoys(directory: Path) -> int:
    """Delete only files listed in the sentinel (plain and .locked variants)."""
    removed = 0
    for name in read_sentinel(directory):
        for candidate in (directory / name, directory / (name + LOCKED_EXT)):
            if candidate.is_file():
                candidate.unlink()
                removed += 1
    marker = directory / MARKER
    if marker.is_file():
        marker.unlink()
    return removed


def prepare(directory: Path, count: int) -> List[str]:
    check_dir(directory)
    directory.mkdir(parents=True, exist_ok=True)
    remove_decoys(directory)
    names = decoy_names(count)
    (directory / SENTINEL).write_text(json.dumps({"tool": "simulate_attack", "files": names}), encoding="utf-8")
    for name in names:
        (directory / name).write_text("SecuPredict decoy file %s. Contains no real data.\n" % name,
                                      encoding="utf-8")
    print("prepare: %d decoy files in %s" % (len(names), directory))
    return names


def encrypt(directory: Path, delay: float) -> List[IO[str]]:
    """Overwrite and rename decoys. Returns open handles to the .locked files."""
    check_dir(directory)
    names = read_sentinel(directory)
    if not names:
        fail("no decoys in %s; run 'prepare' first" % directory)
    (directory / MARKER).write_text(json.dumps({"pid": os.getpid(), "tool": "simulate_attack",
                                                "started": time.time()}), encoding="utf-8")
    handles: List[IO[str]] = []
    done = 0
    for name in names:
        source = directory / name
        if not source.is_file():
            continue
        source.write_text(HARMLESS, encoding="utf-8")
        target = directory / (name + LOCKED_EXT)
        os.replace(str(source), str(target))
        handles.append(open(str(target), "r", encoding="utf-8"))
        done += 1
        time.sleep(delay)
    print("encrypt: %d decoys renamed to *%s" % (done, LOCKED_EXT))
    return handles


def bruteforce(log_path: Path, attempts: int, ip: str, delay: float) -> None:
    """Append sshd-style failed logins with current timestamps."""
    check_log(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists() or log_path.stat().st_size == 0:
        log_path.write_text(LOG_HEADER + " (written by tools/simulate_attack.py)\n", encoding="utf-8")
    for i in range(attempts):
        now = datetime.now()
        line = "%s %2d %s demo-host sshd[%d]: Failed password for %s from %s port %d ssh2\n" % (
            MONTHS[now.month - 1], now.day, now.strftime("%H:%M:%S"), 4000 + i,
            USERS[i % len(USERS)], ip, 40000 + i)
        with open(str(log_path), "a", encoding="utf-8") as fh:
            fh.write(line)
        time.sleep(delay)
    print("bruteforce: %d failed logins from %s appended to %s" % (attempts, ip, log_path))


def cleanup(directory: Path, log_path: Path) -> None:
    check_dir(directory)
    if directory.is_dir():
        removed = remove_decoys(directory)
        print("cleanup: removed %d decoy files from %s" % (removed, directory))
    check_log(log_path)
    if log_path.exists():
        log_path.write_text(LOG_HEADER + " (written by tools/simulate_attack.py)\n", encoding="utf-8")
        print("cleanup: %s reset" % log_path)


def hold(directory: Path, handles: List[IO[str]], seconds: float) -> None:
    """Stay alive with the decoys open, then release them."""
    try:
        if seconds > 0 and handles:
            print("hold: keeping %d decoys open for %.0f s (pid %d)" % (len(handles), seconds, os.getpid()))
            time.sleep(seconds)
    finally:
        for handle in handles:
            handle.close()
        marker = directory / MARKER
        if marker.is_file():
            marker.unlink()


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Safe attack simulation for the SecuPredict demo")
    p.add_argument("command", nargs="?", default="all",
                   choices=("all", "prepare", "encrypt", "bruteforce", "cleanup"))
    p.add_argument("--files-dir", default="demo_files", help="decoy folder (default ./demo_files)")
    p.add_argument("--log", default=os.path.join("demo_logs", "auth.log"), help="test log file")
    p.add_argument("--count", type=int, default=20, help="number of decoy files")
    p.add_argument("--attempts", type=int, default=25, help="number of failed logins")
    p.add_argument("--ip", default="203.0.113.45", help="source address (documentation range by default)")
    p.add_argument("--hold", type=float, default=25.0, help="seconds to keep the decoys open afterwards")
    p.add_argument("--settle", type=float, default=3.0,
                   help="pause after 'prepare' so the monitor records the decoys before they change")
    a = p.parse_args(argv)
    directory, log_path = Path(a.files_dir), Path(a.log)
    count = max(1, min(a.count, 200))
    attempts = max(1, min(a.attempts, 500))

    if a.command == "prepare":
        prepare(directory, count)
    elif a.command == "encrypt":
        hold(directory, encrypt(directory, 0.1), a.hold)
    elif a.command == "bruteforce":
        bruteforce(log_path, attempts, a.ip, 0.1)
    elif a.command == "cleanup":
        cleanup(directory, log_path)
    else:
        check_log(log_path)
        prepare(directory, count)
        time.sleep(max(0.0, a.settle))
        handles = encrypt(directory, 0.1)
        try:
            bruteforce(log_path, attempts, a.ip, 0.1)
        finally:
            hold(directory, handles, a.hold)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
