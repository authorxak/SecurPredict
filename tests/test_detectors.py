"""Detector tests on synthetic data: thresholds, time windows, deduplication, statistics."""
import os
import random

from secupredict.detectors import (AuthLogDetector, FileChangeDetector, StatAnomalyDetector, ThresholdRules,
                                   parse_auth_line, parse_log_time)

T0 = 1_800_000_000.0


# Threshold rules ------------------------------------------------------------

def test_threshold_needs_sustained_time():
    rules = ThresholdRules({"cpu": 90.0}, sustain_sec=20.0)
    assert rules.check("h", {"cpu": 95.0}, now=T0) == []
    assert rules.check("h", {"cpu": 95.0}, now=T0 + 19) == []
    hits = rules.check("h", {"cpu": 96.0}, now=T0 + 20)
    assert len(hits) == 1 and hits[0].metric == "cpu" and hits[0].value == 96.0


def test_threshold_resets_when_value_drops():
    rules = ThresholdRules({"cpu": 90.0}, sustain_sec=20.0)
    rules.check("h", {"cpu": 95.0}, now=T0)
    rules.check("h", {"cpu": 50.0}, now=T0 + 10)  # short spike ends
    assert rules.check("h", {"cpu": 95.0}, now=T0 + 21) == []
    assert rules.check("h", {"cpu": 95.0}, now=T0 + 41) != []


def test_threshold_is_per_host_and_boundary_inclusive():
    rules = ThresholdRules({"ram": 92.0}, sustain_sec=5.0)
    rules.check("a", {"ram": 92.0}, now=T0)  # exactly at the limit counts
    rules.check("b", {"ram": 10.0}, now=T0)
    assert [h.host_id for h in rules.check("a", {"ram": 92.0}, now=T0 + 5)] == ["a"]
    assert rules.check("b", {"ram": 10.0}, now=T0 + 5) == []


# Statistical detector -------------------------------------------------------

def _warm(det, host="h", metric="cpu", mean=20.0, noise=2.0, n=60, seed=1):
    rng = random.Random(seed)
    for _ in range(n):
        assert det.observe(host, metric, mean + rng.gauss(0, noise)) is None


def test_stat_no_alert_during_warmup():
    det = StatAnomalyDetector(min_samples=30)
    for _ in range(29):
        assert det.observe("h", "cpu", 99.0 if _ % 2 else 1.0) is None
    assert not det.ready("h", "cpu")


def test_stat_detects_sustained_deviation_once():
    det = StatAnomalyDetector(min_samples=30, sustain=3)
    _warm(det)
    assert det.observe("h", "cpu", 90.0) is None
    assert det.observe("h", "cpu", 91.0) is None
    anomaly = det.observe("h", "cpu", 92.0)
    assert anomaly is not None
    assert anomaly.zscore > 3 and 18 < anomaly.mean < 22 and anomaly.samples == 3
    assert det.observe("h", "cpu", 93.0) is None  # reported once per episode


def test_stat_ignores_single_spike_and_small_shift():
    det = StatAnomalyDetector(min_samples=30, sustain=3, min_delta=8.0)
    _warm(det, noise=0.2)  # very stable host
    assert det.observe("h", "cpu", 95.0) is None  # one spike
    assert det.observe("h", "cpu", 20.0) is None
    for _ in range(10):  # +4 points is many sigmas for this host, but below min_delta
        assert det.observe("h", "cpu", 24.0) is None


def test_stat_respects_each_hosts_usual_level():
    det = StatAnomalyDetector(min_samples=30, sustain=3)
    _warm(det, host="busy", mean=85.0, noise=4.0)
    _warm(det, host="idle", mean=10.0, noise=4.0)
    busy = [det.observe("busy", "cpu", 90.0) for _ in range(5)]
    idle = [det.observe("idle", "cpu", 90.0) for _ in range(5)]
    assert all(x is None for x in busy)  # 90% is normal for the busy server
    assert any(x is not None for x in idle)  # and an anomaly for the idle one
    assert det.is_usual("busy", "cpu", 90.0) and not det.is_usual("idle", "cpu", 90.0)


def test_stat_does_not_report_drops():
    det = StatAnomalyDetector(min_samples=30, sustain=3)
    _warm(det, mean=60.0)
    assert all(det.observe("h", "cpu", 5.0) is None for _ in range(10))


def test_stat_no_false_alarms_on_stationary_noise():
    det = StatAnomalyDetector(min_samples=30, sustain=3)
    rng = random.Random(7)
    assert all(det.observe("h", "cpu", 30 + rng.gauss(0, 5)) is None for _ in range(5000))


# File change detector -------------------------------------------------------

def _make(directory, count, ext=".docx"):
    names = ["doc_%02d%s" % (i, ext) for i in range(count)]
    for name in names:
        (directory / name).write_text("original", encoding="utf-8")
    return names


def _encrypt(directory, names):
    for name in names:
        (directory / name).write_text("overwritten", encoding="utf-8")
        os.replace(str(directory / name), str(directory / (name + ".locked")))


def test_files_baseline_and_plain_creation_are_silent(tmp_path):
    det = FileChangeDetector(tmp_path, change_threshold=3, ext_threshold=3)
    assert det.scan(now=T0) is None
    _make(tmp_path, 20)
    assert det.scan(now=T0 + 1) is None
    assert det.scan(now=T0 + 2) is None


def test_files_mass_rename_triggers_with_real_names(tmp_path):
    names = _make(tmp_path, 12)
    det = FileChangeDetector(tmp_path, window_sec=10, change_threshold=8, ext_threshold=5)
    det.scan(now=T0)
    _encrypt(tmp_path, names)
    first = det.scan(now=T0 + 1)  # threshold crossed, detector waits for the burst to settle
    burst = first or det.scan(now=T0 + 2)
    assert burst is not None
    assert burst.changed == 12 and burst.suspicious == 12
    assert burst.extensions == [".locked"]
    assert {e.path for e in burst.events} == set(names)
    assert all(e.new_path.endswith(".locked") for e in burst.events)


def test_files_below_threshold_is_silent(tmp_path):
    names = _make(tmp_path, 12)
    det = FileChangeDetector(tmp_path, window_sec=10, change_threshold=8, ext_threshold=5)
    det.scan(now=T0)
    for name in names[:4]:  # ordinary work: a few edits
        (tmp_path / name).write_text("edited by user", encoding="utf-8")
    assert det.scan(now=T0 + 1) is None
    assert det.scan(now=T0 + 2) is None


def test_files_content_changes_alone_trigger(tmp_path):
    names = _make(tmp_path, 12)
    det = FileChangeDetector(tmp_path, window_sec=10, change_threshold=8, ext_threshold=5)
    det.scan(now=T0)
    for name in names:
        (tmp_path / name).write_text("changed content, longer than before", encoding="utf-8")
    burst = det.scan(now=T0 + 1) or det.scan(now=T0 + 2)
    assert burst is not None and burst.changed == 12 and burst.suspicious == 0
    assert burst.reasons == ["changes"]


def test_files_time_window(tmp_path):
    names = _make(tmp_path, 12)
    det = FileChangeDetector(tmp_path, window_sec=10, change_threshold=8, ext_threshold=50)
    det.scan(now=T0)
    for i, name in enumerate(names):  # one file every 5 seconds: slow, never 9 inside 10 s
        (tmp_path / name).write_text("slow change %d ........" % i, encoding="utf-8")
        assert det.scan(now=T0 + 5 * (i + 1)) is None


def test_files_deduplication_by_cooldown(tmp_path):
    names = _make(tmp_path, 30)
    det = FileChangeDetector(tmp_path, window_sec=10, change_threshold=8, ext_threshold=5, cooldown_sec=60)
    det.scan(now=T0)
    _encrypt(tmp_path, names[:15])
    assert (det.scan(now=T0 + 1) or det.scan(now=T0 + 2)) is not None
    _encrypt(tmp_path, names[15:])  # the same attack continues
    assert det.scan(now=T0 + 3) is None
    assert det.scan(now=T0 + 4) is None


def test_files_hidden_files_and_missing_dir(tmp_path):
    det = FileChangeDetector(tmp_path / "absent")
    assert det.scan(now=T0) is None and det.status()["exists"] is False
    det2 = FileChangeDetector(tmp_path, change_threshold=1, ext_threshold=1)
    det2.scan(now=T0)
    for i in range(5):
        (tmp_path / (".hidden%d.locked" % i)).write_text("x", encoding="utf-8")
    assert det2.scan(now=T0 + 1) is None


# Failed login detector ------------------------------------------------------

def _line(second, ip="203.0.113.45", user="admin", minute=0):
    return "Nov 15 21:%02d:%02d demo-host sshd[4000]: Failed password for %s from %s port 40000 ssh2" % (
        minute, second, user, ip)


def test_auth_parse_formats():
    f = parse_auth_line(_line(1), T0)
    assert f and f.ip == "203.0.113.45" and f.user == "admin"
    f = parse_auth_line("2026-11-15T21:00:01.123456+05:00 srv sshd[1]: Failed password for invalid user "
                        "bob from 2001:db8::7 port 1 ssh2", T0)
    assert f and f.ip == "2001:db8::7" and f.user == "bob"
    assert parse_auth_line("Nov 15 21:00:01 srv sshd[1]: Accepted password for admin from 203.0.113.45", T0) is None
    assert parse_auth_line("Nov 15 21:00:01 srv sshd[1]: Failed password for x from not-an-ip port 1", T0) is None
    rep = parse_auth_line("Nov 15 21:00:01 srv sshd[1]: message repeated 5 times: [ Failed password for root "
                          "from 203.0.113.9 port 1 ssh2]", T0)
    assert rep and rep.count == 5


def test_auth_iso_time_with_zone_is_exact():
    a = parse_log_time("2026-11-15T21:00:00+05:00 host x", T0)
    b = parse_log_time("2026-11-15T16:00:10Z host x", T0)
    assert b - a == 10


def test_auth_threshold_and_real_values(tmp_path):
    det = AuthLogDetector(tmp_path / "auth.log", window_sec=120, threshold=10, from_start=True)
    assert det.feed([_line(i) for i in range(9)], now=T0) == []
    found = det.feed([_line(9, user="root")], now=T0)
    assert len(found) == 1
    assert found[0].ip == "203.0.113.45" and found[0].attempts == 10
    assert found[0].users == ["admin", "root"]


def test_auth_counts_per_ip(tmp_path):
    det = AuthLogDetector(tmp_path / "auth.log", threshold=10, from_start=True)
    lines = [_line(i, ip="198.51.100.%d" % i) for i in range(30)]  # 30 addresses, one attempt each
    assert det.feed(lines, now=T0) == []


def test_auth_time_window(tmp_path):
    det = AuthLogDetector(tmp_path / "auth.log", window_sec=120, threshold=10, from_start=True)
    slow = [_line(0, minute=m) for m in range(0, 40, 2)]  # one attempt every 2 minutes
    assert det.feed(slow, now=T0) == []
    fast = [_line(s, minute=50) for s in range(10)]  # ten attempts in ten seconds
    assert len(det.feed(fast, now=T0)) == 1


def test_auth_deduplication_by_cooldown(tmp_path):
    det = AuthLogDetector(tmp_path / "auth.log", threshold=5, cooldown_sec=600, from_start=True)
    assert len(det.feed([_line(i) for i in range(5)], now=T0)) == 1
    assert det.feed([_line(i) for i in range(5, 30)], now=T0 + 10) == []  # same IP, still in cooldown
    assert len(det.feed([_line(i, ip="198.51.100.9") for i in range(5)], now=T0 + 10)) == 1  # other IP
    assert len(det.feed([_line(i, minute=30) for i in range(5)], now=T0 + 700)) == 1  # cooldown over


def test_auth_poll_reads_only_new_lines_and_survives_truncation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(_line(i) for i in range(20)) + "\n", encoding="utf-8")
    det = AuthLogDetector(log, threshold=10)  # starts at the end: old lines are ignored
    assert det.poll(now=T0) == []
    with open(str(log), "a", encoding="utf-8") as fh:
        fh.write("\n".join(_line(i, minute=5) for i in range(10)) + "\n")
    assert len(det.poll(now=T0)) == 1
    log.write_text(_line(0, ip="198.51.100.1", minute=9) + "\n", encoding="utf-8")  # rotated
    assert det.poll(now=T0) == [] and det.lines_read == 11
