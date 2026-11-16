"""Integration tests: alert pipeline, response journal, storage, Telegram buttons, web security."""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from secupredict.alerts import Alert, AlertManager
from secupredict.app import App, build_parser, config_from_args, demo_dir_is_safe
from secupredict.config import Config, load_dotenv
from secupredict.report import build_report
from secupredict.response import Responder
from secupredict.storage import Storage
from secupredict.telegram import TelegramBot, alert_keyboard, parse_callback
from secupredict.web import make_handler

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "simulate_attack.py"


class FakeMetrics:
    source = "fake"

    def __init__(self):
        self.value = {"cpu": 10.0, "ram": 40.0, "disk": 50.0, "net_in": 1.0, "net_out": 1.0, "io": 1.0}

    def sample(self):
        return dict(self.value)


@pytest.fixture
def app(tmp_path):
    cfg = Config(data_dir=tmp_path, demo=True, scenario=False, stat_min_samples=20, sustain_sec=0.0)
    application = App(cfg, local=FakeMetrics())
    yield application
    application.shutdown()
    application.storage.close()


def tool(*args, cwd):
    return subprocess.run([sys.executable, str(TOOL)] + list(args), cwd=str(cwd),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)


# Alerts and storage ---------------------------------------------------------

def test_alert_dedup_and_status(tmp_path):
    storage = Storage(":memory:")
    alerts = AlertManager(storage, lambda h: h, tmp_path / "alerts.jsonl")
    a = alerts.raise_alert("medium", "h1", "t", "w", "d", ["s"], kind="cpu")
    assert alerts.recent("h1", "cpu", 600) and not alerts.recent("h1", "ram", 600)
    assert not alerts.recent("h2", "cpu", 600)
    assert not alerts.recent("h1", "cpu", 600, now=a.ts + 601)
    assert alerts.set_status(a.id, "ours", "dashboard")
    assert not alerts.set_status("00000000", "ack", "x") and not alerts.set_status(a.id, "bogus", "x")
    stored = storage.alerts_between(0, time.time() + 1)
    assert stored[0]["status"] == "ours" and stored[0]["steps"] == ["s"]
    line = json.loads((tmp_path / "alerts.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert line["id"] == a.id and line["source"] == "rule"  # 0.2.0 field kept


def test_metrics_retention():
    storage = Storage(":memory:")
    now = time.time()
    storage.insert_metrics([(now - 7200, "h", "real", 1, 1, 1, 1, 1, 1), (now, "h", "real", 2, 2, 2, 2, 2, 2)])
    assert storage.prune_metrics(now - 3600) == 1 and storage.metrics_count() == 1


def test_dotenv_does_not_override_environment(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('# comment\nSP_TEST_A="from file"\nSP_TEST_B=file\n', encoding="utf-8")
    monkeypatch.setenv("SP_TEST_B", "from env")
    monkeypatch.delenv("SP_TEST_A", raising=False)
    load_dotenv(env)
    assert os.environ["SP_TEST_A"] == "from file" and os.environ["SP_TEST_B"] == "from env"


def test_old_cli_flags_still_parse():
    args = build_parser().parse_args(["--profile", "online_shop", "--host", "127.0.0.1", "--port", "8081",
                                      "--no-scenario", "--loop", "--tg-min", "high", "--no-telegram",
                                      "--no-browser", "--data-dir", ".", "-v"])
    cfg = config_from_args(args)
    assert cfg.profile == "online_shop" and cfg.port == 8081 and not cfg.scenario and cfg.tg_token == ""


def test_no_secret_in_source():
    for path in list(ROOT.glob("*.py")) + list((ROOT / "secupredict").glob("*.py")) + [TOOL]:
        text = path.read_text(encoding="utf-8")
        assert "AAF9" not in text and "DEFAULT_TG_TOKEN" not in text, path


# Pipeline: real detectors -> alerts -> journal ------------------------------

def test_simulated_hosts_are_labelled(app):
    state = app.state()
    kinds = {h["id"]: h["real"] for h in state["hosts"]}
    assert kinds["local"] is True and sum(1 for real in kinds.values() if not real) == 5
    app.scenario._suspicious_login()
    alert = app.alerts.snapshot()[0]
    assert alert["origin"] == "simulated" and "СИМУЛЯЦИЯ" in alert["did"]


def test_stat_anomaly_on_local_host_is_real_and_deduplicated(app):
    for _ in range(25):
        app.sample_once()
    assert app.alerts.snapshot() == []
    app.local.value["cpu"] = 75.0
    for _ in range(6):
        app.sample_once()
    real = [a for a in app.alerts.snapshot() if a["host_id"] == "local"]
    assert len(real) == 1  # threshold and anomaly do not duplicate each other
    assert real[0]["detector"] == "stat" and real[0]["origin"] == "real" and "обычных" in real[0]["what"]


def test_threshold_on_usually_busy_host_is_downgraded(app):
    app.local.value["cpu"] = 95.0
    app.rules.sustain_sec = 1e9  # let the baseline learn first
    for _ in range(25):
        app.sample_once()
    app.rules.sustain_sec = 0.0
    app.sample_once()
    alerts = [a for a in app.alerts.snapshot() if a["host_id"] == "local"]
    assert len(alerts) == 1 and alerts[0]["detector"] == "threshold" and alerts[0]["severity"] == "low"


def test_attack_simulation_triggers_real_detectors_dry_run(app, tmp_path):
    app.poll_detectors()  # baseline of an empty state
    assert tool("prepare", "--files-dir", str(app.cfg.watch_dir), cwd=tmp_path).returncode == 0
    app.poll_detectors()
    assert tool("encrypt", "--hold", "0", "--files-dir", str(app.cfg.watch_dir), cwd=tmp_path).returncode == 0
    assert tool("bruteforce", "--log", str(app.cfg.auth_log), cwd=tmp_path).returncode == 0
    for _ in range(3):
        app.poll_detectors()
        time.sleep(0.05)
    by_kind = {a["kind"]: a for a in app.alerts.snapshot()}
    ransom, brute = by_kind["ransomware"], by_kind["bruteforce"]
    assert ransom["severity"] == "critical" and ransom["origin"] == "real" and ransom["staged"] is True
    assert "contract_03.pdf -> contract_03.pdf.locked" in ransom["what"] and ".locked" in ransom["what"]
    assert brute["severity"] == "high" and "203.0.113.45" in brute["what"] and "10 неудачных" in brute["what"]
    assert "dry-run" in brute["did"] and "не заблокирован" in brute["did"]
    actions = app.storage.actions_between(0, time.time() + 1)
    assert {x["action"] for x in actions} == {"terminate_process", "block_ip"}
    assert all(x["mode"] == "dry-run" and x["result"] != "done" for x in actions)
    assert all(x["alert_id"] in (ransom["id"], brute["id"]) and x["reason"] for x in actions)
    report = build_report(app.storage, app.cfg, "Test", 1)
    assert "не является юридическим заключением" in report and "203.0.113.45" in report


def test_enforce_terminates_only_the_simulator(tmp_path):
    storage = Storage(":memory:")
    decoys = tmp_path / "demo_files"
    assert tool("prepare", "--files-dir", str(decoys), cwd=tmp_path).returncode == 0
    proc = subprocess.Popen([sys.executable, str(TOOL), "encrypt", "--hold", "30", "--files-dir", str(decoys)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 10
        while len(list(decoys.glob("*.locked"))) < 20 and time.time() < deadline:
            time.sleep(0.1)
        dry = Responder(storage, enforce=False).handle_file_burst("a1", str(decoys), "test")
        assert dry[0].result == "described" and proc.poll() is None
        done = Responder(storage, enforce=True).handle_file_burst("a2", str(decoys), "test")
        assert done[0].result == "done" and done[0].mode == "enforce"
        proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            proc.kill()
    # A marker that points at a process which is not the simulator is refused.
    (decoys / ".secupredict_sim.json").write_text(json.dumps({"pid": os.getppid()}), encoding="utf-8")
    refused = Responder(storage, enforce=True).handle_file_burst("a3", str(decoys), "test")
    assert refused[0].result == "not_found"


def test_block_ip_refuses_lan_and_needs_admin():
    storage = Storage(":memory:")
    enforce = Responder(storage, enforce=True)
    assert enforce.handle_bruteforce("a", "192.168.1.5", "t")[0].result == "refused"
    assert enforce.handle_bruteforce("a", "127.0.0.1", "t")[0].result == "refused"
    assert enforce.handle_bruteforce("a", "not an ip; rm -rf", "t")[0].result == "refused"
    assert Responder(storage).handle_bruteforce("a", "203.0.113.45", "t")[0].result == "described"
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        result = enforce.handle_bruteforce("a", "203.0.113.45", "t")[0]
        assert result.result == "refused" and "не заблокирован" in result.detail


def test_simulator_refuses_foreign_folder_and_log(tmp_path):
    foreign = tmp_path / "documents"
    foreign.mkdir()
    (foreign / "thesis.docx").write_text("important", encoding="utf-8")
    assert not demo_dir_is_safe(foreign)
    assert tool("all", "--hold", "0", "--settle", "0", "--files-dir", str(foreign), cwd=tmp_path).returncode == 2
    assert tool("cleanup", "--files-dir", str(foreign), cwd=tmp_path).returncode == 2
    assert (foreign / "thesis.docx").read_text(encoding="utf-8") == "important"
    real_log = tmp_path / "real.log"
    real_log.write_text("Nov 15 10:00:00 host sshd[1]: session opened\n", encoding="utf-8")
    assert tool("bruteforce", "--log", str(real_log), cwd=tmp_path).returncode == 2
    assert real_log.read_text(encoding="utf-8").count("\n") == 1


def test_demo_scenario_is_deterministic(tmp_path):
    def run(folder):
        folder.mkdir()
        application = App(Config(data_dir=folder, demo=True, scenario=False), local=FakeMetrics())
        series = [h.simulate() for h in application.hosts.values() if h.kind == "simulated" for _ in range(50)]
        application.shutdown()
        application.storage.close()
        return series
    assert run(tmp_path / "a") == run(tmp_path / "b")


# Telegram -------------------------------------------------------------------

def _alert(severity="critical"):
    return Alert(severity, "local", "pc", "Title", "what", "did", ["step"], origin="real")


def test_telegram_keyboard_only_for_critical_and_no_emoji():
    alert = _alert()
    markup = alert_keyboard(alert)
    assert [b["text"] for b in markup["inline_keyboard"][0]] == ["Принять", "Это мы"]
    assert markup["inline_keyboard"][0][0]["callback_data"] == "ack:" + alert.id
    assert alert_keyboard(_alert("high")) is None
    text = alert.to_telegram("http://127.0.0.1:8080")
    assert "РЕАЛЬНО" in text and all(ord(ch) < 0x2190 for ch in text)
    assert parse_callback("ours:" + alert.id) == ("ours", alert.id)
    assert parse_callback("ack:../../etc") is None and parse_callback("delete:" + alert.id) is None


def test_telegram_button_changes_status(tmp_path):
    storage = Storage(":memory:")
    alerts = AlertManager(storage, lambda h: h)
    alert = alerts.raise_alert("critical", "local", "t", "w", "d", [], kind="ransomware")
    bot = TelegramBot("TEST-TOKEN", tmp_path, "http://x", "medium", lambda: "", alerts.set_status)
    calls = []
    bot._call = lambda method, payload, timeout=15: calls.append((method, payload)) or {}
    bot.subscribers = {111}
    press = {"callback_query": {"id": "q", "data": "ours:" + alert.id, "from": {"username": "owner"},
                                "message": {"message_id": 5, "chat": {"id": 111}}}}
    bot.handle_update(press)
    assert alerts.get(alert.id).status == "ours" and alerts.get(alert.id).status_by == "telegram:owner"
    assert [c[0] for c in calls][:2] == ["answerCallbackQuery", "editMessageReplyMarkup"]
    stranger = {"callback_query": {"id": "q2", "data": "ack:" + alert.id, "from": {},
                                   "message": {"message_id": 6, "chat": {"id": 999}}}}
    bot.handle_update(stranger)
    assert alerts.get(alert.id).status == "ours"  # non-subscriber cannot change status


# Web ------------------------------------------------------------------------

@pytest.fixture
def server(tmp_path):
    cfg = Config(data_dir=tmp_path, demo=True, scenario=False, port=0, dashboard_token="s3cret-token",
                 agent_key="agent-key-1", max_body_bytes=2048)
    application = App(cfg, local=FakeMetrics())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(application))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield application, "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()
    application.shutdown()
    application.storage.close()


def call(url, data=None, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def test_web_requires_token_and_csrf_header(server):
    application, base = server
    auth = {"Authorization": "Bearer s3cret-token"}
    assert call(base + "/api/state")[0] == 401
    assert call(base + "/api/state", headers={"Authorization": "Bearer wrong"})[0] == 401
    status, body = call(base + "/api/state", headers=auth)
    assert status == 200 and json.loads(body)["version"] == "0.3.0"
    post = dict(auth, **{"Content-Type": "application/json"})
    assert call(base + "/api/demo/reset", b"{}", post)[0] == 403  # no X-Requested-With
    post["X-Requested-With"] = "secupredict"
    assert call(base + "/api/demo/reset", b"{}", post)[0] == 200
    assert call(base + "/api/demo/profile", b'{"profile": "online_shop"}', post)[0] == 200
    assert application.state()["company"].startswith("Интернет-магазин")
    assert call(base + "/api/demo/profile", b'{"profile": "nope"}', post)[0] == 400
    assert call(base + "/api/demo/reset", b"x" * 5000, post)[0] == 413
    status, body = call(base + "/", headers=auth)
    assert status == 200 and "https://" not in body and "http://" not in body  # offline: no external resources


def test_web_agent_ingest(server):
    application, base = server
    sample = {"host_id": "laptop-2", "name": "Laptop 2",
              "metrics": {"cpu": 33.3, "ram": 51, "disk": 60, "net_in": 5, "net_out": 6, "io": 7}}
    body = json.dumps(sample).encode("utf-8")
    assert call(base + "/api/ingest", body, {"Content-Type": "application/json"})[0] == 401
    assert call(base + "/api/ingest", body, {"X-Agent-Key": "wrong"})[0] == 401
    assert call(base + "/api/ingest", body, {"X-Agent-Key": "agent-key-1"})[0] == 200
    host = [h for h in application.state()["hosts"] if h["id"] == "agent:laptop-2"][0]
    assert host["real"] is True and host["kind"] == "agent" and host["latest"]["cpu"] == 33.3
    bad = json.dumps({"host_id": "../x", "metrics": {}}).encode("utf-8")
    assert call(base + "/api/ingest", bad, {"X-Agent-Key": "agent-key-1"})[0] == 400
    nan = json.dumps({"host_id": "h", "metrics": {"cpu": "100"}}).encode("utf-8")
    assert call(base + "/api/ingest", nan, {"X-Agent-Key": "agent-key-1"})[0] == 400
