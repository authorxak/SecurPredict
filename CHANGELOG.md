# Changelog

## 0.3.0

### Added
- Mass file change detector (periodic folder walk, no dependencies).
- Failed login detector for sshd-style logs with a sliding time window per IP.
- Statistical anomaly detector (EWMA mean and deviation per host) for CPU and
  memory; threshold alerts are downgraded when the value is usual for the host.
- `tools/simulate_attack.py`: decoy files, harmless "encryption", failed logins
  in a test log. Refuses any folder or log it did not create.
- `РЕАЛЬНО` / `СИМУЛЯЦИЯ` label on every host and alert; `УЧЕБНАЯ АТАКА` label
  for real detections caused by the simulator.
- Demo panel on the dashboard: start scenario, reset, start attack simulation,
  switch profile without restart, open report.
- `--demo`: deterministic 60-second scenario, offline, Telegram off.
- Response module with dry-run (default) and `--enforce`; action journal.
- Telegram inline buttons "Принять" and "Это мы" under critical alerts.
- SQLite storage (`alerts`, `metrics` with retention, `actions`).
- One-page HTML report with a personal data protection self-check list.
- Agent mode (`--agent --server URL --agent-key KEY`) and `POST /api/ingest`.
- Dashboard access token, mandatory for non-local `--host`; login page; request
  body size limit; agent key check; custom-header check on POST requests;
  security headers.
- `.env` support, `.env.example`, `.gitignore`, pytest suite.

### Changed
- Single file split into the `secupredict` package; `secupredict_monitor.py`
  remains the entry point and all 0.2.0 flags still work.
- Scenario alert texts no longer claim that a host was isolated, a program was
  stopped or an address was blocked: they state that this is a simulation.
- Scenario addresses moved to documentation ranges (198.51.100.0/24).
- Emoji removed from Telegram messages and the interface.
- Telegram status is neutral when the bot is off.

### Removed
- Bot token from the source code (`DEFAULT_TG_TOKEN`). The token is read only
  from `TG_BOT_TOKEN`.

### Security
- The token that was present in the 0.2.0 source must be treated as leaked:
  revoke it in BotFather if that has not been done yet.

## 0.2.0
- Single-file monitor: local metrics, simulated fleet, threshold rules,
  scripted scenario, dashboard, Telegram delivery.
