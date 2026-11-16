"""One-page HTML report for a period. Print it to PDF from the browser."""
from __future__ import annotations

import html
import time
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Tuple

from .config import SEV_ORDER, SEV_RU, STATUS_RU, VERSION, Config
from .storage import Storage

YES, NO, UNKNOWN = "есть", "нет", "не проверялось"

ACTION_RU = {"terminate_process": "Завершение процесса", "block_ip": "Блокировка IP"}
RESULT_RU = {"described": "только описано (dry-run)", "done": "выполнено", "failed": "ошибка",
             "refused": "отказано", "not_found": "цель не найдена"}
DETECTOR_RU = {"threshold": "пороги", "stat": "статистический детектор", "files": "детектор файлов",
               "authlog": "детектор входов", "scenario": "демо-сценарий"}


def compliance_checklist(cfg: Config) -> List[Tuple[str, str, str]]:
    """Self-check items: (item, status, note). Status is one of YES / NO / UNKNOWN.

    Only facts that the monitor can observe about itself get YES or NO.
    Organisational and legal items are always UNKNOWN: the monitor cannot check them.
    """
    token = bool(cfg.dashboard_token)
    return [
        ("Доступ к дашборду монитора закрыт токеном", YES if token else NO,
         "Токен задан." if token else "Токен не задан; дашборд доступен только с этого компьютера."
         if cfg.is_local_bind else "Токен не задан."),
        ("Секреты (токен бота, ключи) хранятся вне исходного кода", YES,
         "Читаются из переменных окружения или файла .env."),
        ("Ведётся журнал событий безопасности (тревог)", YES, "Таблица alerts в локальной базе SQLite."),
        ("Ведётся журнал принятых мер", YES, "Таблица actions: причина, время, режим, результат."),
        ("Срок хранения собранных метрик ограничен", YES,
         "Метрики старше %.0f ч удаляются автоматически." % cfg.metrics_retention_hours),
        ("Монитор не читает содержимое документов и баз с персональными данными", YES,
         "Собираются метрики нагрузки, имена файлов в наблюдаемой папке, IP-адреса и логины из журнала "
         "входов. Относятся ли IP-адреса и логины к персональным данным в вашем случае, не проверялось."),
        ("Шифрование канала агент - сервер и дашборда (TLS)", NO, "В версии 0.3.0 используется HTTP без TLS."),
        ("Шифрование локальной базы монитора", NO, "Файл SQLite хранится без шифрования."),
        ("Индивидуальные учётные записи и разграничение прав в мониторе", NO, "Один общий токен доступа."),
        ("Утверждены внутренние документы по защите персональных данных", UNKNOWN, ""),
        ("Определён перечень лиц, имеющих доступ к персональным данным", UNKNOWN, ""),
        ("Назначено лицо, ответственное за организацию обработки персональных данных", UNKNOWN, ""),
        ("Получены согласия субъектов или есть иное законное основание обработки", UNKNOWN, ""),
        ("База с персональными данными хранится на территории Республики Казахстан", UNKNOWN, ""),
        ("Есть порядок уведомления уполномоченного органа о нарушении безопасности персональных данных",
         UNKNOWN, "Сроки и форму уведомления уточняйте по действующей редакции закона и правил."),
        ("Подано уведомление о начале обработки персональных данных, если оно требуется", UNKNOWN, ""),
        ("Создаются и проверяются резервные копии", UNKNOWN, ""),
    ]


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S")


def build_report(storage: Storage, cfg: Config, company: str, hours: float = 24.0) -> str:
    """Build the report for the last `hours` hours from the SQLite journal."""
    e = html.escape
    until = time.time()
    since = until - hours * 3600
    alerts: List[Dict[str, Any]] = storage.alerts_between(since, until)
    actions: List[Dict[str, Any]] = storage.actions_between(since, until)

    by_sev = Counter(a["severity"] for a in alerts)
    real = [a for a in alerts if a["origin"] == "real"]
    staged = [a for a in real if a["staged"]]
    simulated = [a for a in alerts if a["origin"] != "real"]
    hosts = Counter((a["host_name"], a["origin"]) for a in alerts).most_common(5)

    def alert_rows(items: List[Dict[str, Any]]) -> str:
        if not items:
            return '<tr><td colspan="5" class="muted">Нет записей за период.</td></tr>'
        rows = []
        for a in sorted(items, key=lambda x: (-SEV_ORDER.get(x["severity"], 0), x["ts"])):
            note = " (учебная атака)" if a["staged"] else ""
            rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s%s</td><td>%s</td></tr>" % (
                e(_fmt(a["ts"])), e(SEV_RU.get(a["severity"], a["severity"])), e(a["host_name"]),
                e(a["title"]), e(note),
                e(DETECTOR_RU.get(a["detector"], a["detector"])) + ", " + e(STATUS_RU.get(a["status"], a["status"]))))
        return "".join(rows)

    sev_cells = "".join(
        '<div class="kpi"><b>%d</b><span>%s</span></div>' % (by_sev.get(s, 0), e(SEV_RU[s]))
        for s in ("critical", "high", "medium", "low"))
    host_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%d</td></tr>" % (
            e(name), "РЕАЛЬНО" if origin == "real" else "СИМУЛЯЦИЯ", count)
        for (name, origin), count in hosts) or '<tr><td colspan="3" class="muted">Тревог не было.</td></tr>'
    action_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            e(_fmt(x["ts"])), e(ACTION_RU.get(x["action"], x["action"])), e(x["target"]), e(x["mode"]),
            e(RESULT_RU.get(x["result"], x["result"])), e(x["detail"]))
        for x in actions) or '<tr><td colspan="6" class="muted">Мер за период не принималось.</td></tr>'
    done = sum(1 for x in actions if x["result"] == "done")
    check_rows = "".join(
        '<tr><td>%s</td><td class="st-%s">%s</td><td>%s</td></tr>' % (
            e(item), {YES: "yes", NO: "no"}.get(status, "unk"), e(status), e(note))
        for item, status, note in compliance_checklist(cfg))

    return """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>SecuPredict: отчёт</title><link rel="icon" href="data:,">
<style>
body{font:13px/1.4 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;color:#172634;margin:24px auto;max-width:900px;padding:0 16px}
h1{font-size:20px;margin:0 0 2px} h2{font-size:14px;margin:18px 0 6px;border-bottom:1px solid #d6dde3;padding-bottom:3px}
.muted{color:#5b6b79} table{width:100%%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #e3e8ec;vertical-align:top} th{color:#5b6b79;font-weight:600}
.kpis{display:flex;gap:10px;flex-wrap:wrap} .kpi{border:1px solid #d6dde3;border-radius:6px;padding:6px 12px;min-width:110px}
.kpi b{display:block;font-size:20px} .kpi span{color:#5b6b79;font-size:12px}
.st-yes{color:#2f6b3f;font-weight:600} .st-no{color:#b3263d;font-weight:600} .st-unk{color:#8a6a10;font-weight:600}
.note{border:1px solid #d6dde3;border-radius:6px;padding:8px 10px;margin-top:8px;background:#f6f8f9}
button{font:inherit;padding:4px 12px} @media print{button{display:none} body{margin:0;max-width:none}}
</style></head><body>
<button onclick="window.print()">Печать / сохранить в PDF</button>
<h1>SecuPredict: отчёт по мониторингу</h1>
<div class="muted">%(company)s. Период: %(since)s - %(until)s (%(hours).0f ч). Версия монитора %(version)s, режим реагирования: %(mode)s.</div>

<h2>Тревоги по уровням</h2>
<div class="kpis">%(sev_cells)s
<div class="kpi"><b>%(real)d</b><span>обнаружено реально</span></div>
<div class="kpi"><b>%(simulated)d</b><span>симулировано</span></div></div>
<div class="note">РЕАЛЬНО: детектор сработал на настоящих метриках, файлах или журналах (%(real)d, из них %(staged)d
вызваны учебной атакой simulate_attack на файлах-приманках). СИМУЛЯЦИЯ: демо-парк и сценарий по таймеру (%(simulated)d).</div>

<h2>Самые проблемные устройства</h2>
<table><tr><th>Устройство</th><th>Данные</th><th>Тревог</th></tr>%(host_rows)s</table>

<h2>Обнаружено реально</h2>
<table><tr><th>Время</th><th>Уровень</th><th>Устройство</th><th>Тревога</th><th>Детектор, статус</th></tr>%(real_rows)s</table>

<h2>Симулировано (демо)</h2>
<table><tr><th>Время</th><th>Уровень</th><th>Устройство</th><th>Тревога</th><th>Детектор, статус</th></tr>%(sim_rows)s</table>

<h2>Принятые меры</h2>
<div class="muted">Всего записей: %(n_actions)d, реально выполнено: %(done)d. Запись в режиме dry-run означает, что действие только описано.</div>
<table><tr><th>Время</th><th>Мера</th><th>Цель</th><th>Режим</th><th>Результат</th><th>Подробности</th></tr>%(action_rows)s</table>

<h2>Чек-лист самопроверки по защите персональных данных</h2>
<div class="muted">Ориентир: Закон Республики Казахстан «О персональных данных и их защите». Формат: есть / нет / не проверялось.</div>
<table><tr><th>Пункт</th><th>Статус</th><th>Примечание</th></tr>%(check_rows)s</table>
<div class="note">Чек-лист не является юридическим заключением и не подтверждает соответствие закону.
Монитор проверяет только собственные технические настройки; организационные и правовые пункты должен оценить юрист.</div>
<p class="muted">Сформировано %(until)s.</p>
</body></html>
""" % {
        "company": e(company), "since": e(_fmt(since)), "until": e(_fmt(until)), "hours": hours,
        "version": e(VERSION), "mode": e(cfg.response_mode), "sev_cells": sev_cells,
        "real": len(real), "staged": len(staged), "simulated": len(simulated),
        "host_rows": host_rows, "real_rows": alert_rows(real), "sim_rows": alert_rows(simulated),
        "n_actions": len(actions), "done": done, "action_rows": action_rows, "check_rows": check_rows,
    }
