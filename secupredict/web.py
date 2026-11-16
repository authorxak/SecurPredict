"""HTTP server: dashboard, JSON API, agent ingest, login and report.

The dashboard is one self-contained HTML page: no CDN, works offline.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:  # pragma: no cover
    from .app import App

log = logging.getLogger("secupredict.web")

_ALERT_ACTION = re.compile(r"^/api/alerts/([0-9a-f]{8})/(ack|ours)$")
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "secupredict"
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                               "connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'",
}


def session_value(token: str) -> str:
    """Cookie value derived from the access token (the token itself is never stored in a cookie)."""
    return hmac.new(token.encode("utf-8"), b"secupredict-session", hashlib.sha256).hexdigest()


def make_handler(app: "App") -> type:
    """Build the request handler class bound to one App instance."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "SecuPredict"
        sys_version = ""
        timeout = 15  # seconds; drops stuck connections

        # Helpers ------------------------------------------------------------
        def _send(self, code: int, body: bytes, ctype: str, extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: Dict[str, Any]) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _redirect(self, location: str, extra: Optional[Dict[str, str]] = None) -> None:
            headers = {"Location": location}
            headers.update(extra or {})
            self._send(303, b"", "text/plain", headers)

        def _authorized(self) -> bool:
            token = app.cfg.dashboard_token
            if not token:
                return True
            bearer = self.headers.get("Authorization", "")
            if bearer.startswith("Bearer ") and hmac.compare_digest(bearer[7:].encode(), token.encode()):
                return True
            expected = session_value(token)
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == "sp_session" and hmac.compare_digest(value.encode(), expected.encode()):
                    return True
            return False

        def _body(self) -> Optional[bytes]:
            """Read the request body with a size limit. Sends the error itself and returns None."""
            raw = self.headers.get("Content-Length")
            try:
                length = int(raw) if raw is not None else -1
            except ValueError:
                length = -1
            if length < 0:
                self._json(411, {"ok": False, "error": "нужен заголовок Content-Length"})
                return None
            if length > app.cfg.max_body_bytes:
                self._json(413, {"ok": False, "error": "слишком большое тело запроса"})
                self.close_connection = True
                return None
            return self.rfile.read(length) if length else b""

        def _json_body(self) -> Optional[Dict[str, Any]]:
            body = self._body()
            if body is None:
                return None
            if not body:
                return {}
            try:
                data = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._json(400, {"ok": False, "error": "некорректный JSON"})
                return None
            if not isinstance(data, dict):
                self._json(400, {"ok": False, "error": "ожидался JSON-объект"})
                return None
            return data

        # GET ----------------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            path = url.path
            if path == "/login":
                self._send(200, LOGIN_HTML.replace("__ERROR__", "").encode("utf-8"), "text/html; charset=utf-8")
                return
            if not self._authorized():
                if path.startswith("/api/"):
                    self._json(401, {"ok": False, "error": "нужен токен доступа"})
                else:
                    self._redirect("/login")
                return
            if path in ("/", "/index.html"):
                self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/api/state":
                self._json(200, app.state())
            elif path == "/report":
                try:
                    hours = float(parse_qs(url.query).get("hours", ["24"])[0])
                except ValueError:
                    hours = 24.0
                hours = max(0.1, min(hours, 24.0 * 31))
                self._send(200, app.report_html(hours).encode("utf-8"), "text/html; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain")

        # POST ---------------------------------------------------------------
        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/api/ingest":
                self._ingest()
                return
            if path == "/login":
                self._login()
                return
            if not self._authorized():
                self._json(401, {"ok": False, "error": "нужен токен доступа"})
                return
            if self.headers.get(CSRF_HEADER) != CSRF_VALUE:
                self._json(403, {"ok": False, "error": "запрос отклонён: нет заголовка %s" % CSRF_HEADER})
                return
            data = self._json_body()
            if data is None:
                return
            m = _ALERT_ACTION.match(path)
            if m:
                ok = app.set_alert_status(m.group(1), m.group(2), "dashboard")
                self._json(200 if ok else 404, {"ok": ok})
            elif path == "/api/demo/scenario":
                app.start_scenario()
                self._json(200, {"ok": True, "message": "Сценарий (симуляция) запущен."})
            elif path == "/api/demo/reset":
                app.demo_reset()
                self._json(200, {"ok": True, "message": "Демо сброшено."})
            elif path == "/api/demo/attack":
                ok, message = app.launch_attack()
                self._json(200 if ok else 409, {"ok": ok, "message": message})
            elif path == "/api/demo/profile":
                ok, message = app.set_profile(str(data.get("profile", "")))
                self._json(200 if ok else 400, {"ok": ok, "message": message})
            else:
                self._json(404, {"ok": False, "error": "неизвестный адрес"})

        def _ingest(self) -> None:
            key = app.cfg.agent_key
            if not key:
                self._json(403, {"ok": False, "error": "приём данных агентов выключен: на сервере не задан ключ"})
                return
            given = self.headers.get("X-Agent-Key", "")
            if not hmac.compare_digest(given.encode("utf-8"), key.encode("utf-8")):
                time.sleep(0.3)
                self._json(401, {"ok": False, "error": "неверный ключ агента"})
                return
            data = self._json_body()
            if data is None:
                return
            ok, message = app.ingest(data, self.client_address[0])
            self._json(200 if ok else 400, {"ok": ok, "message": message})

        def _login(self) -> None:
            body = self._body()
            if body is None:
                return
            token = app.cfg.dashboard_token
            given = parse_qs(body.decode("utf-8", "replace")).get("token", [""])[0]
            if token and hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8")):
                cookie = "sp_session=%s; HttpOnly; SameSite=Strict; Path=/" % session_value(token)
                self._redirect("/", {"Set-Cookie": cookie})
                return
            if not token:
                self._redirect("/")
                return
            time.sleep(0.5)
            page = LOGIN_HTML.replace("__ERROR__", "Неверный токен.")
            self._send(401, page.encode("utf-8"), "text/html; charset=utf-8")

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("http: " + fmt, *args)

    return Handler


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecuPredict: вход</title><link rel="icon" href="data:,">
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#EDF1F3;color:#172634;
  font:15px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
form{background:#fff;border:1px solid #D6DDE3;border-radius:10px;padding:24px;width:min(360px,90vw)}
h1{font-size:18px;margin:0 0 4px} p{color:#5B6B79;font-size:13px;margin:0 0 14px}
input{width:100%;box-sizing:border-box;font:inherit;padding:8px 10px;border:1px solid #D6DDE3;border-radius:6px}
button{margin-top:12px;font:inherit;padding:8px 14px;border-radius:6px;border:0;background:#1F7FB8;color:#fff;cursor:pointer}
.err{color:#B3263D;font-size:13px;min-height:18px;margin-top:8px}
</style></head><body>
<form method="post" action="/login">
  <h1>SecuPredict</h1>
  <p>Введите токен доступа к дашборду (переменная SECUPREDICT_DASHBOARD_TOKEN на сервере).</p>
  <label for="token">Токен доступа</label>
  <input id="token" name="token" type="password" autocomplete="current-password" autofocus required>
  <div class="err">__ERROR__</div>
  <button type="submit">Войти</button>
</form>
</body></html>
"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecuPredict: мониторинг</title><link rel="icon" href="data:,">
<style>
:root{
  --paper:#EDF1F3; --surface:#FFFFFF; --ink:#172634; --muted:#5B6B79; --line:#D6DDE3; --sky:#1F7FB8;
  --low:#4F8A5E; --medium:#B98310; --high:#CF5A24; --critical:#B3263D; --isolated:#6650A8; --ok:#4F8A5E;
  --band-ink:#FFFFFF; color-scheme:light;
}
@media (prefers-color-scheme: dark){
  :root{ --paper:#0E1822; --surface:#15222E; --ink:#E2E9EF; --muted:#8C9EAE; --line:#243646; --sky:#52A8DE;
    --low:#6DB17F; --medium:#E0AA35; --high:#EE7A44; --critical:#E5506A; --isolated:#9A85E0; --ok:#6DB17F;
    color-scheme:dark; }
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--paper);color:var(--ink);
  font:15px/1.45 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",sans-serif;
  font-variant-numeric:tabular-nums}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 24px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}
.brand h1{font-size:17px;margin:0;font-weight:650}
.brand p{margin:0;color:var(--muted);font-size:13px}
.meta{display:flex;gap:18px;color:var(--muted);font-size:13px;align-items:center;flex-wrap:wrap}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted);margin-right:6px;vertical-align:1px}
.dot.on{background:var(--ok)} .dot.off{background:var(--critical)}

.band{margin:0 24px;padding:22px 26px;border-radius:14px;background:var(--ok);color:var(--band-ink);
  display:flex;justify-content:space-between;align-items:flex-end;gap:20px;flex-wrap:wrap;
  transition:background-color .6s ease}
.band.sev-low{background:var(--low)} .band.sev-medium{background:var(--medium)}
.band.sev-high{background:var(--high)} .band.sev-critical{background:var(--critical)}
.band strong{display:block;font-size:30px;line-height:1.15;font-weight:700;letter-spacing:-.01em}
.band span{display:block;margin-top:6px;font-size:16px;opacity:.92;max-width:60ch}
.counts{display:flex;gap:18px;font-size:14px}
.counts b{display:block;font-size:22px}

.demo{margin:14px 24px 0;display:flex;gap:10px 14px;align-items:center;flex-wrap:wrap}
.demo h2{margin:0 6px 0 0}
.demo .grow{flex:1 1 220px;color:var(--muted);font-size:13px}
select{font:inherit;font-size:13px;padding:4px 8px;border-radius:6px;border:1px solid var(--line);background:var(--surface);color:var(--ink)}

.layout{display:grid;grid-template-columns:minmax(0,1fr) 380px;gap:20px;padding:20px 24px 40px}
@media (max-width:1000px){.layout{grid-template-columns:1fr}}
h2{font-size:15px;font-weight:650;margin:0 0 10px}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px}
.panel + .panel{margin-top:20px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:640px}
th{font-weight:500;color:var(--muted);font-size:13px;text-align:left;padding:0 8px 8px}
td{padding:10px 8px;border-top:1px solid var(--line);vertical-align:middle}
tr.host{cursor:pointer}
tr.host:hover td{background:color-mix(in srgb,var(--sky) 6%,transparent)}
tr.host.sel td{background:color-mix(in srgb,var(--sky) 11%,transparent)}
tr.host:focus-visible{outline:2px solid var(--sky);outline-offset:-2px}
.hname{font-weight:600}
.hrole{color:var(--muted);font-size:12.5px}
.st{font-size:13px;font-weight:600;white-space:nowrap}
.st::before{content:"";display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;background:currentColor;vertical-align:0}
.st-ok{color:var(--ok)} .st-warning{color:var(--medium)} .st-alert{color:var(--critical)}
.st-isolated{color:var(--isolated)} .st-offline{color:var(--muted)}
.meter{display:flex;align-items:center;gap:8px;white-space:nowrap}
.track{width:40px;height:6px;border-radius:3px;background:var(--line);overflow:hidden}
.fill{height:100%;background:var(--sky)}
.fill.hot{background:var(--high)}
.net{font-size:13px;color:var(--muted);white-space:nowrap}
.spark{display:block}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;padding:1px 7px;border-radius:4px;
  border:1px solid currentColor;white-space:nowrap}
.badge.real{color:var(--ok)} .badge.sim{color:var(--isolated)} .badge.staged{color:var(--medium)}
.badge.mode{color:var(--sky)} .badge.enforce{color:var(--critical)}

.detail-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
.legend{display:flex;gap:16px;font-size:13px;color:var(--muted);flex-wrap:wrap}
.legend i{display:inline-block;width:14px;height:3px;margin-right:6px;vertical-align:3px;border-radius:2px}
#chart{width:100%;height:auto;display:block;margin-top:8px}
#chart text{fill:var(--muted);font-size:11px}
.facts{display:flex;gap:24px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-top:8px}
.facts b{color:var(--ink);font-weight:600}

ul.plain{list-style:none;margin:0;padding:0;font-size:13.5px}
ul.plain li{padding:8px 0;border-top:1px solid var(--line)}
ul.plain li:first-child{border-top:0;padding-top:0}
ul.plain .sub{color:var(--muted);font-size:12.5px;overflow-wrap:anywhere}
table.small{min-width:0;font-size:12.5px}
table.small td,table.small th{padding:6px 8px;vertical-align:top}
table.small td{overflow-wrap:anywhere}

.alerts ol{list-style:none;margin:0;padding:0}
.alert{border-left:4px solid var(--muted);padding:10px 12px;margin-bottom:10px;background:var(--surface);
  border-radius:0 8px 8px 0;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.alert.low{border-left-color:var(--low)} .alert.medium{border-left-color:var(--medium)}
.alert.high{border-left-color:var(--high)} .alert.critical{border-left-color:var(--critical)}
.alert.closed{opacity:.62}
.alert.fresh{animation:flash 2.4s ease-out}
@keyframes flash{0%{background:color-mix(in srgb,var(--critical) 18%,var(--surface))}100%{background:var(--surface)}}
.ah{display:flex;justify-content:space-between;gap:8px;font-size:12.5px;color:var(--muted)}
.sev{font-weight:650}
.sev.low{color:var(--low)} .sev.medium{color:var(--medium)} .sev.high{color:var(--high)} .sev.critical{color:var(--critical)}
.at{font-weight:650;margin:3px 0 4px}
.alert details{font-size:13.5px;color:var(--ink)}
.alert summary{cursor:pointer;color:var(--sky);font-size:13px;margin-top:4px}
.alert p{margin:6px 0;overflow-wrap:anywhere}
.alert ol.steps{list-style:decimal;padding-left:20px;margin:4px 0}
.row{display:flex;justify-content:space-between;align-items:center;margin-top:8px;gap:8px;flex-wrap:wrap}
.btns{display:flex;gap:6px}
.tag{font-size:12px;color:var(--muted)}
button,a.btn{font:inherit;font-size:13px;padding:4px 12px;border-radius:6px;border:1px solid var(--line);
  background:var(--surface);color:var(--ink);cursor:pointer;text-decoration:none;display:inline-block}
button:hover,a.btn:hover{border-color:var(--sky)}
button:focus-visible,a.btn:focus-visible,select:focus-visible{outline:2px solid var(--sky);outline-offset:2px}
button:disabled{opacity:.5;cursor:default}
button.primary{background:var(--sky);border-color:var(--sky);color:#fff}
.empty{color:var(--muted);font-size:14px;padding:8px 0}
.note{color:var(--muted);font-size:12.5px;margin-top:10px}
@media (prefers-reduced-motion: reduce){.band{transition:none}.alert.fresh{animation:none}}
</style></head>
<body>
<header class="top">
  <div class="brand">
    <svg width="30" height="34" viewBox="0 0 30 34" aria-hidden="true"><path d="M15 1 28 6v10c0 8.5-5.6 14.4-13 17C7.6 30.4 2 24.5 2 16V6z" fill="var(--sky)"/><path d="m9 17 4.2 4.2L21.5 12.5" stroke="#fff" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <div><h1 id="company">SecuPredict</h1><p>Мониторинг компьютеров и данных, версия <span id="ver"></span></p></div>
  </div>
  <div class="meta">
    <span id="mode"></span>
    <span id="tg"><span class="dot"></span>Telegram</span>
    <span id="conn"><span class="dot"></span>Связь с сервером</span>
    <span id="clock"></span>
  </div>
</header>

<section id="band" class="band" aria-live="polite">
  <div><strong id="bandTitle">Подключаемся…</strong><span id="bandText"></span></div>
  <div class="counts" id="counts"></div>
</section>

<section class="demo panel" aria-label="Управление демо">
  <h2>Демо</h2>
  <button id="btnScenario" class="primary">Запустить сценарий</button>
  <button id="btnAttack">Запустить имитацию атаки</button>
  <button id="btnReset">Сбросить</button>
  <label class="tag" for="profile">Профиль</label>
  <select id="profile"></select>
  <a class="btn" href="/report" target="_blank" rel="noopener">Отчёт</a>
  <span class="grow" id="demoMsg"></span>
</section>

<main class="layout">
  <section>
    <div class="panel">
      <h2>Компьютеры и серверы</h2>
      <div class="scroll"><table>
        <thead><tr><th>Устройство</th><th>Данные</th><th>Состояние</th><th>Процессор</th><th>Память</th><th>Диск</th><th>Сеть, вход / выход</th></tr></thead>
        <tbody id="hosts"></tbody>
      </table></div>
      <p class="note">РЕАЛЬНО: метрики настоящего компьютера (этого или с агентом). СИМУЛЯЦИЯ: демо-парк, значения сгенерированы.</p>
    </div>
    <div class="panel">
      <div class="detail-head">
        <h2 id="detailTitle">Нагрузка</h2>
        <div class="legend"><span><i style="background:var(--sky)"></i>Процессор</span><span><i style="background:var(--isolated)"></i>Память</span><span><i style="background:var(--muted)"></i>Обычный уровень процессора</span></div>
      </div>
      <svg id="chart" viewBox="0 0 720 200" role="img" aria-label="График нагрузки"></svg>
      <div class="facts" id="facts"></div>
    </div>
    <div class="panel">
      <h2>Детекторы</h2>
      <ul class="plain" id="detectors"></ul>
    </div>
    <div class="panel">
      <h2>Журнал мер реагирования</h2>
      <div class="scroll"><table class="small">
        <thead><tr><th>Время</th><th>Мера</th><th>Режим</th><th>Результат</th><th>Подробности</th></tr></thead>
        <tbody id="actions"></tbody>
      </table></div>
    </div>
  </section>
  <aside class="alerts">
    <div class="panel">
      <h2>Тревоги</h2>
      <ol id="alerts"></ol>
      <p class="note" id="tgnote"></p>
    </div>
  </aside>
</main>

<script>
const ORDER={low:0,medium:1,high:2,critical:3};
const SEV={low:'Низкий',medium:'Средний',high:'Высокий',critical:'Критический'};
const STATUS={ok:'В норме',warning:'Внимание',alert:'Угроза',isolated:'Изолирован (симуляция)',offline:'Нет связи'};
const BAND={critical:'Критическая угроза',high:'Серьёзная угроза',medium:'Нужно проверить',low:'Есть рекомендации'};
const DET={threshold:'пороги',stat:'статистический детектор',files:'детектор файлов',authlog:'детектор входов',scenario:'сценарий по таймеру'};
const ACT={terminate_process:'Завершение процесса',block_ip:'Блокировка IP'};
const RES={described:'только описано',done:'выполнено',failed:'ошибка',refused:'отказано',not_found:'цель не найдена'};
let selected=null, seen=new Set(), firstRender=true, lastState=null, openDetails=new Set(), msgUntil=0;

const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const kb=v=>v>=1024?(v/1024).toFixed(1)+' МБ/с':Math.round(v)+' КБ/с';
const hm=ts=>new Date(ts*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
const originBadge=(origin,staged)=>origin==='real'
  ?(staged?'<span class="badge real">РЕАЛЬНО</span> <span class="badge staged">УЧЕБНАЯ АТАКА</span>':'<span class="badge real">РЕАЛЬНО</span>')
  :'<span class="badge sim">СИМУЛЯЦИЯ</span>';

async function post(url,body){
  try{
    const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'secupredict'},body:JSON.stringify(body||{})});
    if(r.status===401){location.href='/login';return null;}
    const j=await r.json(); say(j.message||j.error||''); tick(); return j;
  }catch(e){say('Нет связи с сервером.');return null;}
}
function say(text){document.getElementById('demoMsg').textContent=text;msgUntil=Date.now()+6000;}

function meter(v){const p=Math.max(0,Math.min(100,v||0));
  return `<div class="meter"><div class="track"><div class="fill${p>=85?' hot':''}" style="width:${p}%"></div></div>${Math.round(p)}%</div>`;}
function spark(arr){const a=arr.slice(-40);if(a.length<2)return '';const w=64,h=24;
  const pts=a.map((v,i)=>`${(i/(a.length-1)*w).toFixed(1)},${(h-2-(v/100)*(h-4)).toFixed(1)}`).join(' ');
  return `<svg class="spark" width="${w}" height="${h}" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="var(--sky)" stroke-width="1.5"/></svg>`;}

function renderHosts(hosts){
  if(!selected||!hosts.find(h=>h.id===selected)) selected=hosts[0]?.id;
  document.getElementById('hosts').innerHTML=hosts.map(h=>{const l=h.latest||{};const off=h.status==='offline';return `
  <tr class="host${h.id===selected?' sel':''}" data-id="${esc(h.id)}" tabindex="0">
    <td><div class="hname">${esc(h.name)}</div><div class="hrole">${esc(h.role)}</div></td>
    <td>${originBadge(h.real?'real':'simulated',false)}</td>
    <td><span class="st st-${h.status}">${STATUS[h.status]||esc(h.status)}</span></td>
    <td><div style="display:flex;gap:10px;align-items:center">${meter(l.cpu)}${spark(h.history.cpu)}</div></td>
    <td>${meter(l.ram)}</td><td>${meter(l.disk)}</td>
    <td class="net">${h.status==='isolated'?'отключена (симуляция)':off?'нет данных':kb(l.net_in||0)+' / '+kb(l.net_out||0)}</td>
  </tr>`}).join('');
  document.querySelectorAll('tr.host').forEach(tr=>{
    const pick=()=>{selected=tr.dataset.id;render(lastState)};
    tr.onclick=pick; tr.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick()}};
  });
}

function renderChart(s){
  const h=s.hosts.find(x=>x.id===selected); if(!h)return;
  const span=Math.round(s.history_points*s.interval/60);
  document.getElementById('detailTitle').textContent=`Нагрузка: ${h.name}, последние ${span} мин`;
  const W=720,H=200,L=36,R=8,T=10,B=22, n=Math.max(2,h.history.cpu.length);
  const x=i=>L+(W-L-R)*(i/(n-1)), y=v=>T+(H-T-B)*(1-v/100);
  let g='';
  for(const v of [0,50,85,100]){g+=`<line x1="${L}" x2="${W-R}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)" ${v===85?'stroke-dasharray="5 4"':''}/><text x="${L-6}" y="${y(v)+4}" text-anchor="end">${v}%</text>`;}
  const line=(arr,c)=>arr.length<2?'':`<polyline points="${arr.map((v,i)=>`${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')}" fill="none" stroke="${c}" stroke-width="2" stroke-linejoin="round"/>`;
  g+=`<text x="${L}" y="${H-5}">раньше</text><text x="${W-R}" y="${H-5}" text-anchor="end">сейчас</text>`;
  const b=h.baseline&&h.baseline.cpu;
  if(b&&b.ready){g+=`<line x1="${L}" x2="${W-R}" y1="${y(b.mean)}" y2="${y(b.mean)}" stroke="var(--muted)" stroke-width="1.5" stroke-dasharray="2 4"/>`;}
  document.getElementById('chart').innerHTML=g+line(h.history.ram,'var(--isolated)')+line(h.history.cpu,'var(--sky)');
  const l=h.latest||{};
  const usual=b?(b.ready?`обычно ${Math.round(b.mean)}% (разброс ${b.std.toFixed(1)})`:`уровень изучается: ${b.n} из ${b.need} замеров`):'';
  document.getElementById('facts').innerHTML=
    `<span>Процессор <b>${Math.round(l.cpu||0)}%</b>${usual?', '+usual:''}</span><span>Память <b>${Math.round(l.ram||0)}%</b></span>`+
    `<span>Диск занят <b>${Math.round(l.disk||0)}%</b></span><span>Чтение и запись диска <b>${kb(l.io||0)}</b></span>`+
    `<span>Сеть <b>${h.status==='isolated'?'отключена (симуляция)':kb(l.net_in||0)+' / '+kb(l.net_out||0)}</b></span>`;
}

function renderBand(s){
  const open=s.alerts.filter(a=>a.status==='open');
  const band=document.getElementById('band');
  const worst=open.reduce((w,a)=>!w||ORDER[a.severity]>ORDER[w.severity]?a:w,null);
  band.className='band'+(worst?' sev-'+worst.severity:'');
  document.getElementById('bandTitle').textContent=worst?BAND[worst.severity]:'Всё спокойно';
  document.getElementById('bandText').textContent=worst
    ?`${worst.origin==='real'?(worst.staged?'Реально, учебная атака':'Реально'):'Симуляция'}. ${worst.host_name}: ${worst.title.toLowerCase()}`
    :`Под наблюдением ${s.hosts.length} устройств, из них настоящих: ${s.hosts.filter(h=>h.real).length}. Открытых тревог нет.`;
  const c={critical:0,high:0,medium:0,low:0}; open.forEach(a=>c[a.severity]++);
  document.getElementById('counts').innerHTML=['critical','high','medium','low']
    .map(k=>`<div><b>${c[k]}</b>${SEV[k].toLowerCase()}</div>`).join('');
}

function renderAlerts(s){
  const list=document.getElementById('alerts');
  list.querySelectorAll('details').forEach(d=>{if(d.open)openDetails.add(d.dataset.id);else openDetails.delete(d.dataset.id);});
  if(!s.alerts.length){list.innerHTML='<li class="empty">Тревог пока нет.</li>';firstRender=false;return;}
  list.innerHTML=s.alerts.map(a=>{const fresh=!firstRender&&!seen.has(a.id);seen.add(a.id);
    if(fresh&&ORDER[a.severity]>=2)openDetails.add(a.id);
    const closed=a.status!=='open';
    const who=a.status_by&&a.status_by.startsWith('telegram')?' в Telegram':' на дашборде';
    return `
  <li class="alert ${a.severity}${closed?' closed':''}${fresh?' fresh':''}">
    <div class="ah"><span class="sev ${a.severity}">${SEV[a.severity]}</span><span>${hm(a.ts)}, ${esc(a.host_name)}</span></div>
    <div class="at">${esc(a.title)}</div>
    <div>${originBadge(a.origin,a.staged)} <span class="tag">${DET[a.detector]||esc(a.detector)}</span></div>
    <details data-id="${a.id}"${openDetails.has(a.id)?' open':''}><summary>Подробнее и что делать</summary>
      <p><b>Что случилось:</b> ${esc(a.what)}</p><p><b>Что сделано:</b> ${esc(a.did)}</p>
      <ol class="steps">${a.steps.map(x=>`<li>${esc(x)}</li>`).join('')}</ol></details>
    <div class="row"><span class="tag">${ORDER[a.severity]>=ORDER[s.telegram.min_severity]&&s.telegram.enabled?'отправлено в Telegram':''}</span>
      ${closed?`<span class="tag">${a.status==='ack'?'Принято':'Отмечено «это мы»'}${who}</span>`
        :`<span class="btns"><button data-act="ack" data-id="${a.id}">Принять</button><button data-act="ours" data-id="${a.id}">Это мы</button></span>`}</div>
  </li>`}).join('');
  list.querySelectorAll('button[data-act]').forEach(b=>b.onclick=()=>{b.disabled=true;post(`/api/alerts/${b.dataset.id}/${b.dataset.act}`);});
  firstRender=false;
}

function renderDetectors(s){
  const f=s.detectors.files, a=s.detectors.authlog, st=s.detectors.stat;
  const items=[];
  items.push(`<li><b>Массовое изменение файлов</b> ${originBadge('real',false)}
    <div class="sub">Папка: ${esc(f.directory)}. ${f.exists?`Под наблюдением файлов: ${f.files}${f.truncated?' (достигнут предел обхода)':''}.`:'Папка пока не создана.'}
    Тревога: больше ${f.change_threshold} изменённых или переименованных файлов за ${f.window_sec} с, либо от ${f.ext_threshold} файлов с подозрительным расширением.</div></li>`);
  items.push(`<li><b>Подбор пароля по журналу входов</b> ${originBadge('real',false)}
    <div class="sub">Журнал: ${esc(a.path)}. ${a.error?esc(a.error)+'.':`Прочитано строк: ${a.lines_read}, неудачных входов: ${a.failures_seen}.`}
    Тревога: от ${a.threshold} неудачных входов с одного IP за ${a.window_sec} с.</div></li>`);
  items.push(`<li><b>Статистический детектор аномалий</b> <span class="tag">(скользящее среднее и отклонение, не нейросеть)</span>
    <div class="sub">Этот компьютер: ${st.local_ready?'обычный уровень изучен':`идёт изучение обычного уровня, ${st.local_n} из ${st.need} замеров`}.
    Тревога: процессор или память выше обычного уровня больше чем на ${st.sigma} сигмы ${st.sustain} замера подряд.${s.local_source==='none'?' Внимание: без psutil на этой ОС процессор и память не измеряются.':''}</div></li>`);
  items.push(`<li><b>Пороги</b>
    <div class="sub">Процессор выше ${s.limits.cpu}%, память выше ${s.limits.ram}%, диск выше ${s.limits.disk}% дольше ${s.limits.sustain} с.</div></li>`);
  document.getElementById('detectors').innerHTML=items.join('');
  document.getElementById('actions').innerHTML=s.actions.length?s.actions.map(x=>`<tr>
    <td>${hm(x.ts)}</td><td>${ACT[x.action]||esc(x.action)}<div class="tag">${esc(x.target)}</div></td>
    <td><span class="badge ${x.mode==='enforce'?'enforce':'mode'}">${esc(x.mode)}</span></td>
    <td>${RES[x.result]||esc(x.result)}</td><td>${esc(x.detail)}</td></tr>`).join('')
    :'<tr><td colspan="5" class="empty">Мер пока не было. Они появятся, когда сработает детектор файлов или входов.</td></tr>';
}

function renderMeta(s){
  document.getElementById('company').textContent='SecuPredict: '+s.company;
  document.getElementById('ver').textContent=s.version+(s.mode.demo?', режим демо':'');
  document.getElementById('mode').innerHTML=`Реагирование: <span class="badge ${s.mode.response==='enforce'?'enforce':'mode'}">${esc(s.mode.response)}</span>`;
  const t=s.telegram, tg=document.getElementById('tg');
  tg.innerHTML=t.enabled?`<span class="dot ${t.online?'on':'off'}"></span>Telegram${t.bot?' @'+esc(t.bot):''}: ${t.subscribers} подписч.`
    :'<span class="dot"></span>Telegram отключён';
  document.getElementById('tgnote').textContent=!t.enabled?'Telegram отключён: тревоги показываются только здесь.':
    t.subscribers?`Тревоги от уровня «${SEV[t.min_severity].toLowerCase()}» и выше уходят в Telegram.`:
    `Чтобы получать тревоги в Telegram, напишите боту ${t.bot?'@'+t.bot:''} команду /start.`;
  const sel=document.getElementById('profile');
  if(document.activeElement!==sel){
    sel.innerHTML=s.profiles.map(p=>`<option value="${esc(p.id)}"${p.id===s.profile?' selected':''}>${esc(p.company)}</option>`).join('');
  }
  const sc=s.scenario;
  document.getElementById('btnScenario').textContent=sc.running?'Перезапустить сценарий':'Запустить сценарий';
  const ba=document.getElementById('btnAttack');
  ba.disabled=s.attack.running; ba.textContent=s.attack.running?'Имитация выполняется…':'Запустить имитацию атаки';
  if(Date.now()>msgUntil){
    document.getElementById('demoMsg').textContent=sc.running?`Сценарий (симуляция) идёт: ${sc.next||'завершается'}.`
      :sc.finished?'Сценарий (симуляция) завершён.':`Сценарий (симуляция) не запущен, длительность ${sc.duration} с.`;
  }
}

function render(s){ if(!s)return; lastState=s; renderMeta(s); renderBand(s); renderHosts(s.hosts); renderChart(s); renderAlerts(s); renderDetectors(s); }

async function tick(){
  const conn=document.querySelector('#conn .dot');
  try{const r=await fetch('/api/state',{cache:'no-store'});
    if(r.status===401){location.href='/login';return;}
    render(await r.json()); conn.className='dot on';}
  catch(e){conn.className='dot off';}
}
document.getElementById('btnScenario').onclick=()=>post('/api/demo/scenario');
document.getElementById('btnAttack').onclick=()=>post('/api/demo/attack');
document.getElementById('btnReset').onclick=()=>{seen=new Set();openDetails=new Set();firstRender=true;post('/api/demo/reset');};
document.getElementById('profile').onchange=e=>{seen=new Set();firstRender=true;e.target.blur();post('/api/demo/profile',{profile:e.target.value});};
setInterval(()=>document.getElementById('clock').textContent=new Date().toLocaleTimeString('ru-RU'),1000);
setInterval(tick,1000); tick();
</script>
</body></html>
"""
