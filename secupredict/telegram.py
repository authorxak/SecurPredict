"""Telegram bot: alert delivery, /start /stop /status and inline buttons.

Uses the Bot API over HTTPS with long polling and only the standard library.
The token comes from the environment; without it the bot stays disabled.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Optional, Set, Tuple

from .alerts import Alert
from .config import SEV_ORDER

log = logging.getLogger("secupredict.telegram")

BUTTONS: Dict[str, Tuple[str, str]] = {
    # callback prefix -> (button text, alert status)
    "ack": ("Принять", "ack"),
    "ours": ("Это мы", "ours"),
}
ANSWERS = {"ack": "Тревога принята", "ours": "Отмечено: это наши действия"}

Message = Tuple[str, Optional[Dict[str, Any]]]


def alert_keyboard(alert: Alert) -> Optional[Dict[str, Any]]:
    """Inline keyboard for critical alerts; other levels are sent without buttons."""
    if alert.severity != "critical":
        return None
    return {"inline_keyboard": [[
        {"text": text, "callback_data": "%s:%s" % (prefix, alert.id)}
        for prefix, (text, _status) in BUTTONS.items()
    ]]}


def parse_callback(data: str) -> Optional[Tuple[str, str]]:
    """"ack:1a2b3c4d" -> ("ack", "1a2b3c4d"). Anything else -> None."""
    prefix, _, alert_id = (data or "").partition(":")
    if prefix in BUTTONS and len(alert_id) == 8 and all(c in "0123456789abcdef" for c in alert_id):
        return prefix, alert_id
    return None


class TelegramBot:
    """Sends alerts to subscribers and applies button presses to alert status."""

    def __init__(self, token: str, data_dir: Path, dashboard_url: str, min_severity: str,
                 status_text: Callable[[], str], on_status: Callable[[str, str, str], bool],
                 allowed_chats: Tuple[int, ...] = (), quiet: bool = False) -> None:
        self.token = token
        self.dashboard_url = dashboard_url
        self.min_severity = min_severity
        self.status_text = status_text
        self.on_status = on_status
        self.allowed_chats = tuple(allowed_chats)
        self.quiet = quiet
        self.subs_path = Path(data_dir) / "tg_subscribers.json"
        self.subscribers: Set[int] = set()
        self.username = ""
        self.enabled = bool(token)
        self.online = False
        self._queue: "queue.Queue[Message]" = queue.Queue()
        self._pending: Deque[Message] = deque(maxlen=10)
        self._stop = threading.Event()
        self._warned_no_subs = False
        self._load_subs()
        self.subscribers.update(self.allowed_chats)

    # Subscribers ------------------------------------------------------------
    def _load_subs(self) -> None:
        try:
            self.subscribers = {int(x) for x in json.loads(self.subs_path.read_text("utf-8"))}
        except (OSError, ValueError, TypeError):
            self.subscribers = set()
        if self.allowed_chats:
            self.subscribers &= set(self.allowed_chats)

    def _save_subs(self) -> None:
        try:
            self.subs_path.write_text(json.dumps(sorted(self.subscribers)), "utf-8")
        except OSError as exc:
            log.error("Cannot save Telegram subscribers: %s", exc)

    def _allowed(self, chat_id: int) -> bool:
        return not self.allowed_chats or chat_id in self.allowed_chats

    # Bot API ----------------------------------------------------------------
    def _call(self, method: str, payload: Dict[str, Any], timeout: float = 15) -> Optional[Any]:
        url = "https://api.telegram.org/bot%s/%s" % (self.token, method)
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self.online = True
            return data.get("result") if data.get("ok") else None
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                log.error("Telegram: bot token rejected (401). Bot disabled.")
                self.enabled = False
            elif exc.code == 409:
                log.error("Telegram: webhook is set or a second copy is polling (409).")
            else:
                log.warning("Telegram %s: HTTP %s", method, exc.code)
        except Exception as exc:  # noqa: BLE001 - network errors, timeouts
            if self.online and not self.quiet:
                log.warning("Telegram unreachable: %s", exc.__class__.__name__)
            self.online = False
        return None

    def start(self) -> None:
        if not self.enabled:
            if not self.quiet:
                log.info("Telegram is off: alerts are shown on the dashboard only.")
            return
        me = self._call("getMe", {})
        if me:
            self.username = me.get("username", "")
        threading.Thread(target=self._poll_loop, name="tg-poll", daemon=True).start()
        threading.Thread(target=self._send_loop, name="tg-send", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    # Outgoing ---------------------------------------------------------------
    def notify(self, alert: Alert) -> None:
        """Queue an alert if its level is at or above the Telegram threshold."""
        if not self.enabled or SEV_ORDER[alert.severity] < SEV_ORDER[self.min_severity]:
            return
        self._queue.put((alert.to_telegram(self.dashboard_url), alert_keyboard(alert)))

    def _send(self, chat_id: int, text: str, markup: Optional[Dict[str, Any]] = None) -> None:
        payload: Dict[str, Any] = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                                   "disable_web_page_preview": True}
        if markup:
            payload["reply_markup"] = markup
        self._call("sendMessage", payload)
        time.sleep(0.05)

    def _send_loop(self) -> None:
        while not self._stop.is_set():
            try:
                text, markup = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            if not self.subscribers:
                self._pending.append((text, markup))
                if not self._warned_no_subs:
                    self._warned_no_subs = True
                    log.warning("No Telegram subscribers yet: send /start to @%s", self.username or "the bot")
                continue
            for chat_id in list(self.subscribers):
                self._send(chat_id, text, markup)

    # Incoming ---------------------------------------------------------------
    def handle_update(self, upd: Dict[str, Any]) -> None:
        """Process one update from getUpdates (message or button press)."""
        callback = upd.get("callback_query")
        if callback:
            self._handle_callback(callback)
            return
        msg = upd.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        text = (msg.get("text") or "").strip().lower()
        if chat_id is None:
            return
        if not self._allowed(chat_id):
            self._send(chat_id, "Этот чат не входит в список разрешённых (TG_CHAT_ID).")
            return
        if text.startswith("/start"):
            self.subscribers.add(chat_id)
            self._save_subs()
            self._send(chat_id, "Вы подписаны на тревоги SecuPredict.\n"
                                "Сообщение придёт, только когда что-то случится.\n"
                                "Команды: /status - сводка, /stop - отписаться.")
            while self._pending:
                queued_text, queued_markup = self._pending.popleft()
                self._send(chat_id, queued_text, queued_markup)
        elif text.startswith("/stop"):
            self.subscribers.discard(chat_id)
            self._save_subs()
            self._send(chat_id, "Вы отписаны от тревог. Вернуться: /start.")
        elif text.startswith("/status"):
            self._send(chat_id, self.status_text())

    def _handle_callback(self, callback: Dict[str, Any]) -> None:
        query_id = callback.get("id")
        message = callback.get("message") or {}
        chat_id = (message.get("chat") or {}).get("id")
        user = callback.get("from") or {}
        parsed = parse_callback(callback.get("data") or "")
        if chat_id is None or chat_id not in self.subscribers or not self._allowed(chat_id) or not parsed:
            self._call("answerCallbackQuery", {"callback_query_id": query_id, "text": "Действие недоступно"})
            return
        prefix, alert_id = parsed
        who = "telegram:%s" % (user.get("username") or user.get("id") or chat_id)
        ok = self.on_status(alert_id, BUTTONS[prefix][1], who)
        self._call("answerCallbackQuery", {
            "callback_query_id": query_id,
            "text": ANSWERS[prefix] if ok else "Тревога не найдена"})
        if ok and message.get("message_id") is not None:
            self._call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message["message_id"],
                                                  "reply_markup": {"inline_keyboard": []}})
            self._send(chat_id, "Статус тревоги %s: %s." % (alert_id, ANSWERS[prefix].lower()))

    def _poll_loop(self) -> None:
        offset = 0
        backoff = 3.0
        while not self._stop.is_set() and self.enabled:
            updates = self._call("getUpdates", {"offset": offset, "timeout": 25,
                                                "allowed_updates": ["message", "callback_query"]}, timeout=35)
            if updates is None:
                self._stop.wait(backoff)
                backoff = min(60.0, backoff * 2)
                continue
            backoff = 3.0
            for upd in updates:
                offset = upd["update_id"] + 1
                try:
                    self.handle_update(upd)
                except Exception as exc:  # noqa: BLE001
                    log.error("Telegram update failed: %s", exc)
