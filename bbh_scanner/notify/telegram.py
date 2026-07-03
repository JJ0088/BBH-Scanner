"""Notifiche via Telegram Bot API.

Costruzione della richiesta separata dall'invio, così `build_message`/`_endpoint`
sono testabili senza rete.
"""

from __future__ import annotations

from typing import Any, Optional

from bbh_scanner.config import TelegramConfig
from bbh_scanner.notify.base import NullNotifier, Notifier


class TelegramNotifier:
    def __init__(self, config: TelegramConfig, session: Any = None):
        self.config = config
        if session is not None:
            self.session = session
        else:
            import requests

            self.session = requests.Session()

    def _endpoint(self) -> str:
        return f"https://api.telegram.org/bot{self.config.bot_token}/sendMessage"

    def _payload(self, text: str) -> dict:
        return {
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

    def send(self, text: str) -> bool:
        if not self.config.configured:
            return False
        try:
            resp = self.session.post(self._endpoint(), json=self._payload(text), timeout=10)
            return getattr(resp, "status_code", 500) == 200
        except Exception:
            return False


def build_notifier(config: TelegramConfig, session: Any = None) -> Notifier:
    """Ritorna un TelegramNotifier se configurato, altrimenti un NullNotifier."""
    if config.configured:
        return TelegramNotifier(config, session=session)
    return NullNotifier()
