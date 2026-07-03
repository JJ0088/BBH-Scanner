from bbh_scanner.config import TelegramConfig
from bbh_scanner.notify.base import NullNotifier
from bbh_scanner.notify.telegram import TelegramNotifier, build_notifier


class _FakeResp:
    status_code = 200


class _FakeSession:
    def __init__(self):
        self.posts = []

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        return _FakeResp()


def test_null_notifier():
    assert NullNotifier().send("x") is False


def test_build_notifier_falls_back_to_null_when_unconfigured():
    n = build_notifier(TelegramConfig(bot_token="", chat_id=""))
    assert isinstance(n, NullNotifier)


def test_telegram_sends_payload():
    cfg = TelegramConfig(bot_token="BOT", chat_id="42")
    session = _FakeSession()
    notifier = TelegramNotifier(cfg, session=session)
    assert notifier.send("ciao") is True
    url, payload = session.posts[0]
    assert "botBOT/sendMessage" in url
    assert payload["chat_id"] == "42"
    assert payload["text"] == "ciao"
