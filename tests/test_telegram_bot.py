from bbh_scanner.config import MODE_OVERRIDE_KEY, Config
from bbh_scanner.db.store import Store
from bbh_scanner.telegram_bot import HELP, TelegramPoller, handle_command


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("BBH_ROOT", str(tmp_path))
    monkeypatch.setenv("BBH_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BBH_DB_PATH", str(tmp_path / "data" / "s.db"))
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "BOT")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
    config = Config.load()
    config.ensure_dirs()
    return config, Store(config.db_path)


def test_help_and_noncommand(tmp_path, monkeypatch):
    config, store = _setup(tmp_path, monkeypatch)
    assert handle_command("/help", store, config) == HELP
    assert handle_command("/start", store, config) == HELP
    assert handle_command("ciao", store, config) is None      # non è un comando


def test_mode_command_sets_state(tmp_path, monkeypatch):
    config, store = _setup(tmp_path, monkeypatch)
    reply = handle_command("/mode turbo", store, config)
    assert "turbo" in reply
    assert store.get_state(MODE_OVERRIDE_KEY) == "turbo"
    assert "uso:" in handle_command("/mode nope", store, config)
    handle_command("/pause", store, config)
    assert store.get_state(MODE_OVERRIDE_KEY) == "paused"
    handle_command("/resume", store, config)
    assert store.get_state(MODE_OVERRIDE_KEY) == "auto"


def test_status_findings_logs(tmp_path, monkeypatch):
    config, store = _setup(tmp_path, monkeypatch)
    store.log_event("INFO", "test", "evento-x")
    store.record_finding({"platform": "hackerone", "program_handle": "acme", "kind": "vuln",
                          "fingerprint": "v1", "severity": "high", "title": "RCE"})
    assert "BBH-Scanner" in handle_command("/status", store, config)
    assert "RCE" in handle_command("/findings high", store, config)
    assert "evento-x" in handle_command("/logs 5", store, config)
    assert "coda" in handle_command("/jobs", store, config)


def test_unknown_command(tmp_path, monkeypatch):
    config, store = _setup(tmp_path, monkeypatch)
    assert "sconosciuto" in handle_command("/pippo", store, config)


def test_handles_botname_suffix(tmp_path, monkeypatch):
    config, store = _setup(tmp_path, monkeypatch)
    assert handle_command("/help@bbh_scanner_bot", store, config) == HELP


# --- Sicurezza del poller: ignora chat non autorizzate --------------------- #

class _Resp:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _FakeSession:
    def __init__(self, updates):
        self._updates = updates
        self.sent = []

    def get(self, url, params=None, timeout=None):
        if "getUpdates" in url:
            return _Resp({"result": self._updates})
        if "sendMessage" in url:
            self.sent.append(params)
            return _Resp({"ok": True})
        return _Resp({})


def test_poll_once_ignores_other_chats(tmp_path, monkeypatch):
    config, store = _setup(tmp_path, monkeypatch)
    updates = [
        {"update_id": 1, "message": {"chat": {"id": 999}, "text": "/status"}},  # estranea
        {"update_id": 2, "message": {"chat": {"id": 42}, "text": "/help"}},     # autorizzata
    ]
    session = _FakeSession(updates)
    poller = TelegramPoller(config, store.db_path, session=session)
    new_offset = poller.poll_once(store, 0)

    assert new_offset == 3                       # offset avanzato oltre l'ultimo update
    assert len(session.sent) == 1                # ha risposto solo alla chat 42
    assert str(session.sent[0]["chat_id"]) == "42"
