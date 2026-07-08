from bbh_scanner import systemd


def test_notify_noop_without_socket(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert systemd.notify_ready() is False
    assert systemd.notify_watchdog() is False
    assert systemd.notify_stopping() is False


def test_notify_bad_socket_is_safe(monkeypatch):
    # socket inesistente: non deve sollevare, ritorna False
    monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent/bbh.sock")
    assert systemd.notify_ready() is False
