from bbh_scanner.config import Config
from bbh_scanner.health import has_blocking_failures, run_checks


def test_run_checks_minimal(tmp_path, monkeypatch):
    for v in ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN",
              "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("BBH_ROOT", str(tmp_path))
    monkeypatch.setenv("BBH_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BBH_DB_PATH", str(tmp_path / "data" / "store.db"))

    checks = run_checks(Config.load(), online=False)
    levels = {c.name: c.level for c in checks}
    assert levels["database"] == "ok"          # DB scrivibile
    assert levels["hackerone"] == "warn"       # niente credenziali
    assert levels["telegram"] == "warn"        # niente token
    assert levels["tool-recon"] == "warn"      # nessun tool nel container
    # nessun controllo bloccante → si può comunque avviare
    assert has_blocking_failures(checks) is False


def test_run_checks_with_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("BBH_ROOT", str(tmp_path))
    monkeypatch.setenv("BBH_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BBH_DB_PATH", str(tmp_path / "data" / "store.db"))
    monkeypatch.setenv("HACKERONE_API_USERNAME", "u")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "t")

    checks = run_checks(Config.load(), online=False)
    levels = {c.name: c.level for c in checks}
    assert levels["hackerone"] == "ok"
