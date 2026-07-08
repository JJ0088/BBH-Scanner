import os

from bbh_scanner.config import load_env_files


def test_load_env_file(tmp_path, monkeypatch):
    for k in ("BBH_TESTVAL", "BBH_QUOTED"):
        monkeypatch.delenv(k, raising=False)
    env = tmp_path / ".env"
    env.write_text("BBH_TESTVAL=fromfile\n# commento\nBBH_QUOTED='q'\n\n", encoding="utf-8")
    monkeypatch.setenv("BBH_ENV_FILE", str(env))

    loaded = load_env_files()
    assert env in loaded
    assert os.environ["BBH_TESTVAL"] == "fromfile"
    assert os.environ["BBH_QUOTED"] == "q"       # apici rimossi


def test_real_env_wins_over_file(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("BBH_TESTVAL=fromfile\n", encoding="utf-8")
    monkeypatch.setenv("BBH_ENV_FILE", str(env))
    monkeypatch.setenv("BBH_TESTVAL", "fromenv")

    load_env_files()
    assert os.environ["BBH_TESTVAL"] == "fromenv"  # l'ambiente reale ha la precedenza


def test_missing_file_is_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("BBH_ENV_FILE", str(tmp_path / "nope.env"))
    assert load_env_files() == []  # nessun file, nessun crash
