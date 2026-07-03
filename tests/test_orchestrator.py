from bbh_scanner.config import Config
from bbh_scanner.db.store import Store
from bbh_scanner.recon.passive import ReconResult
from bbh_scanner.resources.governor import Governor
from bbh_scanner.resources.sensors import SensorReading
from bbh_scanner.scheduler.orchestrator import Orchestrator


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("BBH_ROOT", str(tmp_path))
    monkeypatch.setenv("BBH_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BBH_DB_PATH", str(tmp_path / "data" / "store.db"))
    config = Config.load()
    config.ensure_dirs()
    store = Store(config.db_path)
    # governor deterministico (nessun sensore reale nei test)
    gov = Governor(config.governor,
                   sampler=lambda: SensorReading(cpu_temp=55.0, cpu_load=5.0, on_battery=False))
    orch = Orchestrator(config, store, governor=gov)
    return config, store, orch


def _seed_program(store):
    store.upsert_programs([{
        "platform": "hackerone", "handle": "acme",
        "offers_bounties": True, "submission_state": "open",
    }])
    store.upsert_scopes([{
        "id": "hackerone:acme:*.acme.com", "platform": "hackerone",
        "program_handle": "acme", "asset_identifier": "*.acme.com",
        "normalized_type": "wildcard", "normalized_value": "*.acme.com",
    }])


def test_do_recon_drains_job_queue(tmp_path, monkeypatch):
    config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_program(store)
    orch.set_mode("powersave")  # concorrenza 1, deterministico

    processed = orch.do_recon()
    assert processed == 1
    assert store.job_counts().get("done") == 1
    # senza tool, il seed 'acme.com' diventa un asset subdomain + finding new_subdomain
    assert store.stats()["assets"] >= 1
    assert store.stats()["findings"] >= 1

    # secondo giro: nessun programma dovuto (last_recon_at appena impostato) → 0
    assert orch.do_recon() == 0


def test_paused_governor_skips_recon(tmp_path, monkeypatch):
    config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_program(store)
    # temperatura critica → PAUSED
    orch.governor._sampler = lambda: SensorReading(cpu_temp=95.0)
    processed = orch.do_recon()
    assert processed == 0
    # il job resta in coda (queued), pronto per il prossimo tick
    assert store.job_counts().get("queued") == 1


def test_host_down_detection(tmp_path, monkeypatch):
    config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_program(store)

    # 1ª passata: due host vivi (httpx ha girato → skipped_steps senza 'httpx')
    r1 = ReconResult(handle="acme", subdomains=["a.acme.com", "b.acme.com"],
                     alive=["https://a.acme.com/", "https://b.acme.com/"], skipped_steps=[])
    orch._persist_recon("hackerone", "acme", r1)
    assert set(store.alive_hosts("hackerone", "acme")) == {
        "https://a.acme.com/", "https://b.acme.com/"
    }

    # 2ª passata: b non risponde più → host_down
    r2 = ReconResult(handle="acme", subdomains=["a.acme.com", "b.acme.com"],
                     alive=["https://a.acme.com/"], skipped_steps=[])
    orch._persist_recon("hackerone", "acme", r2)
    assert store.alive_hosts("hackerone", "acme") == ["https://a.acme.com/"]
    kinds = {f["kind"] for f in store.unnotified_findings(limit=100)}
    assert "host_down" in kinds


def test_no_false_host_down_when_httpx_skipped(tmp_path, monkeypatch):
    config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_program(store)
    r1 = ReconResult(handle="acme", subdomains=["a.acme.com"],
                     alive=["https://a.acme.com/"], skipped_steps=[])
    orch._persist_recon("hackerone", "acme", r1)
    # httpx saltato (tool assente): alive vuoto, ma NON deve marcare host_down
    r2 = ReconResult(handle="acme", subdomains=["a.acme.com"],
                     alive=[], skipped_steps=["httpx"])
    orch._persist_recon("hackerone", "acme", r2)
    assert store.alive_hosts("hackerone", "acme") == ["https://a.acme.com/"]
    kinds = {f["kind"] for f in store.unnotified_findings(limit=100)}
    assert "host_down" not in kinds
