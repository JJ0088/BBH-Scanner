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
    # senza tool, il seed 'acme.com' diventa un asset subdomain; il baseline NON crea findings
    assert store.stats()["assets"] >= 1
    assert store.stats()["findings"] == 0

    # secondo giro: nessun programma dovuto (last_recon_at appena impostato) → 0
    assert orch.do_recon() == 0


def test_recon_findings_are_deltas_not_baseline(tmp_path, monkeypatch):
    from bbh_scanner.recon.passive import ReconResult
    _config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_program(store)

    # baseline: due sottodomini → 2 asset, ZERO findings (è il punto di partenza)
    orch._persist_and_mark("hackerone", "acme", ReconResult(
        handle="acme", subdomains=["a.acme.com", "b.acme.com"], skipped_steps=["httpx"]))
    assert store.stats()["assets"] == 2
    assert store.stats()["findings"] == 0

    # secondo giro: un sottodominio NUOVO → un solo finding (il delta)
    orch._persist_and_mark("hackerone", "acme", ReconResult(
        handle="acme", subdomains=["a.acme.com", "b.acme.com", "c.acme.com"],
        skipped_steps=["httpx"]))
    assert store.stats()["assets"] == 3
    assert store.stats()["findings"] == 1
    assert "c.acme.com" in store.list_findings(kind="new_subdomain")[0]["title"]


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


class _RecordingNotifier:
    def __init__(self):
        self.sent = []

    def send(self, text):
        self.sent.append(text)
        return True


def _seed_url_target(store):
    store.upsert_programs([{
        "platform": "hackerone", "handle": "acme",
        "offers_bounties": True, "submission_state": "open",
    }])
    store.upsert_scopes([{
        "id": "hackerone:acme:https://acme.com/", "platform": "hackerone",
        "program_handle": "acme", "asset_identifier": "https://acme.com/",
        "normalized_type": "url", "normalized_value": "https://acme.com/",
    }])


def test_active_scan_disabled_by_default(tmp_path, monkeypatch):
    _config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_program(store)
    assert orch.do_active_scan() == 0  # BBH_ACTIVE_SCAN non impostato


def test_active_scan_runs_and_filters_notifications(tmp_path, monkeypatch):
    monkeypatch.setenv("BBH_ACTIVE_SCAN", "1")
    monkeypatch.setenv("BBH_ANNOUNCE_PROGRESS", "0")  # isola il filtro notifiche findings
    _config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_url_target(store)

    import bbh_scanner.scheduler.orchestrator as om
    from bbh_scanner.active.nuclei import NucleiFinding, NucleiScanResult
    from bbh_scanner.recon.tools import ToolStatus

    monkeypatch.setattr(om, "check_tools",
                        lambda t=None: {"nuclei": ToolStatus("nuclei", True, "/x")})
    monkeypatch.setattr(om, "run_nuclei",
                        lambda handle, targets, workdir, cfg, nice=10, timeout=3600, tools=None:
                        NucleiScanResult(handle=handle, rc=0, findings=[
                            NucleiFinding("cve", "RCE", "high", "https://acme.com/x", "acme.com"),
                            NucleiFinding("tls", "TLS", "info", "https://acme.com/", "acme.com"),
                        ]))
    rec = _RecordingNotifier()
    orch.notifier = rec

    assert orch.do_active_scan() == 1
    assert len(store.list_findings(kind="vuln")) == 2

    orch.flush_notifications()
    # solo il finding high viene notificato; l'info è soppresso
    assert len(rec.sent) == 1
    assert "RCE" in rec.sent[0]


def test_active_scan_suspended_in_powersave(tmp_path, monkeypatch):
    monkeypatch.setenv("BBH_ACTIVE_SCAN", "1")
    _config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_url_target(store)

    import bbh_scanner.scheduler.orchestrator as om
    from bbh_scanner.recon.tools import ToolStatus
    monkeypatch.setattr(om, "check_tools",
                        lambda t=None: {"nuclei": ToolStatus("nuclei", True, "/x")})
    orch.set_mode("powersave")  # regime troppo basso per lo scan attivo
    assert orch.do_active_scan() == 0
    assert store.job_counts().get("queued") == 1  # accodato ma non eseguito


def test_baseline_recon_suppresses_notifications(tmp_path, monkeypatch):
    _config, store, orch = _setup(tmp_path, monkeypatch)
    _seed_program(store)
    rec = _RecordingNotifier()
    orch.notifier = rec
    orch.set_mode("powersave")

    orch.do_recon()
    rec.sent.clear()                              # scarta la notifica di cambio regime
    assert store.stats()["assets"] >= 1          # superficie mappata nel DB
    assert orch.flush_notifications() == 0        # ma niente notifiche di finding (baseline)
    assert rec.sent == []


def test_flush_batches_asset_deltas(tmp_path, monkeypatch):
    _config, store, orch = _setup(tmp_path, monkeypatch)
    rec = _RecordingNotifier()
    orch.notifier = rec
    for i in range(3):
        store.record_finding({"platform": "hackerone", "program_handle": "acme",
                              "kind": "new_subdomain", "fingerprint": f"s{i}",
                              "title": f"new_subdomain: s{i}"})
    for i in range(2):
        store.record_finding({"platform": "hackerone", "program_handle": "acme",
                              "kind": "new_host", "fingerprint": f"h{i}",
                              "title": f"new_host: h{i}"})

    sent = orch.flush_notifications()
    assert sent == 1                    # UN riepilogo, non 5 messaggi
    assert "+3 sottodomini" in rec.sent[0]
    assert "+2 host" in rec.sent[0]
    assert store.unnotified_findings() == []


def test_flush_vuln_medium_plus_only(tmp_path, monkeypatch):
    _config, store, orch = _setup(tmp_path, monkeypatch)
    rec = _RecordingNotifier()
    orch.notifier = rec
    store.record_finding({"platform": "hackerone", "program_handle": "acme", "kind": "vuln",
                          "fingerprint": "v1", "severity": "high", "title": "RCE @ x"})
    store.record_finding({"platform": "hackerone", "program_handle": "acme", "kind": "vuln",
                          "fingerprint": "v2", "severity": "info", "title": "TLS @ y"})

    sent = orch.flush_notifications()
    assert sent == 1                    # solo il high; l'info è soppresso
    assert "RCE" in rec.sent[0]
    assert store.unnotified_findings() == []   # anche l'info è marcato come visto


def test_request_stop_sets_flag(tmp_path, monkeypatch):
    _config, _store, orch = _setup(tmp_path, monkeypatch)
    assert not orch._stop.is_set()
    orch.request_stop()
    assert orch._stop.is_set()


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
