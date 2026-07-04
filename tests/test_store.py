from bbh_scanner.db.store import Store


def _store(tmp_path):
    return Store(tmp_path / "test.db")


def test_migrate_creates_schema(tmp_path):
    store = _store(tmp_path)
    assert store.stats() == {
        "programs": 0, "scopes": 0, "assets": 0, "findings": 0, "jobs": 0
    }


def test_upsert_programs_idempotent(tmp_path):
    store = _store(tmp_path)
    prog = {
        "platform": "hackerone", "handle": "acme", "name": "Acme",
        "offers_bounties": True, "submission_state": "open", "scope_count": 3,
    }
    assert store.upsert_programs([prog]) == 1
    store.upsert_programs([{**prog, "name": "Acme2"}])
    progs = store.list_programs()
    assert len(progs) == 1
    assert progs[0]["name"] == "Acme2"
    assert progs[0]["offers_bounties"] == 1


def test_upsert_scopes_and_list(tmp_path):
    store = _store(tmp_path)
    scope = {
        "id": "hackerone:acme:*.acme.com", "platform": "hackerone",
        "program_handle": "acme", "asset_identifier": "*.acme.com",
        "normalized_type": "wildcard", "normalized_value": "*.acme.com",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    assert store.upsert_scopes([scope]) == 1
    store.upsert_scopes([scope])  # idempotente
    scopes = store.list_scopes("hackerone", "acme")
    assert len(scopes) == 1
    assert store.list_scopes("hackerone", "acme", types=("domain",)) == []


def test_findings_dedup_and_notify(tmp_path):
    store = _store(tmp_path)
    f = {
        "platform": "hackerone", "program_handle": "acme", "kind": "new_subdomain",
        "fingerprint": "abc123", "title": "new_subdomain: x.acme.com",
    }
    assert store.record_finding(f) is True
    assert store.record_finding(f) is False  # stesso fingerprint
    pending = store.unnotified_findings()
    assert len(pending) == 1
    store.mark_notified([pending[0]["id"]])
    assert store.unnotified_findings() == []


def test_sync_state_roundtrip(tmp_path):
    store = _store(tmp_path)
    assert store.get_state("k") is None
    store.set_state("k", "v1")
    store.set_state("k", "v2")
    assert store.get_state("k") == "v2"


def test_events(tmp_path):
    store = _store(tmp_path)
    store.log_event("INFO", "test", "ciao", program_handle="acme")
    events = store.recent_events()
    assert events[0]["message"] == "ciao"
    assert events[0]["component"] == "test"


def test_prune_asset_findings(tmp_path):
    store = _store(tmp_path)
    store.record_finding({"platform": "h", "program_handle": "a", "kind": "new_subdomain",
                          "fingerprint": "s1", "title": "x"})
    store.record_finding({"platform": "h", "program_handle": "a", "kind": "new_host",
                          "fingerprint": "h1", "title": "y"})
    store.record_finding({"platform": "h", "program_handle": "a", "kind": "vuln",
                          "fingerprint": "v1", "severity": "high", "title": "z"})
    assert store.prune_asset_findings() == 2      # rimuove subdomain+host, tiene vuln
    assert store.stats()["findings"] == 1
    assert store.list_findings(kind="vuln")[0]["title"] == "z"


def test_asset_values(tmp_path):
    store = _store(tmp_path)
    from bbh_scanner.db.store import _now_iso
    with store.transaction() as c:
        c.execute("INSERT INTO assets(id,platform,program_handle,kind,value,first_seen_at,"
                  "last_seen_at) VALUES('i','h','a','subdomain','x.a.com',?,?);",
                  (_now_iso(), _now_iso()))
    assert store.asset_values("h", "a", "subdomain") == {"x.a.com"}
    assert store.asset_values("h", "a", "host") == set()


def test_summary(tmp_path):
    store = _store(tmp_path)
    store.upsert_programs([{
        "platform": "hackerone", "handle": "a", "offers_bounties": True,
        "submission_state": "open", "scope_count": 1,
    }])
    store.upsert_scopes([{
        "id": "hackerone:a:*.a.com", "platform": "hackerone", "program_handle": "a",
        "asset_identifier": "*.a.com", "normalized_type": "wildcard",
        "normalized_value": "*.a.com",
    }])
    store.record_finding({"platform": "hackerone", "program_handle": "a", "kind": "vuln",
                          "fingerprint": "v1", "severity": "high", "title": "x"})
    s = store.summary()
    assert s["stats"]["programs"] == 1
    assert s["programs_enabled"] == 1
    assert s["scope_types"].get("wildcard") == 1
    assert s["vuln_severities"].get("high") == 1
