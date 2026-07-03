from bbh_scanner.collectors import sync as sync_mod
from bbh_scanner.collectors.hackerone import (
    HackerOneClient,
    HackerOneCollector,
    parse_program,
    parse_scope,
    program_is_interesting,
)
from bbh_scanner.config import HackerOneConfig
from bbh_scanner.db.store import Store


def test_parse_program():
    obj = {
        "id": "1", "type": "program",
        "attributes": {
            "handle": "acme", "name": "Acme", "offers_bounties": True,
            "submission_state": "open", "state": "public_mode", "open_scope": True,
        },
    }
    p = parse_program(obj)
    assert p.handle == "acme"
    assert p.offers_bounties is True
    assert p.url == "https://hackerone.com/acme"


def test_parse_scope_normalizes():
    obj = {
        "id": "9", "type": "structured-scope",
        "attributes": {
            "asset_identifier": "*.acme.com", "asset_type": "WILDCARD",
            "eligible_for_bounty": True, "updated_at": "2026-01-02T00:00:00Z",
        },
    }
    s = parse_scope(obj, "acme")
    assert s.normalized_type == "wildcard"
    assert s.asset_identifier == "*.acme.com"
    assert s.id == "hackerone:acme:*.acme.com"


def test_program_is_interesting():
    good = parse_program({"attributes": {"handle": "a", "submission_state": "open",
                                         "offers_bounties": True}})
    closed = parse_program({"attributes": {"handle": "b", "submission_state": "closed",
                                           "offers_bounties": True}})
    nobounty = parse_program({"attributes": {"handle": "c", "submission_state": "open",
                                             "offers_bounties": False}})
    assert program_is_interesting(good)
    assert not program_is_interesting(closed)
    assert not program_is_interesting(nobounty)


# --- Fake transport per testare paginazione e sync senza rete --------------- #

class _FakeResponse:
    def __init__(self, body, status=200):
        self._body = body
        self.status_code = status
        self.headers = {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeSession:
    """Risponde in base al path: programs (1 pagina) e structured_scopes (1 pagina)."""

    def __init__(self):
        self.auth = None
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params))
        if url.endswith("/programs"):
            return _FakeResponse({
                "data": [{
                    "attributes": {
                        "handle": "acme", "name": "Acme", "offers_bounties": True,
                        "submission_state": "open",
                    }
                }],
                "links": {},
            })
        if "structured_scopes" in url:
            return _FakeResponse({
                "data": [
                    {"attributes": {"asset_identifier": "*.acme.com",
                                    "asset_type": "WILDCARD",
                                    "updated_at": "2026-01-03T00:00:00Z"}},
                    {"attributes": {"asset_identifier": "api.acme.com",
                                    "asset_type": "URL",
                                    "updated_at": "2026-01-02T00:00:00Z"}},
                ],
                "links": {},
            })
        return _FakeResponse({"data": [], "links": {}})


def _collector():
    cfg = HackerOneConfig(username="u", token="t", max_requests_per_min=100000)
    client = HackerOneClient(cfg, session=_FakeSession(), sleep=lambda *_: None)
    return HackerOneCollector(client)


def test_collector_list_programs_and_scopes():
    coll = _collector()
    programs = coll.list_programs()
    assert [p.handle for p in programs] == ["acme"]
    scopes = coll.list_scopes("acme")
    assert {s.normalized_type for s in scopes} == {"wildcard", "api"}


def test_sync_persists(tmp_path):
    store = Store(tmp_path / "s.db")
    coll = _collector()
    result = sync_mod.sync(coll, store)
    assert result.programs_kept == 1
    assert result.scopes_upserted == 2
    progs = store.list_programs()
    assert progs[0]["scope_count"] == 2
    assert progs[0]["scope_hash"]
    # il cursore incrementale è impostato all'updated_at più recente
    assert store.get_state("hackerone:acme:scopes_updated_cursor") == "2026-01-03T00:00:00Z"


def test_incremental_second_sync_uses_cursor(tmp_path):
    store = Store(tmp_path / "s.db")
    coll = _collector()
    sync_mod.sync(coll, store)
    coll.client.session.calls.clear()
    sync_mod.sync(coll, store)
    # la seconda sync deve passare il filtro updated_at__gt sugli scope
    scope_calls = [c for c in coll.client.session.calls if "structured_scopes" in c[0]]
    assert scope_calls
    assert any("filter[updated_at__gt]" in (c[1] or {}) for c in scope_calls)
