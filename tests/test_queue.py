from datetime import datetime, timedelta, timezone

from bbh_scanner.scheduler.queue import select_due


def _now():
    return datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)


def test_never_scanned_is_first():
    programs = [
        {"platform": "hackerone", "handle": "old", "enabled": 1,
         "scope_hash": "h", "last_recon_hash": "h",
         "last_recon_at": (_now() - timedelta(days=10)).isoformat()},
        {"platform": "hackerone", "handle": "new", "enabled": 1,
         "scope_hash": "h", "last_recon_hash": None, "last_recon_at": None},
    ]
    due = select_due(programs, _now(), interval_sec=3600)
    assert due[0].handle == "new"
    assert due[0].reason == "mai-scansionato"


def test_changed_scope_prioritized_over_stale():
    programs = [
        {"platform": "hackerone", "handle": "stale", "enabled": 1,
         "scope_hash": "h", "last_recon_hash": "h",
         "last_recon_at": (_now() - timedelta(days=30)).isoformat()},
        {"platform": "hackerone", "handle": "changed", "enabled": 1,
         "scope_hash": "NEW", "last_recon_hash": "OLD",
         "last_recon_at": (_now() - timedelta(hours=1)).isoformat()},
    ]
    due = select_due(programs, _now(), interval_sec=3600)
    handles = [c.handle for c in due]
    assert handles.index("changed") < handles.index("stale")


def test_not_due_excluded():
    programs = [
        {"platform": "hackerone", "handle": "fresh", "enabled": 1,
         "scope_hash": "h", "last_recon_hash": "h",
         "last_recon_at": (_now() - timedelta(minutes=5)).isoformat()},
    ]
    assert select_due(programs, _now(), interval_sec=3600) == []


def test_disabled_excluded():
    programs = [
        {"platform": "hackerone", "handle": "off", "enabled": 0,
         "scope_hash": "h", "last_recon_hash": None, "last_recon_at": None},
    ]
    assert select_due(programs, _now(), interval_sec=3600) == []
