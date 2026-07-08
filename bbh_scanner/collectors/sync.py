"""Sincronizzazione collector -> Store.

Orchestrazione pura del flusso: lista programmi -> filtra -> upsert; per ogni
programma interessante scarica gli scope (incrementale via cursore updated_at) ->
upsert -> ricalcola scope_hash -> aggiorna cursore. Registra tutto su `events`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from bbh_scanner.collectors.base import Collector
from bbh_scanner.collectors.hackerone import program_is_interesting
from bbh_scanner.db.store import Store
from bbh_scanner.normalize import sha256_hex


@dataclass
class SyncResult:
    programs_seen: int = 0
    programs_kept: int = 0
    scopes_upserted: int = 0

    def __str__(self) -> str:
        return (
            f"programs_seen={self.programs_seen} programs_kept={self.programs_kept} "
            f"scopes_upserted={self.scopes_upserted}"
        )


def _cursor_key(platform: str, handle: str) -> str:
    return f"{platform}:{handle}:scopes_updated_cursor"


def sync(collector: Collector, store: Store,
         incremental: bool = True,
         only_handle: Optional[str] = None) -> SyncResult:
    result = SyncResult()
    platform = collector.platform

    programs = collector.list_programs()
    result.programs_seen = len(programs)

    kept = [p for p in programs if program_is_interesting(p)]
    if only_handle:
        kept = [p for p in kept if p.handle == only_handle]
    result.programs_kept = len(kept)

    store.upsert_programs([p.as_row() for p in kept])
    store.log_event(
        "INFO", "sync",
        f"programmi: visti={result.programs_seen} tenuti={result.programs_kept}",
        data={"platform": platform},
    )

    for p in kept:
        cursor = store.get_state(_cursor_key(platform, p.handle)) if incremental else None
        scopes = collector.list_scopes(p.handle, updated_since=cursor)
        if scopes:
            store.upsert_scopes([s.as_row() for s in scopes])
            result.scopes_upserted += len(scopes)

        # scope_hash e cursore si calcolano sull'insieme completo in DB.
        all_scopes = store.list_scopes(platform, p.handle)
        scope_hash = (
            sha256_hex(s["asset_identifier"] for s in all_scopes) if all_scopes else None
        )
        store.set_program_scope_summary(platform, p.handle, len(all_scopes), scope_hash)

        newest = _max_updated_at(all_scopes)
        if newest:
            store.set_state(_cursor_key(platform, p.handle), newest)

    store.log_event(
        "INFO", "sync", f"sync completata: {result}", data={"platform": platform}
    )
    return result


def _max_updated_at(scopes) -> Optional[str]:
    vals = [s.get("updated_at") for s in scopes if s.get("updated_at")]
    return max(vals) if vals else None
