"""Selezione e prioritizzazione dei job di recon — logica PURA (testata).

Regola: un asset nuovo o cambiato = superficie non ancora testata, quindi va per
primo. Ordine di priorità:
  1. programmi mai sottoposti a recon;
  2. programmi il cui scope_hash è cambiato dall'ultima recon;
  3. i più stantii (last_recon_at più vecchio) oltre l'intervallo.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


@dataclass(order=True)
class JobCandidate:
    # `sort_index` guida l'ordinamento: valori più bassi = priorità più alta.
    sort_index: int
    handle: str
    platform: str
    reason: str

    @property
    def priority(self) -> int:
        return -self.sort_index


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def select_due(programs: List[Dict[str, Any]], now: datetime,
               interval_sec: int) -> List[JobCandidate]:
    """Ritorna i candidati recon *dovuti*, ordinati per priorità decrescente.

    Ogni programma è un dict con almeno: platform, handle, enabled, scope_hash,
    last_recon_at (ISO|None), last_recon_hash (ISO|None).
    """
    interval = timedelta(seconds=interval_sec)
    candidates: List[JobCandidate] = []

    for p in programs:
        if not p.get("enabled", 1):
            continue
        handle = p.get("handle")
        platform = p.get("platform", "hackerone")
        if not handle:
            continue

        last_recon = _parse_iso(p.get("last_recon_at"))
        scope_hash = p.get("scope_hash")
        last_hash = p.get("last_recon_hash")

        if last_recon is None:
            candidates.append(JobCandidate(0, handle, platform, "mai-scansionato"))
            continue

        if scope_hash and scope_hash != last_hash:
            candidates.append(JobCandidate(1, handle, platform, "scope-cambiato"))
            continue

        if now - last_recon >= interval:
            # più vecchio = sort_index più basso entro la fascia "stantio".
            age_sec = int((now - last_recon).total_seconds())
            candidates.append(
                JobCandidate(max(2, 10_000_000 - age_sec), handle, platform, "stantio")
            )

    candidates.sort()
    return candidates
