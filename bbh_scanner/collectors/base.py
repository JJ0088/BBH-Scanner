"""Astrazione comune a tutte le piattaforme (HackerOne, Bugcrowd, YesWeHack, Intigriti).

Ogni collector normalizza i dati della propria piattaforma nel modello comune e sa
sincronizzarli nello Store. HackerOne è l'unica implementazione in questa fase; la
firma è pensata perché aggiungere una piattaforma non tocchi lo scheduler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@dataclass
class Program:
    platform: str
    handle: str
    name: Optional[str] = None
    url: Optional[str] = None
    offers_bounties: Optional[bool] = None
    submission_state: Optional[str] = None
    state: Optional[str] = None
    open_scope: Optional[bool] = None

    def as_row(self) -> Dict[str, Any]:
        return {
            "platform": self.platform, "handle": self.handle, "name": self.name,
            "url": self.url, "offers_bounties": self.offers_bounties,
            "submission_state": self.submission_state, "state": self.state,
            "open_scope": self.open_scope,
        }


@dataclass
class Scope:
    platform: str
    program_handle: str
    asset_identifier: str
    normalized_type: str
    normalized_value: str
    asset_type: Optional[str] = None
    eligible_for_bounty: Optional[bool] = None
    eligible_for_submission: Optional[bool] = None
    max_severity: Optional[str] = None
    instruction: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.platform}:{self.program_handle}:{self.asset_identifier}"

    def as_row(self) -> Dict[str, Any]:
        return {
            "id": self.id, "platform": self.platform,
            "program_handle": self.program_handle,
            "asset_identifier": self.asset_identifier, "asset_type": self.asset_type,
            "eligible_for_bounty": self.eligible_for_bounty,
            "eligible_for_submission": self.eligible_for_submission,
            "max_severity": self.max_severity, "instruction": self.instruction,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "normalized_type": self.normalized_type,
            "normalized_value": self.normalized_value,
        }


@runtime_checkable
class Collector(Protocol):
    """Interfaccia comune. Ogni piattaforma la implementa."""

    platform: str

    def list_programs(self) -> List[Program]:
        ...

    def list_scopes(self, handle: str, updated_since: Optional[str] = None) -> List[Scope]:
        ...
