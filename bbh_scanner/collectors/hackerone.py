"""Collector HackerOne — Hacker API v1.

- Auth: HTTP Basic (username = API token identifier, password = token value).
- Rate limit lettura: 600 req/min (300 per i report). Throttle + backoff su 429.
- Sync incrementale: gli structured_scopes si filtrano per `updated_at` (novità 2026),
  quindi dopo la prima sync scarichiamo solo gli scope cambiati.

Il parsing (`parse_program`, `parse_scope`) è separato dalla rete: testabile senza token.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from bbh_scanner.collectors.base import Collector, Program, Scope
from bbh_scanner.config import HackerOneConfig
from bbh_scanner.normalize import detect_and_normalize

PLATFORM = "hackerone"

# Tipi di asset che il toolchain web sa gestire; gli altri li registriamo ma non
# li scheduliamo per il recon.
WEB_ASSET_TYPES = {"URL", "WILDCARD", "CIDR", "OTHER", "API"}


def _b(value: Any) -> Optional[bool]:
    if value is None:
        return None
    return bool(value)


def parse_program(obj: Dict[str, Any]) -> Optional[Program]:
    """Mappa un oggetto 'program' della Hacker API nel modello comune."""
    attrs = obj.get("attributes", obj) if isinstance(obj, dict) else {}
    handle = attrs.get("handle") or obj.get("id")
    if not handle:
        return None
    return Program(
        platform=PLATFORM,
        handle=str(handle),
        name=attrs.get("name"),
        url=f"https://hackerone.com/{handle}",
        offers_bounties=_b(attrs.get("offers_bounties")),
        submission_state=attrs.get("submission_state"),
        state=attrs.get("state"),
        open_scope=_b(attrs.get("open_scope")),
    )


def parse_scope(obj: Dict[str, Any], handle: str) -> Optional[Scope]:
    """Mappa uno 'structured-scope' della Hacker API nel modello comune."""
    attrs = obj.get("attributes", obj) if isinstance(obj, dict) else {}
    asset_identifier = attrs.get("asset_identifier")
    if not asset_identifier:
        return None
    asset_identifier = str(asset_identifier).strip()
    ntype, nvalue = detect_and_normalize(asset_identifier)
    return Scope(
        platform=PLATFORM,
        program_handle=handle,
        asset_identifier=asset_identifier,
        normalized_type=ntype,
        normalized_value=nvalue,
        asset_type=attrs.get("asset_type"),
        eligible_for_bounty=_b(attrs.get("eligible_for_bounty")),
        eligible_for_submission=_b(attrs.get("eligible_for_submission")),
        max_severity=attrs.get("max_severity"),
        instruction=attrs.get("instruction"),
        created_at=attrs.get("created_at"),
        updated_at=attrs.get("updated_at"),
    )


def program_is_interesting(p: Program) -> bool:
    """Filtro a monte: monitoriamo solo programmi aperti che offrono bounty."""
    if p.submission_state and p.submission_state != "open":
        return False
    if p.offers_bounties is False:
        return False
    return True


class HackerOneClient:
    """Client HTTP con throttle e backoff. `session` è iniettabile per i test."""

    def __init__(self, config: HackerOneConfig, session: Any = None,
                 sleep=time.sleep):
        self.config = config
        self._sleep = sleep
        self._min_interval = 60.0 / max(1, config.max_requests_per_min)
        self._last_request = 0.0
        if session is not None:
            self.session = session
        else:
            import requests

            self.session = requests.Session()
            self.session.auth = (config.username, config.token)

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        wait = self._min_interval - elapsed
        if wait > 0:
            self._sleep(wait)
        self._last_request = time.monotonic()

    def get(self, path: str, params: Optional[Dict[str, Any]] = None,
            max_retries: int = 4) -> Dict[str, Any]:
        url = f"{self.config.base_url}/{path.lstrip('/')}"
        attempt = 0
        while True:
            self._throttle()
            resp = self.session.get(url, params=params, timeout=30)
            status = getattr(resp, "status_code", 200)
            if status == 429 and attempt < max_retries:
                retry_after = _retry_after(resp, attempt)
                self._sleep(retry_after)
                attempt += 1
                continue
            resp.raise_for_status()
            return resp.json()

    def iter_pages(self, path: str, params: Optional[Dict[str, Any]] = None):
        """Itera le pagine seguendo `links.next`."""
        params = dict(params or {})
        page = 1
        while True:
            page_params = dict(params)
            page_params["page[number]"] = page
            body = self.get(path, params=page_params)
            data = body.get("data", [])
            yield data
            links = body.get("links", {}) or {}
            if not links.get("next"):
                break
            page += 1


def _retry_after(resp: Any, attempt: int) -> float:
    headers = getattr(resp, "headers", {}) or {}
    ra = headers.get("Retry-After")
    if ra:
        try:
            return float(ra)
        except ValueError:
            pass
    return min(2 ** attempt, 16)  # backoff esponenziale, cap 16s


class HackerOneCollector(Collector):
    """Implementazione `Collector` per HackerOne."""

    platform = PLATFORM

    def __init__(self, client: HackerOneClient):
        self.client = client

    def list_programs(self) -> List[Program]:
        out: List[Program] = []
        for page in self.client.iter_pages("programs"):
            for obj in page:
                p = parse_program(obj)
                if p:
                    out.append(p)
        return out

    def list_scopes(self, handle: str,
                   updated_since: Optional[str] = None) -> List[Scope]:
        params: Dict[str, Any] = {}
        if updated_since:
            params["filter[updated_at__gt]"] = updated_since
        out: List[Scope] = []
        for page in self.client.iter_pages(
            f"programs/{handle}/structured_scopes", params=params
        ):
            for obj in page:
                s = parse_scope(obj, handle)
                if s:
                    out.append(s)
        return out
