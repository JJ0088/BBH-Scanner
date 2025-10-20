#!/usr/bin/env python3
"""
import_scopes.py — importa il dump HackerOne nel DB SQLite (con filtri incrementali)
+ logging uniforme timestampato, Slack opzionale e timing.

Novità operative:
- Log file: logs/bbh_importer<YYYY.MM.DD-HH.MM.SS>.log
- Riepilogo finale con durata e contatori (stdout + log + Slack se SLACK_WEBHOOK_URL)
- Nessun cambio alla logica dati rispetto all'ultima versione
"""

from __future__ import annotations
from pathlib import Path
import argparse
import json
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone
import os
import sys
import time
import logging

# --- PATH dinamici e import del package locale ---
_DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("BBH_ROOT", str(_DEFAULT_ROOT)))
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from typing import List, Dict, Tuple

try:
    from bbh_code.store import Store, init_db  # type: ignore
except ModuleNotFoundError as e:
    msg = (
        "Impossibile importare bbh_code.store.\n"
        "Assicurati che la cartella del package si chiami 'bbh_code' (underscore),\n"
        "che contenga un __init__.py, e che tu stia lanciando il comando dalla root del progetto.\n"
        "Esempio: python -m bbh_code.import_scopes -i data/H1-All-Scopes.json\n"
    )
    raise SystemExit(msg) from e

# --- Logging uniforme ---
LOGS_DIR = ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_ts = datetime.now().strftime("%Y.%m.%d-%H.%M.%S")
IMPORT_LOG_FILE = LOGS_DIR / f"bbh_importer{_ts}.log"
logging.basicConfig(
    filename=str(IMPORT_LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [importer] %(message)s",
)
logger = logging.getLogger("importer")

# --- Slack opzionale ---
import urllib.request as _ur

def notify_slack(text: str) -> None:
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return
    try:
        data = json.dumps({"text": text}).encode("utf-8")
        req = _ur.Request(url, data=data, headers={"Content-Type": "application/json"})
        _ur.urlopen(req, timeout=5).read()
    except Exception:
        # non bloccare l'import in caso di errore di notifica
        logger.warning("Slack notify fallita", exc_info=False)

# --- Helpers di normalizzazione ---

def _is_url(s: str) -> bool:
    s = s.strip()
    return s.startswith("http://") or s.startswith("https://")


def _is_wildcard(s: str) -> bool:
    return "*" in s


def _clean_url(u: str) -> str:
    u = u.strip()
    try:
        p = urlparse(u)
        p = p._replace(fragment="")
        return urlunparse(p)
    except Exception:
        return u


def _hostname_from_any(s: str) -> str | None:
    try:
        if _is_url(s):
            return urlparse(s).hostname
        host = s.strip().replace("*.", "").strip()
        if "." in host and "/" not in host and not host.startswith("http"):
            return host
    except Exception:
        return None
    return None


def detect_and_normalize(asset_identifier: str) -> Tuple[str, str]:
    a = asset_identifier.strip()
    if _is_wildcard(a):
        return ("wildcard", a)
    if _is_url(a):
        host = urlparse(a).hostname or ""
        if "/api" in a or host.startswith("api.") or ".api." in host:
            return ("api", _clean_url(a))
        return ("url", _clean_url(a))
    host = _hostname_from_any(a)
    if host:
        if host.startswith("api.") or ".api." in host:
            return ("api", f"https://{host}/")
        return ("domain", f"https://{host}/")
    return ("url", _clean_url(a))


def sha256_hex(items: List[str]) -> str:
    import hashlib
    h = hashlib.sha256()
    for s in sorted(items):
        h.update(s.encode("utf-8", errors="ignore"))
    return h.hexdigest()


class DummyCtx:
    def __enter__(self):
        return None
    def __exit__(self, *exc):
        return False


# --- Loader JSON robusto ---

def load_programs(data: object) -> List[Dict]:
    if isinstance(data, dict) and isinstance(data.get("programs"), dict):
        out = []
        for handle, pdata in data["programs"].items():  # type: ignore[assignment]
            if not isinstance(pdata, dict):
                continue
            if "handle" not in pdata or not pdata["handle"]:
                pdata = {**pdata, "handle": handle}
            out.append(pdata)
        return out
    if isinstance(data, dict) and isinstance(data.get("programs"), list):
        return data["programs"]  # type: ignore[return-value]
    if isinstance(data, list):
        return data  # type: ignore[return-value]
    raise ValueError("Formato JSON non riconosciuto: atteso {programs:{...}} o {programs:[...]} o [...].")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Import principale ---

def import_scopes(
    json_path: Path,
    dry_run: bool = False,
    only_handles: str = "",
    progress: int = 1000,
    skip_ineligible: bool = False,
    min_updated_since: str = "",
) -> None:
    if not json_path.exists():
        raise FileNotFoundError(f"File non trovato: {json_path}")

    t0 = time.time()
    logger.info("start import: file=%s", str(json_path))

    raw = json.loads(json_path.read_text(encoding="utf-8"))
    programs = load_programs(raw)

    store = Store()
    only_set = {h.strip() for h in only_handles.split(",") if h.strip()}

    cutoff = None
    if min_updated_since:
        s = min_updated_since.strip()
        try:
            if len(s) == 10 and s[4] == "-" and s[7] == "-":
                s = s + "T00:00:00+00:00"
            s = s.replace("Z", "+00:00")
            cutoff = datetime.fromisoformat(s)
            if cutoff.tzinfo is None:
                cutoff = cutoff.replace(tzinfo=timezone.utc)
        except Exception:
            print(f"[warn] --min-updated-since non parseable: {min_updated_since}")
            logger.warning("min-updated-since non parseable: %s", min_updated_since)
            cutoff = None

    if not dry_run:
        store.conn.execute("PRAGMA journal_mode=WAL;")
        store.conn.execute("PRAGMA synchronous=NORMAL;")
        store.conn.execute("PRAGMA temp_store=MEMORY;")
        store.conn.execute("PRAGMA cache_size=-20000;")

    inserted_scopes = 0
    inserted_programs = 0

    with (store.conn if not dry_run else DummyCtx()):
        for p in programs:
            handle = p.get("handle") or p.get("name") or p.get("id")
            if not handle:
                continue
            if only_set and handle not in only_set:
                continue

            program_id = str(p.get("id") or handle)
            name = p.get("name") or handle
            url = p.get("url") or p.get("profile_url") or None
            state = p.get("state") or p.get("program_state") or None
            submission_state = p.get("submission_state") or None
            last_fetch_at = now_iso()

            scopes_list = []
            if isinstance(p.get("scopes"), list):
                scopes_list = p["scopes"]
            elif isinstance(p.get("relationships"), dict):
                rel = p["relationships"]
                if isinstance(rel.get("structured_scopes"), dict) and isinstance(rel["structured_scopes"].get("data"), list):
                    scopes_list = rel["structured_scopes"]["data"]

            asset_ids: List[str] = []
            for s in scopes_list:
                if isinstance(s, dict) and "attributes" in s:
                    attrs = s["attributes"]
                    ai = attrs.get("asset_identifier")
                    at = attrs.get("asset_type")
                    elig = attrs.get("eligible_for_bounty")
                    instr = attrs.get("instruction")
                    maxsev = attrs.get("max_severity")
                    created = attrs.get("created_at")
                    updated = attrs.get("updated_at")
                    scope_id = str(s.get("id") or f"{handle}:{ai}")
                else:
                    ai = s.get("asset_identifier") if isinstance(s, dict) else None
                    at = s.get("asset_type") if isinstance(s, dict) else None
                    elig = s.get("eligible_for_bounty") if isinstance(s, dict) else None
                    instr = s.get("instruction") if isinstance(s, dict) else None
                    maxsev = s.get("max_severity") if isinstance(s, dict) else None
                    created = s.get("created_at") if isinstance(s, dict) else None
                    updated = s.get("updated_at") if isinstance(s, dict) else None
                    scope_id = str(s.get("id") if isinstance(s, dict) and s.get("id") else f"{handle}:{ai}")

                if isinstance(ai, str):
                    ai = ai.strip()
                if not ai:
                    continue

                if skip_ineligible and (elig is False or elig == 0 or str(elig).lower() == "false"):
                    continue

                if cutoff and updated:
                    try:
                        u = str(updated).strip().replace("Z", "+00:00")
                        ts = datetime.fromisoformat(u)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        if ts < cutoff:
                            continue
                    except Exception:
                        pass

                ntype, nvalue = detect_and_normalize(str(ai))
                asset_ids.append(str(ai))

                if not dry_run:
                    Store().save_scope({  # usa una nuova connessione? preferiamo riusare store
                        "id": scope_id,
                        "program_handle": handle,
                        "asset_identifier": str(ai),
                        "asset_type": at,
                        "eligible_for_bounty": int(bool(elig)) if elig is not None else None,
                        "instruction": instr,
                        "max_severity": maxsev,
                        "created_at": created,
                        "updated_at": updated or now_iso(),
                        "normalized_type": ntype,
                        "normalized_value": nvalue,
                    })

                inserted_scopes += 1
                if inserted_scopes % max(1, progress) == 0:
                    logger.info("progress scopes=%d", inserted_scopes)
                    print(f"[import] scopes inseriti: {inserted_scopes}", flush=True)

            scope_hash = sha256_hex(asset_ids) if asset_ids else None
            if not dry_run:
                Store().save_program({
                    "id": program_id,
                    "handle": handle,
                    "name": name,
                    "url": url,
                    "state": state,
                    "submission_state": submission_state,
                    "last_fetch_at": last_fetch_at,
                    "scope_count": len(asset_ids),
                    "scope_hash": scope_hash,
                })

            inserted_programs += 1
            if inserted_programs % 100 == 0:
                logger.info("progress programs=%d", inserted_programs)
                print(f"[import] programmi inseriti: {inserted_programs}", flush=True)

    if not dry_run:
        store.conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_scopes_asset ON scopes(asset_identifier);
            CREATE INDEX IF NOT EXISTS idx_scopes_type ON scopes(normalized_type);
            CREATE INDEX IF NOT EXISTS idx_scopes_prog_type ON scopes(program_handle, normalized_type);
            """
        )
        store.conn.execute("ANALYZE;")
        store.conn.execute("PRAGMA optimize;")

    dur = time.time() - t0
    summary = (
        f"[Importer] programs={inserted_programs} scopes={inserted_scopes} "
        f"duration_sec={round(dur,3)} log={IMPORT_LOG_FILE.name}"
    )
    logger.info(summary)
    print(summary)
    print(f"✅ Import completato da {json_path}")
    notify_slack(summary)


# --- CLI ---

def main():
    ap = argparse.ArgumentParser(description="Importa H1-All-Scopes.json nel DB store.db")
    ap.add_argument("--input", "-i", type=Path, default=ROOT / "data" / "H1-All-Scopes.json",
                    help="Percorso al file JSON esportato dal Collector")
    ap.add_argument("--dry-run", action="store_true", help="Parse senza scrivere sul DB")
    ap.add_argument("--only-handles", type=str, default="", help="Lista di handle separati da virgola")
    ap.add_argument("--progress", type=int, default=1000, help="Frequenza log progresso (scopes)")
    ap.add_argument("--skip-ineligible", action="store_true",
                    help="Salta gli scope non eligibili per bounty")
    ap.add_argument("--min-updated-since", type=str, default="",
                    help="Importa solo scope con updated_at >= YYYY-MM-DD (o ISO completo)")
    args = ap.parse_args()

    init_db()
    import_scopes(
        args.input,
        dry_run=args.dry_run,
        only_handles=args.only_handles,
        progress=args.progress,
        skip_ineligible=args.skip_ineligible,
        min_updated_since=args.min_updated_since,
    )


if __name__ == "__main__":
    main()

