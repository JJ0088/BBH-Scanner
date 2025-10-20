#!/usr/bin/env python3
"""
filterer.py — Fase 2 del BBH-Scanner (PATCH)

Questa patch cambia la directory di output dei workflow:
- PRIMA: results/filtered/<handle>/...
- ORA:   filtered_output/workflows/<handle>/...

Resta invariata la logica di hashing, manifest per handle (.meta/manifest.json),
CLI e formati dei file seed.
"""

from __future__ import annotations
import os
import sys
import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Iterable, Tuple, Set, Optional
from urllib.parse import urlparse
import argparse
from datetime import datetime

# --- Versione del Filterer (compare nel manifest e nei log) ---
FILTERER_VERSION = "0.2.1"

# --- Path dinamici coerenti con gli altri moduli ---
_DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("BBH_ROOT", str(_DEFAULT_ROOT)))
DATA_DIR = Path(os.environ.get("BBH_DATA_DIR", str(ROOT / "data")))
# PATCH: i workflow devono stare in filtered_output/workflows
WORKFLOWS_DIR = ROOT / "filtered_output" / "workflows"
LOGS_DIR = ROOT / "logs"

# Import layer DB (+ DB_PATH per scriverlo nel manifest)
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))
try:
    from bbh_code.store import Store, DB_PATH as STORE_DB_PATH  # type: ignore
except ModuleNotFoundError as e:
    raise SystemExit(
        "Impossibile importare bbh_code.store: lancia da root progetto e verifica __init__.py"
    ) from e

# --- Logging con filename timestampato ---
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_ts = datetime.now().strftime("%Y.%m.%d-%H.%M.%S")
LOG_FILE = LOGS_DIR / f"bbh_filterer{_ts}.log"
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [filterer] %(message)s",
)
logger = logging.getLogger("filterer")


# --- Slack notify (opt-in) ---
def notify_slack(text: str) -> None:
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return
    try:
        import urllib.request as _ur

        data = json.dumps({"text": text}).encode("utf-8")
        req = _ur.Request(url, data=data, headers={"Content-Type": "application/json"})
        _ur.urlopen(req, timeout=5).read()
    except Exception:
        logger.warning("Slack notify fallita", exc_info=False)


# --- Helpers hashing/I-O ---
def sha256_text(s: str) -> str:
    h = hashlib.sha256()
    h.update(s.encode("utf-8"))
    return h.hexdigest()


def write_if_changed(
    path: Path, content: str, overwrite: bool = False
) -> Tuple[bool, str]:
    """Scrive `content` su `path` solo se contenuto cambiato (o overwrite=True).
    Ritorna (written, hexhash). Registra/legge l'hash da .hash/<nome>.sha256
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    hash_dir = path.parent / ".hash"
    hash_dir.mkdir(parents=True, exist_ok=True)
    h = sha256_text(content)
    hash_file = hash_dir / f"{path.name}.sha256"

    prev = None
    if hash_file.exists() and not overwrite:
        try:
            prev = hash_file.read_text(encoding="utf-8").strip()
        except Exception:
            prev = None
    if prev and prev == h and not overwrite:
        return (False, h)  # invariato

    path.write_text(content, encoding="utf-8")
    hash_file.write_text(h, encoding="utf-8")
    return (True, h)


# --- Normalizzazione minima ---
def strip_wildcard_to_domain(value: str) -> str:
    v = value.strip()
    if v.startswith("*."):
        return v[2:]
    return v


def host_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def ensure_https_root(host_or_url: str) -> str:
    h = host_or_url.strip()
    if h.startswith("http://") or h.startswith("https://"):
        return h
    return f"https://{h}/"


# --- DB utilities per manifest/skip-unchanged ---
def get_program_info(handle: str) -> Optional[Dict[str, object]]:
    st = Store()
    cur = st.conn.execute(
        "SELECT scope_count, scope_hash FROM programs WHERE handle=?;",
        (handle,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def read_manifest(handle: str) -> Optional[Dict[str, object]]:
    mf = WORKFLOWS_DIR / handle / ".meta" / "manifest.json"
    if not mf.exists():
        return None
    try:
        return json.loads(mf.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_manifest(handle: str, payload: Dict[str, object]) -> None:
    meta_dir = WORKFLOWS_DIR / handle / ".meta"
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "manifest.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# --- Costruzione set per ciascun file ---
def collect_sets_for_handle(scopes: List[Dict]) -> Dict[str, Set[str]]:
    subfinder_seeds: Set[str] = set()
    httpx_seeds: Set[str] = set()
    katana_seeds: Set[str] = set()
    nuclei_urls: Set[str] = set()

    for s in scopes:
        ntype = (s.get("normalized_type") or "").strip().lower()
        nval = (s.get("normalized_value") or "").strip()
        if not ntype or not nval:
            continue

        if ntype == "wildcard":
            dom = strip_wildcard_to_domain(nval)
            subfinder_seeds.add(dom)
            katana_seeds.add(ensure_https_root(dom))

        elif ntype == "domain":
            subfinder_seeds.add(nval)
            host = host_from_url(nval) or nval
            httpx_seeds.add(ensure_https_root(host))
            katana_seeds.add(ensure_https_root(host))

        elif ntype == "url":
            httpx_seeds.add(nval)
            nuclei_urls.add(nval)

        elif ntype == "api":
            httpx_seeds.add(nval)
            nuclei_urls.add(nval)
            if "*" in nval:
                host = host_from_url(nval)
                if host:
                    katana_seeds.add(ensure_https_root(host))

    return {
        "subfinder_seeds": subfinder_seeds,
        "httpx_seeds": httpx_seeds,
        "katana_seeds": katana_seeds,
        "nuclei_urls": nuclei_urls,
    }


# --- Serializzazioni deterministiche ---
def serialize_lines(items: Iterable[str]) -> str:
    norm: Set[str] = set()
    for it in items:
        t = (it or "").strip()
        if t:
            norm.add(t)
    lines = sorted(norm, key=lambda x: x.casefold())
    return "\n".join(lines) + ("\n" if lines else "")


def serialize_jsonl_urls(items: Iterable[str]) -> str:
    out: List[str] = []
    seen: Set[str] = set()
    for it in items:
        t = (it or "").strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(json.dumps({"url": t}, ensure_ascii=False))
    return "\n".join(out) + ("\n" if out else "")


# --- Core per singolo handle ---
def generate_for_handle(
    handle: str, overwrite: bool = False, skip_empty: bool = False
) -> Dict[str, Dict[str, object]]:
    store = Store()
    scopes = store.list_scopes(handle)
    sets = collect_sets_for_handle(scopes)

    out_dir = WORKFLOWS_DIR / handle  # PATCH: workflows output
    out_dir.mkdir(parents=True, exist_ok=True)

    plan_txt = [
        ("subfinder_seeds.txt", sets["subfinder_seeds"]),
        ("httpx_seeds.txt", sets["httpx_seeds"]),
        ("katana_seeds.txt", sets["katana_seeds"]),
        ("nuclei_urls.txt", sets["nuclei_urls"]),
    ]

    report: Dict[str, Dict[str, object]] = {}

    # TXT
    for fname, s in plan_txt:
        content = serialize_lines(s)
        if skip_empty and not content:
            report[fname] = {"written": False, "count": 0, "hash": ""}
            continue
        written, h = write_if_changed(out_dir / fname, content, overwrite=overwrite)
        report[fname] = {"written": written, "count": len(s), "hash": h}

    # JSONL (input preferito di nuclei)
    jsonl_content = serialize_jsonl_urls(sets["nuclei_urls"])
    if not (skip_empty and not jsonl_content):
        written, h = write_if_changed(
            out_dir / "nuclei_urls.jsonl", jsonl_content, overwrite=overwrite
        )
        report["nuclei_urls.jsonl"] = {
            "written": written,
            "count": len(sets["nuclei_urls"]),
            "hash": h,
        }
    else:
        report["nuclei_urls.jsonl"] = {"written": False, "count": 0, "hash": ""}

    return report


# --- Utility ---
def list_all_handles() -> List[str]:
    st = Store()
    rows = st.list_programs()
    return [r.get("handle") for r in rows if r.get("handle")]


# --- CLI ---
def main():
    ap = argparse.ArgumentParser(
        description="Filterer — genera file per subfinder/httpx/katana/nuclei"
    )
    ap.add_argument(
        "--only-handles",
        type=str,
        default="",
        help="Lista di handle separati da virgola",
    )
    ap.add_argument(
        "--overwrite",
        action="store_true",
        help="Riscrive i file anche se hash invariato",
    )
    ap.add_argument("--skip-empty", action="store_true", help="Non creare file vuoti")
    ap.add_argument(
        "--skip-unchanged",
        action="store_true",
        help="Salta l'handle se l'hash degli scope non è cambiato rispetto al manifest precedente",
    )
    ap.add_argument(
        "--progress", type=int, default=0, help="Logga ogni N handle processati (0=off)"
    )
    args = ap.parse_args()

    t0 = time.time()

    handles = (
        [h.strip() for h in args.only_handles.split(",") if h.strip()]
        if args.only_handles
        else list_all_handles()
    )
    if not handles:
        print("[filterer] Nessun handle da processare.")
        return

    total = {"written": 0, "skipped": 0, "handles_skipped_unchanged": 0}
    per_handle_stats = {}

    for i, handle in enumerate(handles, 1):
        # --- Short-circuit: skip-unchanged basato su scope_hash in DB + manifest precedente ---
        prog = get_program_info(handle)
        prev_manifest = read_manifest(handle)
        if args.skip_unchanged and prog and prev_manifest:
            if (
                prog.get("scope_hash")
                and prev_manifest.get("last_scope_hash")
                and prog["scope_hash"] == prev_manifest["last_scope_hash"]
            ):
                total["handles_skipped_unchanged"] += 1
                logger.info(f"[skip-unchanged] {handle} (scope_hash invariato)")
                if args.progress and i % args.progress == 0:
                    print(
                        f"[filterer] Processati {i}/{len(handles)} handle… (skip-unchanged attivo)",
                        flush=True,
                    )
                continue

        # --- Generazione ---
        hstart = time.time()
        rep = generate_for_handle(
            handle, overwrite=args.overwrite, skip_empty=args.skip_empty
        )
        hdur = time.time() - hstart
        per_handle_stats[handle] = rep

        # Conteggi file scritti / saltati
        w = sum(1 for v in rep.values() if v["written"])
        s = sum(1 for v in rep.values() if not v["written"])
        total["written"] += w
        total["skipped"] += s

        # Scrivi/aggiorna manifest con meta-info e contatori (NEL WORKFLOW DIR)
        manifest_payload = {
            "handle": handle,
            "filterer_version": FILTERER_VERSION,
            "db_path": str(STORE_DB_PATH),
            "log_file": str(LOG_FILE.name),
            "started_at": datetime.fromtimestamp(hstart).isoformat(),
            "finished_at": datetime.fromtimestamp(hstart + hdur).isoformat(),
            "duration_sec": round(hdur, 3),
            "files": {
                k: {"count": v["count"], "written": v["written"], "hash": v["hash"]}
                for k, v in rep.items()
            },
            "scope_count": (
                int(prog["scope_count"])
                if prog and prog.get("scope_count") is not None
                else None
            ),
            "last_scope_hash": prog["scope_hash"] if prog else None,
        }
        write_manifest(handle, manifest_payload)

        if args.progress and i % args.progress == 0:
            print(f"[filterer] Processati {i}/{len(handles)} handle…", flush=True)

    # Log & Slack: riepilogo globale + timing totale
    total_dur = time.time() - t0
    msg = (
        f"[Filterer] v{FILTERER_VERSION} Handles={len(handles)} "
        f"files_written={total['written']} files_skipped={total['skipped']} "
        f"skip_unchanged={total['handles_skipped_unchanged']} "
        f"duration_sec={round(total_dur, 3)} log={LOG_FILE.name}"
    )
    logger.info(msg)
    print(msg)
    # prima:
    notify_slack(msg)

    # dopo: solo se esplicitamente abilitato
    if os.getenv("BBH_FILTERER_SLACK", "0") == "1":
        notify_slack(msg)

    # Mini sommario per i primi 3 handle processati (non saltati)
    shown = 0
    for h, rep in per_handle_stats.items():
        print(f"- {h}")
        for fname, meta in rep.items():
            print(f"    {fname:18s} written={meta['written']} count={meta['count']}")
        shown += 1
        if shown >= 3:
            break


if __name__ == "__main__":
    main()
