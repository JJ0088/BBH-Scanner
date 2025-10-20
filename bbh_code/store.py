#!/usr/bin/env python3
# `bbh_code/store.py` (commentato, completo)
"""
store.py — cuore dati del BBH-Scanner.

Responsabilità:
- Creare e aprire il DB SQLite in modo sicuro (auto-crea la cartella dati).
- Definire lo schema (tabelle 'programs' e 'scopes' + indice base).
- Fornire API semplici: save_program, save_scope, list_programs, list_scopes, stats.
- Esporre una piccola CLI per operazioni veloci (init/info/list-*).

Scelte:
- Path dinamici via env (BBH_ROOT, BBH_DATA_DIR, BBH_DB_PATH) per portabilità.
- row_factory=sqlite3.Row per ottenere dict(row) comodamente.
- Upsert con ON CONFLICT per idempotenza (nessun duplicato).
"""

from __future__ import annotations
import os
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional
import json

# === PATH DINAMICI ===
# Deduciamo la root del progetto da questo file, ma permettiamo override da env.
_DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("BBH_ROOT", str(_DEFAULT_ROOT)))
DATA_DIR = Path(os.environ.get("BBH_DATA_DIR", str(ROOT / "data")))
DB_PATH = Path(os.environ.get("BBH_DB_PATH", str(DATA_DIR / "store.db")))

# === SCHEMA DATABASE ===
# Due tabelle principali:
# - programs: un record per programma HackerOne
# - scopes: asset per programma, con normalizzazione tipo/valore
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS programs (
    id TEXT PRIMARY KEY,            -- id H1 o handle come fallback
    handle TEXT UNIQUE NOT NULL,    -- identificatore unico del programma
    name TEXT,                      -- nome umano del programma
    url TEXT,                       -- pagina profilo/URL H1
    state TEXT,                     -- stato programma (se disponibile)
    submission_state TEXT,          -- stato submission (se disponibile)
    last_fetch_at TEXT,             -- ISO datetime dell'ultima import
    scope_count INTEGER DEFAULT 0,  -- numero di scope collegati
    scope_hash TEXT                 -- hash degli asset_identifier per confronti veloci
);

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,               -- id scope H1 o "<handle>:<asset_identifier>"
    program_handle TEXT NOT NULL,      -- FK logica verso programs.handle
    asset_identifier TEXT NOT NULL,    -- valore originale (raw)
    asset_type TEXT,                   -- tipo H1 originale (se presente)
    eligible_for_bounty INTEGER,       -- 0/1 (se presente nel dump)
    instruction TEXT,                  -- note/istruzioni H1 (se presenti)
    max_severity TEXT,                 -- severità massima (se presente)
    created_at TEXT,                   -- timestamp creato (se presente)
    updated_at TEXT,                   -- timestamp aggiornato (se presente)
    normalized_type TEXT,              -- url | api | domain | wildcard
    normalized_value TEXT,             -- valore normalizzato coerente col tipo
    UNIQUE(program_handle, asset_identifier)
);

-- indice base per query comuni per programma
CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_handle);
"""

# === FUNZIONI BASE ===

def get_conn() -> sqlite3.Connection:
    """
    Apre la connessione, creando la cartella dati se manca.
    Abilita foreign_keys e imposta row_factory per accesso tipo dict.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)      # sqlite non crea le cartelle da solo
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")        # regola di integrità (non usiamo FK reali qui, ma buona pratica)
    conn.row_factory = sqlite3.Row                   # consente dict(row)
    return conn


def init_db() -> None:
    """
    Applica lo schema al DB (create if not exists).
    Idempotente: rilanciarla non rompe nulla.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA_SQL)
    print(f"✅ Database inizializzato in {DB_PATH}")


class Store:
    """
    Wrapper semplice attorno alla connessione SQLite.

    Pattern: manteniamo self.conn aperta finché l'istanza vive.
    Nel nostro caso (processo singolo) è semplice e funzionale.
    """

    def __init__(self, db_path: Path | None = None):
        self.db_path = Path(db_path) if db_path else DB_PATH
        # Lazy-init: se il DB non esiste, crea subito lo schema.
        if not self.db_path.exists():
            init_db()
        self.conn = get_conn()

    # --- Programmi ---

    def save_program(self, program: Dict):
        """
        Upsert di un programma (idempotente).
        Chiave di conflitto: handle (univoco).
        Aggiorna nome, url, state, submission_state, last_fetch_at, scope_count, scope_hash.
        """
        sql = """
        INSERT INTO programs (id, handle, name, url, state, submission_state,
                              last_fetch_at, scope_count, scope_hash)
        VALUES (:id, :handle, :name, :url, :state, :submission_state,
                :last_fetch_at, :scope_count, :scope_hash)
        ON CONFLICT(handle) DO UPDATE SET
            name=excluded.name,
            url=excluded.url,
            state=excluded.state,
            submission_state=excluded.submission_state,
            last_fetch_at=excluded.last_fetch_at,
            scope_count=excluded.scope_count,
            scope_hash=excluded.scope_hash;
        """
        self.conn.execute(sql, program)
        self.conn.commit()

    def list_programs(self) -> List[Dict]:
        """Elenca tutti i programmi ordinati per handle."""
        cur = self.conn.execute("SELECT * FROM programs ORDER BY handle;")
        return [dict(row) for row in cur.fetchall()]

    # --- Scopes ---

    def save_scope(self, scope: Dict):
        """
        Upsert di uno scope (idempotente) basato su (program_handle, asset_identifier).
        Aggiorna i campi descrittivi e la normalizzazione (tipo/valore).
        """
        sql = """
        INSERT INTO scopes (
            id, program_handle, asset_identifier, asset_type,
            eligible_for_bounty, instruction, max_severity,
            created_at, updated_at, normalized_type, normalized_value
        )
        VALUES (
            :id, :program_handle, :asset_identifier, :asset_type,
            :eligible_for_bounty, :instruction, :max_severity,
            :created_at, :updated_at, :normalized_type, :normalized_value
        )
        ON CONFLICT(program_handle, asset_identifier) DO UPDATE SET
            asset_type=excluded.asset_type,
            eligible_for_bounty=excluded.eligible_for_bounty,
            instruction=excluded.instruction,
            max_severity=excluded.max_severity,
            updated_at=excluded.updated_at,
            normalized_type=excluded.normalized_type,
            normalized_value=excluded.normalized_value;
        """
        self.conn.execute(sql, scope)
        self.conn.commit()

    def list_scopes(self, handle: Optional[str] = None) -> List[Dict]:
        """Elenca gli scope; se `handle` è passato, filtra per programma."""
        if handle:
            cur = self.conn.execute(
                "SELECT * FROM scopes WHERE program_handle=? ORDER BY updated_at DESC;",
                (handle,),
            )
        else:
            cur = self.conn.execute("SELECT * FROM scopes;")
        return [dict(row) for row in cur.fetchall()]

    def stats(self) -> Dict[str, int]:
        """Ritorna conteggi rapidi (programs, scopes)."""
        cur = self.conn.execute("SELECT COUNT(*) AS n FROM programs;")
        programs = cur.fetchone()["n"]
        cur = self.conn.execute("SELECT COUNT(*) AS n FROM scopes;")
        scopes = cur.fetchone()["n"]
        return {"programs": programs, "scopes": scopes}


# === CLI ===
# Piccola interfaccia a riga di comando per azioni veloci durante lo sviluppo.

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Gestione DB BBH-Scanner")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init", help="Crea il database e lo schema")
    sub.add_parser("info", help="Mostra statistiche di base")
    sub.add_parser("list-programs", help="Elenca tutti i programmi")
    sub.add_parser("list-scopes", help="Elenca tutti gli scope")

    args = parser.parse_args()
    store = Store()

    if args.cmd == "init":
        init_db()
    elif args.cmd == "info":
        print(json.dumps(store.stats(), indent=2))
    elif args.cmd == "list-programs":
        for p in store.list_programs():
            handle = p.get("handle") or "<no-handle>"
            scount = p.get("scope_count") or 0
            state = p.get("state") or "?"
            print(f"{handle:30s} {scount} scopes  ({state})")
    elif args.cmd == "list-scopes":
        scopes = store.list_scopes()
        print(f"{len(scopes)} scopes totali")
        for s in scopes[:10]:
            ph = s.get("program_handle") or "?"
            ai = s.get("asset_identifier") or "?"
            print(f"- {ph:20s} {ai}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

