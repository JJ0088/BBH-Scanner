"""Store SQLite ridisegnato.

Differenze chiave rispetto al vecchio MVP:
- **una sola connessione** per processo (niente `Store()` sparsi);
- **WAL** + pragmas di performance impostati una volta;
- upsert **batch** via `executemany` (niente commit-per-riga);
- transazioni esplicite via context manager;
- migrazioni tramite `PRAGMA user_version`.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn


class Store:
    """Facciata tipizzata sul DB. Possiede la connessione per tutta la sua vita."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.conn = connect(self.db_path)
        self._migrate()

    # --- Lifecycle --------------------------------------------------------- #

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version;").fetchone()[0]
        if version < 1:
            self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION};")
            self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.execute("PRAGMA optimize;")
        except Exception:
            pass
        self.conn.close()

    @contextmanager
    def transaction(self):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # --- sync_state (cursori) --------------------------------------------- #

    def get_state(self, key: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT value FROM sync_state WHERE key=?;", (key,)
        ).fetchone()
        return row["value"] if row else None

    def set_state(self, key: str, value: str) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO sync_state(key, value, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at;",
                (key, value, _now_iso()),
            )

    # --- programs ---------------------------------------------------------- #

    def upsert_programs(self, programs: Iterable[Dict[str, Any]]) -> int:
        rows = list(programs)
        if not rows:
            return 0
        now = _now_iso()
        payload = [
            (
                p["platform"], p["handle"], p.get("name"), p.get("url"),
                _as_int(p.get("offers_bounties")), p.get("submission_state"),
                p.get("state"), _as_int(p.get("open_scope")), now,
                int(p.get("scope_count") or 0), p.get("scope_hash"),
                _as_int(p.get("enabled"), default=1),
            )
            for p in rows
        ]
        with self.transaction() as c:
            c.executemany(
                "INSERT INTO programs(platform, handle, name, url, offers_bounties, "
                "submission_state, state, open_scope, last_fetch_at, scope_count, "
                "scope_hash, enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(platform, handle) DO UPDATE SET "
                "name=excluded.name, url=excluded.url, "
                "offers_bounties=excluded.offers_bounties, "
                "submission_state=excluded.submission_state, state=excluded.state, "
                "open_scope=excluded.open_scope, last_fetch_at=excluded.last_fetch_at, "
                "scope_count=excluded.scope_count, scope_hash=excluded.scope_hash;",
                payload,
            )
        return len(payload)

    def list_programs(self, platform: Optional[str] = None,
                      enabled_only: bool = False) -> List[Dict]:
        sql = "SELECT * FROM programs"
        clauses, params = [], []
        if platform:
            clauses.append("platform=?")
            params.append(platform)
        if enabled_only:
            clauses.append("enabled=1")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY platform, handle;"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def set_program_scope_summary(self, platform: str, handle: str,
                                  scope_count: int, scope_hash: Optional[str]) -> None:
        with self.transaction() as c:
            c.execute(
                "UPDATE programs SET scope_count=?, scope_hash=?, last_fetch_at=? "
                "WHERE platform=? AND handle=?;",
                (scope_count, scope_hash, _now_iso(), platform, handle),
            )

    # --- scopes ------------------------------------------------------------ #

    def upsert_scopes(self, scopes: Iterable[Dict[str, Any]]) -> int:
        rows = list(scopes)
        if not rows:
            return 0
        now = _now_iso()
        payload = [
            (
                s["id"], s["platform"], s["program_handle"], s["asset_identifier"],
                s.get("asset_type"), _as_int(s.get("eligible_for_bounty")),
                _as_int(s.get("eligible_for_submission")), s.get("max_severity"),
                s.get("instruction"), s.get("created_at"), s.get("updated_at"),
                s.get("normalized_type"), s.get("normalized_value"), now, now,
            )
            for s in rows
        ]
        with self.transaction() as c:
            c.executemany(
                "INSERT INTO scopes(id, platform, program_handle, asset_identifier, "
                "asset_type, eligible_for_bounty, eligible_for_submission, max_severity, "
                "instruction, created_at, updated_at, normalized_type, normalized_value, "
                "first_seen_at, last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "asset_type=excluded.asset_type, "
                "eligible_for_bounty=excluded.eligible_for_bounty, "
                "eligible_for_submission=excluded.eligible_for_submission, "
                "max_severity=excluded.max_severity, instruction=excluded.instruction, "
                "created_at=excluded.created_at, updated_at=excluded.updated_at, "
                "normalized_type=excluded.normalized_type, "
                "normalized_value=excluded.normalized_value, "
                "last_seen_at=excluded.last_seen_at;",
                payload,
            )
        return len(payload)

    def list_scopes(self, platform: str, handle: str,
                   types: Optional[Iterable[str]] = None) -> List[Dict]:
        sql = "SELECT * FROM scopes WHERE platform=? AND program_handle=?"
        params: List[Any] = [platform, handle]
        if types:
            tlist = list(types)
            sql += f" AND normalized_type IN ({','.join('?' * len(tlist))})"
            params.extend(tlist)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    # --- findings ---------------------------------------------------------- #

    def record_finding(self, finding: Dict[str, Any]) -> bool:
        """Inserisce un finding se il fingerprint è nuovo. Ritorna True se nuovo.

        Se già presente, aggiorna solo `last_seen_at` e ritorna False (così il
        chiamante notifica una volta sola).
        """
        now = _now_iso()
        fingerprint = finding["fingerprint"]
        with self.transaction() as c:
            existing = c.execute(
                "SELECT 1 FROM findings WHERE fingerprint=?;", (fingerprint,)
            ).fetchone()
            if existing:
                c.execute(
                    "UPDATE findings SET last_seen_at=? WHERE fingerprint=?;",
                    (now, fingerprint),
                )
                return False
            c.execute(
                "INSERT INTO findings(platform, program_handle, kind, fingerprint, "
                "severity, title, data, status, first_seen_at, last_seen_at) "
                "VALUES(?,?,?,?,?,?,?, 'new', ?, ?);",
                (
                    finding.get("platform"), finding.get("program_handle"),
                    finding["kind"], fingerprint,
                    finding.get("severity", "info"), finding.get("title"),
                    json.dumps(finding.get("data", {}), ensure_ascii=False), now, now,
                ),
            )
            return True

    def list_findings(self, kind: Optional[str] = None,
                      severities: Optional[Iterable[str]] = None,
                      limit: int = 50) -> List[Dict]:
        sql = "SELECT * FROM findings"
        clauses, params = [], []
        if kind:
            clauses.append("kind=?")
            params.append(kind)
        if severities:
            slist = list(severities)
            clauses.append(f"severity IN ({','.join('?' * len(slist))})")
            params.extend(slist)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?;"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def unnotified_findings(self, limit: int = 50) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE notified_at IS NULL "
            "ORDER BY first_seen_at LIMIT ?;",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_notified(self, finding_ids: Iterable[int]) -> None:
        ids = list(finding_ids)
        if not ids:
            return
        with self.transaction() as c:
            c.executemany(
                "UPDATE findings SET notified_at=? WHERE id=?;",
                [(_now_iso(), i) for i in ids],
            )

    def suppress_unnotified(self, platform: str, handle: str,
                            kinds: Optional[Iterable[str]] = None) -> int:
        """Segna come 'viste' (senza notificare) le finding pendenti di un programma.

        Usato per il **baseline**: alla prima mappatura di un programma registriamo la
        superficie ma non sommergiamo di notifiche; da lì in poi si notificano solo i delta.
        """
        sql = ("UPDATE findings SET notified_at=? WHERE platform=? AND program_handle=? "
               "AND notified_at IS NULL")
        params: List[Any] = [_now_iso(), platform, handle]
        if kinds:
            klist = list(kinds)
            sql += f" AND kind IN ({','.join('?' * len(klist))})"
            params.extend(klist)
        with self.transaction() as c:
            return c.execute(sql, params).rowcount

    # --- events ------------------------------------------------------------ #

    def log_event(self, level: str, component: str, message: str,
                  program_handle: Optional[str] = None,
                  job_id: Optional[int] = None,
                  data: Optional[Dict] = None) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO events(ts, level, component, job_id, program_handle, "
                "message, data) VALUES(?,?,?,?,?,?,?);",
                (
                    _now_iso(), level, component, job_id, program_handle, message,
                    json.dumps(data, ensure_ascii=False) if data else None,
                ),
            )

    def recent_events(self, limit: int = 20) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?;", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def prune_events(self, days: int) -> int:
        """Cancella gli eventi più vecchi di `days` giorni (retention osservabilità)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.transaction() as c:
            cur = c.execute("DELETE FROM events WHERE ts < ?;", (cutoff,))
            return cur.rowcount

    # --- jobs (coda di lavoro con macchina a stati) ------------------------ #

    def enqueue_job(self, kind: str, platform: Optional[str] = None,
                    program_handle: Optional[str] = None, target: Optional[str] = None,
                    priority: int = 0, sig: Optional[str] = None,
                    next_due_at: Optional[str] = None) -> Optional[int]:
        """Accoda un job se non ne esiste già uno identico queued/running.

        Ritorna l'id del nuovo job, o None se già presente (dedup). Nota: usiamo un
        controllo esplicito con `IS` (null-safe) perché nell'indice UNIQUE i target
        NULL sarebbero considerati distinti.
        """
        now = _now_iso()
        with self.transaction() as c:
            existing = c.execute(
                "SELECT id FROM jobs WHERE kind=? AND platform IS ? AND program_handle IS ? "
                "AND target IS ? AND state IN ('queued','running');",
                (kind, platform, program_handle, target),
            ).fetchone()
            if existing:
                return None
            cur = c.execute(
                "INSERT INTO jobs(kind, platform, program_handle, target, state, priority, "
                "attempts, next_due_at, sig, created_at) "
                "VALUES(?,?,?,?, 'queued', ?, 0, ?, ?, ?);",
                (kind, platform, program_handle, target, priority, next_due_at or now, sig, now),
            )
            return cur.lastrowid

    def claim_jobs(self, limit: int, kinds: Optional[Iterable[str]] = None) -> List[Dict]:
        """Prende fino a `limit` job dovuti (queued, next_due_at<=now) e li marca running.

        `kinds` filtra per tipo (es. solo 'recon_passive' o solo 'nuclei_scan'), così
        pipeline diverse non si rubano i job a vicenda.
        """
        now = _now_iso()
        sql = ("SELECT * FROM jobs WHERE state='queued' "
               "AND (next_due_at IS NULL OR next_due_at<=?)")
        params: List[Any] = [now]
        if kinds:
            klist = list(kinds)
            sql += f" AND kind IN ({','.join('?' * len(klist))})"
            params.extend(klist)
        sql += " ORDER BY priority DESC, next_due_at ASC, id ASC LIMIT ?;"
        params.append(limit)
        with self.transaction() as c:
            rows = c.execute(sql, params).fetchall()
            claimed = [dict(r) for r in rows]
            for r in claimed:
                c.execute(
                    "UPDATE jobs SET state='running', started_at=?, attempts=attempts+1 WHERE id=?;",
                    (now, r["id"]),
                )
                # rifletti nel dict restituito lo stato aggiornato
                r["state"] = "running"
                r["started_at"] = now
                r["attempts"] = (r["attempts"] or 0) + 1
        return claimed

    def complete_job(self, job_id: int) -> None:
        with self.transaction() as c:
            c.execute(
                "UPDATE jobs SET state='done', finished_at=?, error=NULL WHERE id=?;",
                (_now_iso(), job_id),
            )

    def fail_job(self, job_id: int, error: str, retry_after_sec: Optional[int] = None,
                 max_attempts: int = 3) -> str:
        """Fallisce un job. Se sotto `max_attempts` e con `retry_after_sec`, lo ri-accoda
        con backoff; altrimenti lo marca 'failed'. Ritorna lo stato finale."""
        now = _now_iso()
        with self.transaction() as c:
            row = c.execute("SELECT attempts FROM jobs WHERE id=?;", (job_id,)).fetchone()
            attempts = row["attempts"] if row else max_attempts
            if retry_after_sec is not None and attempts < max_attempts:
                next_due = (
                    datetime.now(timezone.utc) + timedelta(seconds=retry_after_sec)
                ).isoformat()
                c.execute(
                    "UPDATE jobs SET state='queued', next_due_at=?, error=?, finished_at=? WHERE id=?;",
                    (next_due, error, now, job_id),
                )
                return "queued"
            c.execute(
                "UPDATE jobs SET state='failed', error=?, finished_at=? WHERE id=?;",
                (error, now, job_id),
            )
            return "failed"

    def requeue_stale_running(self) -> int:
        """Alla ripartenza: i job rimasti 'running' (per un crash) tornano 'queued'."""
        with self.transaction() as c:
            cur = c.execute(
                "UPDATE jobs SET state='queued', started_at=NULL WHERE state='running';"
            )
            return cur.rowcount

    def list_jobs(self, states: Optional[Iterable[str]] = None, limit: int = 50) -> List[Dict]:
        sql = "SELECT * FROM jobs"
        params: List[Any] = []
        if states:
            slist = list(states)
            sql += f" WHERE state IN ({','.join('?' * len(slist))})"
            params.extend(slist)
        sql += " ORDER BY id DESC LIMIT ?;"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def job_counts(self) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT state, COUNT(*) AS n FROM jobs GROUP BY state;"
        ).fetchall()
        return {r["state"]: r["n"] for r in rows}

    # --- assets (per detection host_down) ---------------------------------- #

    def alive_hosts(self, platform: str, handle: str) -> List[str]:
        rows = self.conn.execute(
            "SELECT value FROM assets WHERE platform=? AND program_handle=? "
            "AND kind='host' AND alive=1;",
            (platform, handle),
        ).fetchall()
        return [r["value"] for r in rows]

    def mark_host_down(self, platform: str, handle: str, value: str) -> None:
        with self.transaction() as c:
            c.execute(
                "UPDATE assets SET alive=0, last_seen_at=? "
                "WHERE platform=? AND program_handle=? AND kind='host' AND value=?;",
                (_now_iso(), platform, handle, value),
            )

    # --- stats ------------------------------------------------------------- #

    def stats(self) -> Dict[str, int]:
        def count(table: str) -> int:
            return self.conn.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]

        return {
            "programs": count("programs"),
            "scopes": count("scopes"),
            "assets": count("assets"),
            "findings": count("findings"),
            "jobs": count("jobs"),
        }

    def _group_counts(self, sql: str, params: Iterable[Any] = ()) -> Dict[str, int]:
        return {row[0]: row[1] for row in self.conn.execute(sql, tuple(params)).fetchall()}

    def summary(self) -> Dict[str, Any]:
        """Riepilogo ricco per la dashboard `bbh status` (una sola raccolta di query)."""
        enabled = self.conn.execute(
            "SELECT COUNT(*) FROM programs WHERE enabled=1;"
        ).fetchone()[0]
        last_sync = self.conn.execute(
            "SELECT MAX(last_fetch_at) FROM programs;"
        ).fetchone()[0]
        return {
            "stats": self.stats(),
            "programs_enabled": enabled,
            "last_sync_at": last_sync,
            "scope_types": self._group_counts(
                "SELECT normalized_type, COUNT(*) FROM scopes GROUP BY 1 ORDER BY 2 DESC;"
            ),
            "asset_kinds": self._group_counts(
                "SELECT kind, COUNT(*) FROM assets GROUP BY 1 ORDER BY 2 DESC;"
            ),
            "alive_hosts": self.conn.execute(
                "SELECT COUNT(*) FROM assets WHERE kind='host' AND alive=1;"
            ).fetchone()[0],
            "finding_kinds": self._group_counts(
                "SELECT kind, COUNT(*) FROM findings GROUP BY 1 ORDER BY 2 DESC;"
            ),
            "vuln_severities": self._group_counts(
                "SELECT severity, COUNT(*) FROM findings WHERE kind='vuln' GROUP BY 1;"
            ),
            "jobs": self.job_counts(),
        }


def _as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip().lower()
    if s in ("true", "1", "yes"):
        return 1
    if s in ("false", "0", "no"):
        return 0
    try:
        return int(s)
    except ValueError:
        return default
