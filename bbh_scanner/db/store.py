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
from datetime import datetime, timezone
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
