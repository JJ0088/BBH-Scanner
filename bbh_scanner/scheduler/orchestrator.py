"""Orchestratore residente: il "tick" del 24/7 (recon-only in questa fase).

Un giro (`run_once`):
  1. sync del collector se dovuto;
  2. selezione dei programmi con recon dovuto (prioritizzati);
  3. recon passivo per ciascuno, entro il budget, con persistenza di asset e delta;
  4. notifica dei nuovi findings + heartbeat.

`run_forever` ripete `run_once` a intervalli; è pensato per girare sotto systemd.
Lo stato vive nel DB, quindi il processo è ripartibile dopo un crash/reboot.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional

from bbh_scanner.collectors import sync as sync_mod
from bbh_scanner.collectors.hackerone import (
    HackerOneClient,
    HackerOneCollector,
)
from bbh_scanner.config import Config
from bbh_scanner.db.store import Store
from bbh_scanner.normalize import sha256_hex
from bbh_scanner.notify.base import Notifier, NullNotifier
from bbh_scanner.recon.passive import ReconResult, run_passive
from bbh_scanner.recon.tools import check_tools
from bbh_scanner.resources.governor import Governor, ResourcePlan
from bbh_scanner.scheduler.queue import select_due

MODE_OVERRIDE_KEY = "governor:mode_override"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


class Orchestrator:
    def __init__(self, config: Config, store: Store,
                 notifier: Optional[Notifier] = None,
                 governor: Optional[Governor] = None):
        self.config = config
        self.store = store
        self.notifier = notifier or NullNotifier()
        self.governor = governor or Governor(config.governor)
        self._last_sync = 0.0
        self._last_heartbeat = 0.0
        self._last_mode: Optional[str] = None

    def current_override(self) -> str:
        return self.store.get_state(MODE_OVERRIDE_KEY) or "auto"

    def set_mode(self, mode: str) -> None:
        self.store.set_state(MODE_OVERRIDE_KEY, mode)

    # --- collector --------------------------------------------------------- #

    def _build_collector(self) -> Optional[HackerOneCollector]:
        h1 = self.config.hackerone
        if not h1.configured:
            return None
        return HackerOneCollector(HackerOneClient(h1))

    def do_sync(self) -> None:
        collector = self._build_collector()
        if collector is None:
            self.store.log_event("WARN", "sync", "HackerOne non configurato: sync saltata")
            return
        result = sync_mod.sync(collector, self.store)
        self.notifier.send(f"🔄 Sync HackerOne — {result}")

    # --- recon ------------------------------------------------------------- #

    def _recon_markers(self, platform: str, handle: str) -> Dict[str, Optional[str]]:
        return {
            "last_recon_at": self.store.get_state(f"{platform}:{handle}:last_recon_at"),
            "last_recon_hash": self.store.get_state(f"{platform}:{handle}:last_recon_hash"),
        }

    def _due_programs(self) -> List:
        programs = self.store.list_programs(enabled_only=True)
        enriched = []
        for p in programs:
            markers = self._recon_markers(p["platform"], p["handle"])
            enriched.append({**p, **markers})
        return select_due(enriched, _now(), self.config.recon_interval_sec)

    def do_recon(self, max_handles: Optional[int] = None) -> int:
        """Esegue il recon sui programmi dovuti, rispettando il governor.

        La concorrenza e il `nice` sono decisi dal governor a ogni "chunk"; se la
        temperatura è critica (PAUSED) il recon si ferma e riprenderà al prossimo tick.
        Le chiamate ai tool (I/O) girano in parallelo; le letture/scritture SQLite
        restano nel thread principale (connessione unica).
        """
        tools = check_tools()
        due = self._due_programs()
        if max_handles is not None:
            due = due[:max_handles]
        if not due:
            return 0

        override = self.current_override()
        timeout = self.config.budget.tool_timeout_sec
        processed = 0
        i = 0
        while i < len(due):
            plan = self.governor.plan(override=override)
            self._note_mode(plan)
            if not plan.can_work:
                self.store.log_event(
                    "INFO", "governor", f"recon in pausa: {plan.reason}",
                    data={"mode": plan.mode.value},
                )
                break

            chunk = due[i:i + max(1, plan.max_concurrency)]
            # 1) preparazione (DB, main thread)
            prepared = [
                (c, *self._prepare_recon(c.platform, c.handle)) for c in chunk
            ]
            # 2) esecuzione tool (parallela, nessun accesso DB)
            results: Dict[str, ReconResult] = {}
            if plan.max_concurrency <= 1:
                for cand, workdir, scopes in prepared:
                    results[cand.handle] = run_passive(
                        cand.handle, scopes, workdir, timeout=timeout,
                        nice=plan.nice, tools=tools,
                    )
            else:
                with ThreadPoolExecutor(max_workers=plan.max_concurrency) as ex:
                    fut = {
                        ex.submit(run_passive, cand.handle, scopes, workdir,
                                  timeout, plan.nice, tools): cand
                        for cand, workdir, scopes in prepared
                    }
                    for f in as_completed(fut):
                        cand = fut[f]
                        try:
                            results[cand.handle] = f.result()
                        except Exception as e:
                            self.store.log_event(
                                "ERROR", "recon", f"job {cand.handle} fallito: {e}",
                                program_handle=cand.handle,
                            )
            # 3) persistenza (DB, main thread)
            for cand, _workdir, _scopes in prepared:
                res = results.get(cand.handle)
                if res is not None:
                    self._persist_and_mark(cand.platform, cand.handle, res)
            processed += len(chunk)
            i += len(chunk)
        return processed

    def _prepare_recon(self, platform: str, handle: str):
        scopes = self.store.list_scopes(platform, handle, types=("wildcard", "domain"))
        workdir = self.config.data_dir / "recon" / platform / handle
        return workdir, scopes

    def _persist_and_mark(self, platform: str, handle: str, result: ReconResult) -> None:
        new_findings = self._persist_recon(platform, handle, result)
        self.store.set_state(f"{platform}:{handle}:last_recon_at", _now_iso())
        prog = next(
            (p for p in self.store.list_programs(platform) if p["handle"] == handle), None
        )
        if prog and prog.get("scope_hash"):
            self.store.set_state(f"{platform}:{handle}:last_recon_hash", prog["scope_hash"])
        self.store.log_event(
            "INFO", "recon",
            f"recon {handle}: subs={len(result.subdomains)} alive={len(result.alive)} "
            f"new_findings={new_findings} skipped={result.skipped_steps}",
            program_handle=handle,
        )

    def _note_mode(self, plan: ResourcePlan) -> None:
        """Notifica su Telegram solo quando il regime cambia (niente spam)."""
        if plan.mode.value == self._last_mode:
            return
        self._last_mode = plan.mode.value
        emoji = {"turbo": "🚀", "normal": "▶️", "powersave": "🐢", "paused": "⏸️"}.get(
            plan.mode.value, "•"
        )
        self.store.log_event(
            "INFO", "governor", f"regime → {plan.mode.value} ({plan.reason})",
            data={"mode": plan.mode.value, "nice": plan.nice,
                  "concurrency": plan.max_concurrency},
        )
        self.notifier.send(f"{emoji} regime: {plan.mode.value} — {plan.reason}")

    def _persist_recon(self, platform: str, handle: str, result) -> int:
        """Salva asset scoperti e genera findings per i nuovi sottodomini/host vivi."""
        new_count = 0
        now = _now_iso()
        rows = []
        for sub in result.subdomains:
            rows.append(("subdomain", sub, "subfinder"))
        for host in result.alive:
            rows.append(("host", host, "httpx"))
        with self.store.transaction() as c:
            for kind, value, source in rows:
                asset_id = f"{platform}:{handle}:{kind}:{value}"
                c.execute(
                    "INSERT INTO assets(id, platform, program_handle, kind, value, "
                    "source, alive, first_seen_at, last_seen_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET last_seen_at=excluded.last_seen_at;",
                    (asset_id, platform, handle, kind, value, source,
                     1 if kind == "host" else None, now, now),
                )
        for kind, value, _ in rows:
            fkind = "new_subdomain" if kind == "subdomain" else "new_host"
            fp = sha256_hex([f"{platform}:{handle}:{fkind}:{value}"])
            is_new = self.store.record_finding({
                "platform": platform, "program_handle": handle, "kind": fkind,
                "fingerprint": fp, "severity": "info",
                "title": f"{fkind}: {value}", "data": {"value": value},
            })
            if is_new:
                new_count += 1
        return new_count

    # --- notify pending ---------------------------------------------------- #

    def flush_notifications(self) -> int:
        pending = self.store.unnotified_findings()
        sent_ids = []
        for f in pending:
            emoji = {"new_subdomain": "🌐", "new_host": "🟢"}.get(f["kind"], "•")
            ok = self.notifier.send(
                f"{emoji} [{f['program_handle']}] {f['title']}"
            )
            if ok:
                sent_ids.append(f["id"])
        self.store.mark_notified(sent_ids)
        return len(sent_ids)

    # --- loop -------------------------------------------------------------- #

    def run_once(self) -> Dict[str, int]:
        now = time.monotonic()
        did_sync = False
        if now - self._last_sync >= self.config.sync_interval_sec or self._last_sync == 0:
            self.do_sync()
            self._last_sync = now
            did_sync = True
        processed = self.do_recon()
        notified = self.flush_notifications()

        if now - self._last_heartbeat >= self.config.heartbeat_interval_sec:
            stats = self.store.stats()
            self.notifier.send(
                f"💓 heartbeat — programmi:{stats['programs']} scope:{stats['scopes']} "
                f"asset:{stats['assets']} findings:{stats['findings']}"
            )
            self._last_heartbeat = now

        return {"synced": int(did_sync), "recon": processed, "notified": notified}

    def run_forever(self, tick_sleep: int = 60) -> None:  # pragma: no cover
        self.store.log_event("INFO", "orchestrator", "avvio loop 24/7")
        self.notifier.send(f"▶️ BBH-Scanner avviato — {_now_iso()}")
        while True:
            try:
                self.run_once()
            except Exception as e:
                self.store.log_event("ERROR", "orchestrator", f"tick fallito: {e}")
            time.sleep(tick_sleep)
