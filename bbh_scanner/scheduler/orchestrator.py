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

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional

from bbh_scanner import systemd

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
        self._stop = threading.Event()

    def request_stop(self) -> None:
        self._stop.set()

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

    def _enqueue_due(self) -> int:
        """Accoda un job recon_passive per ogni programma dovuto (dedup nello Store)."""
        n = 0
        for cand in self._due_programs():
            jid = self.store.enqueue_job(
                "recon_passive", platform=cand.platform,
                program_handle=cand.handle, priority=cand.priority,
            )
            if jid is not None:
                n += 1
        return n

    def do_recon(self, max_handles: Optional[int] = None) -> int:
        """Recon guidato dalla coda `jobs`: enqueue dei dovuti → claim → esegui → chiusura.

        **Ripartibile**: i job rimasti 'running' per un crash tornano 'queued'. Concorrenza
        e `nice` li decide il governor a ogni giro; se la temperatura è critica (PAUSED) il
        recon si ferma e riprende al prossimo tick. I tool (I/O) girano in parallelo, le
        scritture SQLite nel thread principale (connessione unica).
        """
        tools = check_tools()
        self.store.requeue_stale_running()
        self._enqueue_due()

        override = self.current_override()
        timeout = self.config.budget.tool_timeout_sec
        processed = 0
        while max_handles is None or processed < max_handles:
            plan = self.governor.plan(override=override)
            self._note_mode(plan)
            if not plan.can_work:
                self.store.log_event(
                    "INFO", "governor", f"recon in pausa: {plan.reason}",
                    data={"mode": plan.mode.value},
                )
                break

            limit = max(1, plan.max_concurrency)
            if max_handles is not None:
                limit = min(limit, max_handles - processed)
            claimed = self.store.claim_jobs(limit)
            if not claimed:
                break

            # 1) preparazione (DB, main thread)
            prepared = [
                (job, *self._prepare_recon(job["platform"], job["program_handle"]))
                for job in claimed
            ]
            # 2) esecuzione tool (parallela, nessun accesso DB)
            results: Dict[int, object] = {}
            if plan.max_concurrency <= 1:
                for job, workdir, scopes in prepared:
                    results[job["id"]] = self._run_passive_safe(
                        job["program_handle"], scopes, workdir, timeout, plan.nice, tools
                    )
            else:
                with ThreadPoolExecutor(max_workers=plan.max_concurrency) as ex:
                    fut = {
                        ex.submit(self._run_passive_safe, job["program_handle"], scopes,
                                  workdir, timeout, plan.nice, tools): job
                        for job, workdir, scopes in prepared
                    }
                    for f in as_completed(fut):
                        results[fut[f]["id"]] = f.result()
            # 3) persistenza + chiusura job (DB, main thread)
            for job, _workdir, _scopes in prepared:
                res = results.get(job["id"])
                if isinstance(res, ReconResult):
                    self._persist_and_mark(job["platform"], job["program_handle"], res)
                    self.store.complete_job(job["id"])
                else:
                    state = self.store.fail_job(
                        job["id"], str(res),
                        retry_after_sec=self.config.governor.cooldown_sec,
                    )
                    self.store.log_event(
                        "ERROR", "recon",
                        f"job {job['program_handle']} fallito ({state}): {res}",
                        program_handle=job["program_handle"],
                    )
                processed += 1
        return processed

    def _run_passive_safe(self, handle, scopes, workdir, timeout, nice, tools):
        """Esegue il recon senza sollevare: ritorna ReconResult o l'eccezione catturata."""
        try:
            return run_passive(handle, scopes, workdir, timeout=timeout, nice=nice, tools=tools)
        except Exception as e:  # pragma: no cover - difensivo
            return e

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
        """Salva asset scoperti e genera i delta (findings): nuovi sottodomini, nuovi
        host vivi e host caduti."""
        new_count = 0
        now = _now_iso()
        rows = []
        for sub in result.subdomains:
            rows.append(("subdomain", sub, "subfinder"))
        for host in result.alive:
            rows.append(("host", host, "httpx"))

        # host_down: solo se httpx ha davvero girato (altrimenti `alive` è vuoto per
        # assenza del tool, non perché gli host sono caduti).
        gone_hosts: List[str] = []
        if "httpx" not in result.skipped_steps:
            prev_alive = set(self.store.alive_hosts(platform, handle))
            gone_hosts = sorted(prev_alive - set(result.alive))

        with self.store.transaction() as c:
            for kind, value, source in rows:
                asset_id = f"{platform}:{handle}:{kind}:{value}"
                c.execute(
                    "INSERT INTO assets(id, platform, program_handle, kind, value, "
                    "source, alive, first_seen_at, last_seen_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET last_seen_at=excluded.last_seen_at, "
                    "alive=excluded.alive, source=excluded.source;",
                    (asset_id, platform, handle, kind, value, source,
                     1 if kind == "host" else None, now, now),
                )
        for host in gone_hosts:
            self.store.mark_host_down(platform, handle, host)

        # findings: nuovi asset
        for kind, value, _ in rows:
            fkind = "new_subdomain" if kind == "subdomain" else "new_host"
            fp = sha256_hex([f"{platform}:{handle}:{fkind}:{value}"])
            if self.store.record_finding({
                "platform": platform, "program_handle": handle, "kind": fkind,
                "fingerprint": fp, "severity": "info",
                "title": f"{fkind}: {value}", "data": {"value": value},
            }):
                new_count += 1

        # findings: host caduti (fingerprint stabile → una notifica per host)
        for host in gone_hosts:
            fp = sha256_hex([f"{platform}:{handle}:host_down:{host}"])
            if self.store.record_finding({
                "platform": platform, "program_handle": handle, "kind": "host_down",
                "fingerprint": fp, "severity": "info",
                "title": f"host_down: {host}", "data": {"value": host},
            }):
                new_count += 1
        return new_count

    # --- notify pending ---------------------------------------------------- #

    def flush_notifications(self) -> int:
        pending = self.store.unnotified_findings()
        sent_ids = []
        for f in pending:
            emoji = {"new_subdomain": "🌐", "new_host": "🟢", "host_down": "🔴"}.get(
                f["kind"], "•"
            )
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
            jobs = self.store.job_counts()
            self.notifier.send(
                f"💓 heartbeat — programmi:{stats['programs']} scope:{stats['scopes']} "
                f"asset:{stats['assets']} findings:{stats['findings']} "
                f"job(queued:{jobs.get('queued', 0)} failed:{jobs.get('failed', 0)})"
            )
            # retention: pota gli eventi vecchi per non far crescere il DB all'infinito
            pruned = self.store.prune_events(self.config.budget.retention_days)
            if pruned:
                self.store.log_event(
                    "INFO", "retention", f"eventi potati: {pruned}"
                )
            self._last_heartbeat = now

        return {"synced": int(did_sync), "recon": processed, "notified": notified}

    def _install_signal_handlers(self) -> None:  # pragma: no cover
        import signal

        def _handler(*_):
            self.request_stop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                pass  # non nel main thread: lo scheduler gira comunque

    def run_forever(self, tick_sleep: int = 60) -> None:  # pragma: no cover
        """Loop residente 24/7. Arresto pulito su SIGTERM/SIGINT (systemd stop/reboot):
        finisce il tick corrente ed esce. Integra il watchdog systemd se disponibile."""
        self._install_signal_handlers()
        self.store.log_event("INFO", "orchestrator", "avvio loop 24/7")
        self.notifier.send(f"▶️ BBH-Scanner avviato — {_now_iso()}")
        systemd.notify_ready()

        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as e:
                self.store.log_event("ERROR", "orchestrator", f"tick fallito: {e}")
            systemd.notify_watchdog()
            # sleep interrompibile: uno stop sveglia subito il loop
            self._stop.wait(timeout=tick_sleep)

        systemd.notify_stopping()
        self.store.log_event("INFO", "orchestrator", "arresto pulito")
        self.notifier.send(f"⏹️ BBH-Scanner arrestato — {_now_iso()}")
