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
from bbh_scanner.config import MODE_OVERRIDE_KEY, Config
from bbh_scanner.db.store import Store
from bbh_scanner.normalize import sha256_hex
from bbh_scanner.notify.base import Notifier, NullNotifier
from bbh_scanner.active.nuclei import build_targets, run_nuclei
from bbh_scanner.recon.passive import ReconResult, run_passive
from bbh_scanner.recon.tools import check_tools
from bbh_scanner.resources.governor import Governor, Mode, ResourcePlan
from bbh_scanner.scheduler.queue import select_due

# Emoji per severità (findings vulnerabilità nuclei).
_SEV_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
# Notifichiamo sempre gli asset-delta; per i vuln solo da medium in su.
_NOTIFY_ALWAYS_KINDS = {"new_subdomain", "new_host", "host_down"}
_NOTIFY_SEVERITIES = {"medium", "high", "critical"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except ValueError:
        return None


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
            claimed = self.store.claim_jobs(limit, kinds=["recon_passive"])
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
        # baseline = prima mappatura in assoluto di questo programma
        is_baseline = self.store.get_state(f"{platform}:{handle}:last_recon_at") is None
        new_findings = self._persist_recon(platform, handle, result, is_baseline=is_baseline)
        if is_baseline:
            self.store.log_event(
                "INFO", "recon",
                f"baseline {handle}: {len(result.subdomains)} sottodomini / "
                f"{len(result.alive)} host mappati (nessun finding: è il punto di partenza)",
                program_handle=handle,
            )
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

    def _persist_recon(self, platform: str, handle: str, result,
                       is_baseline: bool = False) -> int:
        """Salva gli asset scoperti (inventario in `assets`) e genera **solo i delta**
        come findings: sottodomini/host *nuovi rispetto a ciò che era già noto* e host
        caduti. Sul **baseline** non genera alcun finding di asset (sarebbe l'intera
        superficie): l'inventario vive nella tabella `assets`."""
        new_count = 0
        now = _now_iso()

        # cosa era già noto PRIMA di questo giro (per isolare i veri nuovi)
        existing_subs = self.store.asset_values(platform, handle, "subdomain")
        existing_hosts = self.store.asset_values(platform, handle, "host")

        rows = [("subdomain", s, "subfinder") for s in result.subdomains]
        rows += [("host", h, "httpx") for h in result.alive]

        # host_down: solo se httpx ha davvero girato
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

        # findings SOLO sui delta (mai sul baseline: gli asset stanno in `assets`)
        if not is_baseline:
            for value in (s for s in result.subdomains if s not in existing_subs):
                fp = sha256_hex([f"{platform}:{handle}:new_subdomain:{value}"])
                if self.store.record_finding({
                    "platform": platform, "program_handle": handle, "kind": "new_subdomain",
                    "fingerprint": fp, "severity": "info",
                    "title": f"new_subdomain: {value}", "data": {"value": value},
                }):
                    new_count += 1
            for value in (h for h in result.alive if h not in existing_hosts):
                fp = sha256_hex([f"{platform}:{handle}:new_host:{value}"])
                if self.store.record_finding({
                    "platform": platform, "program_handle": handle, "kind": "new_host",
                    "fingerprint": fp, "severity": "info",
                    "title": f"new_host: {value}", "data": {"value": value},
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

    # --- scan attivo (nuclei) ---------------------------------------------- #

    def _active_targets(self, platform: str, handle: str) -> List[str]:
        scopes = self.store.list_scopes(platform, handle, types=("url", "api"))
        alive = self.store.alive_hosts(platform, handle)
        return build_targets(scopes, alive)

    def _enqueue_active_due(self) -> int:
        """Accoda un job nuclei_scan per i programmi con bersagli e scaduti di intervallo."""
        now = _now()
        interval = self.config.active.scan_interval_sec
        n = 0
        for p in self.store.list_programs(enabled_only=True):
            platform, handle = p["platform"], p["handle"]
            if not self._active_targets(platform, handle):
                continue
            last = self.store.get_state(f"{platform}:{handle}:last_active_at")
            if last:
                last_dt = _parse_iso(last)
                if last_dt and (now - last_dt).total_seconds() < interval:
                    continue
            if self.store.enqueue_job("nuclei_scan", platform=platform,
                                      program_handle=handle) is not None:
                n += 1
        return n

    def do_active_scan(self, max_handles: Optional[int] = None) -> int:
        """Scan attivo con nuclei — OPT-IN e gated dal governor.

        Non fa nulla se `BBH_ACTIVE_SCAN` è off o se `nuclei` non è installato. Gira solo
        quando il regime è NORMAL o TURBO (mai powersave/pausa): lo scan attivo è pesante
        e aggressivo per la rete, quindi cede il passo appena usi il PC.
        """
        if not self.config.active.enabled:
            return 0
        tools = check_tools(("nuclei",))
        if not tools["nuclei"].available:
            self.store.log_event(
                "WARN", "nuclei", "scan attivo abilitato ma 'nuclei' non è nel PATH"
            )
            return 0

        self._enqueue_active_due()
        override = self.current_override()
        timeout = self.config.active.timeout_sec
        processed = 0
        while max_handles is None or processed < max_handles:
            plan = self.governor.plan(override=override)
            if plan.mode not in (Mode.NORMAL, Mode.TURBO):
                self.store.log_event(
                    "INFO", "nuclei",
                    f"scan attivo sospeso (regime {plan.mode.value})",
                )
                break
            claimed = self.store.claim_jobs(1, kinds=["nuclei_scan"])
            if not claimed:
                break
            job = claimed[0]
            platform, handle = job["platform"], job["program_handle"]
            targets = self._active_targets(platform, handle)
            workdir = self.config.data_dir / "active" / platform / handle
            try:
                result = run_nuclei(
                    handle, targets, workdir, self.config.active,
                    nice=plan.nice, timeout=timeout, tools=tools,
                )
            except Exception as e:
                self.store.fail_job(job["id"], str(e),
                                    retry_after_sec=self.config.governor.cooldown_sec)
                self.store.log_event("ERROR", "nuclei",
                                     f"scan {handle} fallito: {e}", program_handle=handle)
                processed += 1
                continue
            new_vulns = self._persist_nuclei(platform, handle, result)
            self.store.set_state(f"{platform}:{handle}:last_active_at", _now_iso())
            self.store.complete_job(job["id"])
            self.store.log_event(
                "INFO", "nuclei",
                f"scan {handle}: bersagli={len(targets)} findings={len(result.findings)} "
                f"nuovi={new_vulns}" + (" (nuclei assente/saltato)" if result.skipped else ""),
                program_handle=handle,
            )
            processed += 1
        return processed

    def _persist_nuclei(self, platform: str, handle: str, result) -> int:
        new_count = 0
        for f in result.findings:
            fp = sha256_hex([f"{platform}:{handle}:vuln:{f.template_id}:{f.matched_at}"])
            if self.store.record_finding({
                "platform": platform, "program_handle": handle, "kind": "vuln",
                "fingerprint": fp, "severity": f.severity,
                "title": f"{f.name} @ {f.matched_at}",
                "data": {"template_id": f.template_id, "matched_at": f.matched_at,
                         "host": f.host, "severity": f.severity},
            }):
                new_count += 1
        return new_count

    # --- notify pending ---------------------------------------------------- #

    def flush_notifications(self) -> int:
        """Invia le notifiche pendenti, senza spam:

        - **asset-delta** (nuovi sottodomini/host, host caduti): **un riepilogo per
          programma** (es. "🌐 [acme] +3 sottodomini, +1 host") invece di un messaggio
          per asset;
        - **vuln**: un messaggio per finding, ma **solo da medium in su** (info/low
          vengono soppressi e si consultano con `bbh findings`).

        Tutte le finding processate vengono marcate come viste (anche quelle soppresse),
        così la coda non si accumula.
        """
        pending = self.store.unnotified_findings(limit=2000)
        if not pending:
            return 0

        deltas: Dict[str, Dict[str, int]] = {}   # handle -> {kind: count}
        vulns: List[Dict] = []
        to_mark: List[int] = []
        sent = 0

        for f in pending:
            to_mark.append(f["id"])
            kind = f["kind"]
            if kind in _NOTIFY_ALWAYS_KINDS:
                deltas.setdefault(f["program_handle"], {}).setdefault(kind, 0)
                deltas[f["program_handle"]][kind] += 1
            elif (f.get("severity") or "").lower() in _NOTIFY_SEVERITIES:
                vulns.append(f)
            # else: vuln sotto soglia → soppresso (solo marcato)

        # un riepilogo per programma per gli asset-delta
        for handle, kinds in deltas.items():
            bits = []
            if kinds.get("new_subdomain"):
                bits.append(f"+{kinds['new_subdomain']} sottodomini")
            if kinds.get("new_host"):
                bits.append(f"+{kinds['new_host']} host vivi")
            if kinds.get("host_down"):
                bits.append(f"−{kinds['host_down']} host caduti")
            if self.notifier.send(f"🌐 [{handle}] {', '.join(bits)}"):
                sent += 1

        # un messaggio per ogni vuln medium+
        for f in vulns:
            emoji = _SEV_EMOJI.get((f.get("severity") or "").lower(), "•")
            if self.notifier.send(f"{emoji} [{f['program_handle']}] {f['title']}"):
                sent += 1

        self.store.mark_notified(to_mark)
        return sent

    # --- loop -------------------------------------------------------------- #

    def run_once(self) -> Dict[str, int]:
        now = time.monotonic()
        did_sync = False
        if now - self._last_sync >= self.config.sync_interval_sec or self._last_sync == 0:
            self.do_sync()
            self._last_sync = now
            did_sync = True
        processed = self.do_recon()
        scanned = self.do_active_scan()
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

        return {"synced": int(did_sync), "recon": processed,
                "scanned": scanned, "notified": notified}

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

        # bot Telegram a comandi (thread con connessione DB propria)
        if self.config.telegram.configured:
            from bbh_scanner.telegram_bot import TelegramPoller

            TelegramPoller(self.config, self.store.db_path, stop_event=self._stop).start_thread()
            self.store.log_event(
                "INFO", "telegram", "avvio bot comandi (/status /logs /findings /mode …)"
            )
        else:
            self.store.log_event(
                "WARN", "telegram",
                "bot NON avviato: TELEGRAM_BOT_TOKEN/CHAT_ID mancanti (usa .env o export)"
            )

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
