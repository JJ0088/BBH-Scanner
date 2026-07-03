"""CLI unificata: `bbh <comando>`.

Comandi: init | sync | recon | status | run | version
"""

from __future__ import annotations

import argparse
import json
import sys

from bbh_scanner import __version__
from bbh_scanner.config import Config
from bbh_scanner.db.store import Store
from bbh_scanner.logging_setup import setup_logging
from bbh_scanner.notify.telegram import build_notifier


def _store(config: Config) -> Store:
    config.ensure_dirs()
    return Store(config.db_path)


def cmd_init(config: Config, args) -> int:
    store = _store(config)
    stats = store.stats()
    print(f"✅ DB inizializzato in {config.db_path}")
    print(json.dumps(stats, indent=2))
    store.close()
    return 0


def cmd_sync(config: Config, args) -> int:
    from bbh_scanner.collectors import sync as sync_mod
    from bbh_scanner.collectors.hackerone import HackerOneClient, HackerOneCollector

    if not config.hackerone.configured:
        print("❌ HackerOne non configurato. Imposta HACKERONE_API_USERNAME e "
              "HACKERONE_API_TOKEN.", file=sys.stderr)
        return 2
    store = _store(config)
    collector = HackerOneCollector(HackerOneClient(config.hackerone))
    result = sync_mod.sync(collector, store, only_handle=args.only_handle)
    print(f"✅ Sync completata: {result}")
    store.close()
    return 0


def cmd_recon(config: Config, args) -> int:
    from bbh_scanner.scheduler.orchestrator import Orchestrator

    store = _store(config)
    notifier = build_notifier(config.telegram)
    orch = Orchestrator(config, store, notifier)
    processed = orch.do_recon(max_handles=args.limit)
    notified = orch.flush_notifications()
    print(f"✅ Recon: {processed} programmi, {notified} notifiche inviate")
    store.close()
    return 0


def cmd_sensors(config: Config, args) -> int:
    from bbh_scanner.resources.governor import decide
    from bbh_scanner.resources.sensors import sample_sensors
    from bbh_scanner.scheduler.orchestrator import MODE_OVERRIDE_KEY

    store = _store(config)
    override = store.get_state(MODE_OVERRIDE_KEY) or "auto"
    reading = sample_sensors(monitor_nvidia=config.governor.monitor_nvidia)
    plan = decide(reading, config.governor, override)

    def fmt(v, unit=""):
        return f"{v}{unit}" if v is not None else "n/d"

    print("== Sensori ==")
    print(f"  CPU temp : {fmt(reading.cpu_temp, '°C')}")
    print(f"  GPU temp : {fmt(reading.gpu_temp, '°C')}")
    print(f"  CPU load : {fmt(reading.cpu_load, '%')}")
    print(f"  batteria : {'sì' if reading.on_battery else ('no' if reading.on_battery is False else 'n/d')}"
          f" ({fmt(reading.battery_percent, '%')})")
    print("== Governor ==")
    print(f"  override richiesto : {override}")
    print(f"  regime deciso      : {plan.mode.value}  ({plan.reason})")
    print(f"  concorrenza / nice : {plan.max_concurrency} / {plan.nice}")
    store.close()
    return 0


def cmd_mode(config: Config, args) -> int:
    from bbh_scanner.scheduler.orchestrator import MODE_OVERRIDE_KEY

    valid = ("auto", "turbo", "powersave", "paused")
    store = _store(config)
    if args.value is None:
        print(store.get_state(MODE_OVERRIDE_KEY) or "auto")
        store.close()
        return 0
    if args.value not in valid:
        print(f"❌ modalità non valida. Usa una di: {', '.join(valid)}", file=sys.stderr)
        store.close()
        return 2
    store.set_state(MODE_OVERRIDE_KEY, args.value)
    print(f"✅ modalità impostata: {args.value} (il daemon la raccoglie al prossimo tick)")
    store.close()
    return 0


def cmd_scan(config: Config, args) -> int:
    from bbh_scanner.scheduler.orchestrator import Orchestrator

    if not config.active.enabled:
        print("⚠️  Scan attivo disabilitato. Abilitalo con BBH_ACTIVE_SCAN=1 "
              "(gira solo in regime NORMAL/TURBO).", file=sys.stderr)
        return 2
    store = _store(config)
    orch = Orchestrator(config, store, build_notifier(config.telegram))
    scanned = orch.do_active_scan(max_handles=args.limit)
    notified = orch.flush_notifications()
    print(f"✅ Scan attivo: {scanned} programmi, {notified} notifiche inviate")
    store.close()
    return 0


def cmd_findings(config: Config, args) -> int:
    store = _store(config)
    sev = [s.strip() for s in args.severity.split(",")] if args.severity else None
    rows = store.list_findings(kind=args.kind, severities=sev, limit=args.limit)
    print(f"== Findings ({len(rows)}) ==")
    for f in rows:
        print(f"  [{(f['severity'] or '?'):8s}] {f['kind']:14s} "
              f"{(f['program_handle'] or '-'):22s} {f['title']}")
    store.close()
    return 0


def cmd_status(config: Config, args) -> int:
    from bbh_scanner.scheduler.orchestrator import MODE_OVERRIDE_KEY

    store = _store(config)
    stats = store.stats()
    print("== BBH-Scanner status ==")
    print(json.dumps(stats, indent=2))
    print(f"\nmodalità: {store.get_state(MODE_OVERRIDE_KEY) or 'auto'}")
    jobs = store.job_counts()
    if jobs:
        print("coda job: " + "  ".join(f"{k}:{v}" for k, v in sorted(jobs.items())))
    print("\nProgrammi (primi 15):")
    for p in store.list_programs()[:15]:
        print(f"  {p['platform']:10s} {p['handle']:24s} "
              f"scopes={p['scope_count']} bounties={p['offers_bounties']}")
    print("\nEventi recenti:")
    for e in store.recent_events(10):
        print(f"  {e['ts']} {e['level']:5s} [{e['component']}] {e['message']}")
    store.close()
    return 0


def cmd_run(config: Config, args) -> int:  # pragma: no cover - loop
    from bbh_scanner.scheduler.orchestrator import Orchestrator

    setup_logging(config.logs_dir, config.log_level, config.log_json)
    store = _store(config)
    notifier = build_notifier(config.telegram)
    orch = Orchestrator(config, store, notifier)
    if args.once:
        result = orch.run_once()
        print(json.dumps(result, indent=2))
        store.close()
        return 0
    orch.run_forever(tick_sleep=args.tick)
    return 0


def cmd_doctor(config: Config, args) -> int:
    from bbh_scanner.health import has_blocking_failures, run_checks

    checks = run_checks(config, online=args.online)
    symbol = {"ok": "✅", "warn": "⚠️ ", "fail": "❌"}
    print("== bbh doctor ==")
    for c in checks:
        print(f"  {symbol.get(c.level, '•')} {c.name:20s} {c.detail}")
    if has_blocking_failures(checks):
        print("\n❌ Ci sono problemi bloccanti: risolvili prima di avviare il servizio.")
        return 1
    warns = sum(1 for c in checks if c.level == "warn")
    print(f"\n✅ Pronto per l'avvio." + (f" ({warns} avvisi non bloccanti)" if warns else ""))
    return 0


def cmd_jobs(config: Config, args) -> int:
    store = _store(config)
    counts = store.job_counts()
    print("== Coda job ==")
    print("  " + ("  ".join(f"{k}:{v}" for k, v in sorted(counts.items())) or "(vuota)"))
    states = [args.state] if args.state else None
    rows = store.list_jobs(states=states, limit=args.limit)
    if rows:
        print(f"\nUltimi {len(rows)} job:")
        for j in rows:
            print(f"  #{j['id']:<5} {j['state']:8s} {j['kind']:14s} "
                  f"{(j['program_handle'] or '-'):24s} attempts={j['attempts']}"
                  + (f"  err={j['error'][:40]}" if j['error'] else ""))
    store.close()
    return 0


def cmd_version(config: Config, args) -> int:
    print(f"bbh-scanner {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="bbh", description="BBH-Scanner (recon 24/7)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="Crea/migra il database")

    p_sync = sub.add_parser("sync", help="Sincronizza programmi/scope dal collector")
    p_sync.add_argument("--only-handle", default=None, help="Sincronizza un solo handle")

    p_recon = sub.add_parser("recon", help="Esegui recon passivo sui programmi dovuti")
    p_recon.add_argument("--limit", type=int, default=None, help="Max programmi per giro")

    sub.add_parser("status", help="Mostra stato e statistiche")

    p_doctor = sub.add_parser("doctor", help="Verifica pre-avvio (DB, credenziali, tool, sensori, Telegram)")
    p_doctor.add_argument("--online", action="store_true",
                          help="Testa anche la raggiungibilità di HackerOne e l'invio Telegram")

    p_jobs = sub.add_parser("jobs", help="Mostra la coda dei job")
    p_jobs.add_argument("--state", default=None,
                        help="Filtra per stato (queued|running|done|failed)")
    p_jobs.add_argument("--limit", type=int, default=20, help="Quanti job elencare")

    p_scan = sub.add_parser("scan", help="Scan attivo nuclei (opt-in, gated dal governor)")
    p_scan.add_argument("--limit", type=int, default=None, help="Max programmi per giro")

    p_find = sub.add_parser("findings", help="Elenca i findings")
    p_find.add_argument("--kind", default=None, help="Filtra per tipo (vuln|new_subdomain|...)")
    p_find.add_argument("--severity", default=None, help="CSV: es. medium,high,critical")
    p_find.add_argument("--limit", type=int, default=30)

    sub.add_parser("sensors", help="Mostra temperature CPU/GPU, carico e regime deciso")

    p_mode = sub.add_parser("mode", help="Imposta/mostra la modalità (auto|turbo|powersave|paused)")
    p_mode.add_argument("value", nargs="?", default=None,
                        help="auto | turbo | powersave | paused (vuoto = mostra corrente)")

    p_run = sub.add_parser("run", help="Loop residente 24/7 (o --once)")
    p_run.add_argument("--once", action="store_true", help="Un solo giro e poi esci")
    p_run.add_argument("--tick", type=int, default=60, help="Secondi tra i tick")

    sub.add_parser("version", help="Mostra la versione")
    return ap


_DISPATCH = {
    "init": cmd_init,
    "sync": cmd_sync,
    "recon": cmd_recon,
    "status": cmd_status,
    "doctor": cmd_doctor,
    "jobs": cmd_jobs,
    "scan": cmd_scan,
    "findings": cmd_findings,
    "sensors": cmd_sensors,
    "mode": cmd_mode,
    "run": cmd_run,
    "version": cmd_version,
}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    config = Config.load()
    try:
        return _DISPATCH[args.cmd](config, args)
    except BrokenPipeError:
        # output troncato da una pipe (es. `bbh status | head`): usciamo puliti.
        try:
            import os

            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
