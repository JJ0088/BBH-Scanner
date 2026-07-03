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


def cmd_status(config: Config, args) -> int:
    store = _store(config)
    stats = store.stats()
    print("== BBH-Scanner status ==")
    print(json.dumps(stats, indent=2))
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
    "run": cmd_run,
    "version": cmd_version,
}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    config = Config.load()
    return _DISPATCH[args.cmd](config, args)


if __name__ == "__main__":
    sys.exit(main())
