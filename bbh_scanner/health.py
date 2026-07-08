"""Verifica pre-avvio (`bbh doctor`): controlla che tutto sia pronto per girare
sull'Acer prima di lanciare il servizio 24/7.

Ogni check è a tolleranza di guasto e ritorna un livello ok|warn|fail. Solo i `fail`
sono bloccanti (es. DB non scrivibile); le credenziali/tool mancanti sono `warn`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from bbh_scanner.config import Config
from bbh_scanner.db.store import Store
from bbh_scanner.recon.tools import check_tools
from bbh_scanner.resources.governor import decide
from bbh_scanner.resources.sensors import sample_sensors


@dataclass
class Check:
    name: str
    level: str   # ok | warn | fail
    detail: str


def run_checks(config: Config, online: bool = False,
               store: Optional[Store] = None) -> List[Check]:
    checks: List[Check] = []

    # --- Database ---
    own_store = False
    try:
        if store is None:
            config.ensure_dirs()
            store = Store(config.db_path)
            own_store = True
        store.stats()
        checks.append(Check("database", "ok", str(config.db_path)))
    except Exception as e:
        checks.append(Check("database", "fail", f"non accessibile: {e}"))

    # --- Credenziali HackerOne ---
    if config.hackerone.configured:
        checks.append(Check("hackerone", "ok", "credenziali presenti"))
        if online and store is not None:
            checks.append(_check_hackerone_online(config))
    else:
        checks.append(Check("hackerone", "warn",
                            "HACKERONE_API_USERNAME/TOKEN non impostate (niente sync)"))

    # --- Tool recon ---
    tools = check_tools()
    missing = [n for n, st in tools.items() if not st.available]
    if not missing:
        checks.append(Check("tool-recon", "ok", "subfinder/dnsx/httpx nel PATH"))
    else:
        checks.append(Check("tool-recon", "warn",
                            f"mancanti: {', '.join(missing)} (step relativi saltati)"))

    # --- Scan attivo (nuclei) ---
    if config.active.enabled:
        nuclei = check_tools(("nuclei",))["nuclei"]
        if nuclei.available:
            checks.append(Check("scan-attivo", "ok",
                                f"abilitato — nuclei presente (rate={config.active.rate_limit}/s)"))
        else:
            checks.append(Check("scan-attivo", "warn",
                                "abilitato ma 'nuclei' non è nel PATH"))
    else:
        checks.append(Check("scan-attivo", "ok",
                            "disabilitato (BBH_ACTIVE_SCAN=1 per attivarlo)"))

    # --- Sensori + governor ---
    reading = sample_sensors(monitor_nvidia=config.governor.monitor_nvidia)
    plan = decide(reading, config.governor, "auto")
    temp_bits = []
    temp_bits.append(f"CPU={reading.cpu_temp}°C" if reading.cpu_temp is not None else "CPU=n/d")
    temp_bits.append(f"GPU={reading.gpu_temp}°C" if reading.gpu_temp is not None else "GPU=n/d")
    if reading.cpu_temp is None and reading.gpu_temp is None:
        checks.append(Check("sensori", "warn",
                            "nessuna temperatura leggibile (k10temp/nvidia-smi assenti?) "
                            f"→ regime deciso: {plan.mode.value}"))
    else:
        checks.append(Check("sensori", "ok",
                            f"{' '.join(temp_bits)} → regime: {plan.mode.value}"))

    # --- Telegram ---
    if config.telegram.configured:
        if online:
            from bbh_scanner.notify.telegram import build_notifier

            ok = build_notifier(config.telegram).send("🩺 bbh doctor — test notifica")
            checks.append(Check("telegram", "ok" if ok else "warn",
                                "test inviato" if ok else "invio fallito (rete/allowlist?)"))
        else:
            checks.append(Check("telegram", "ok", "configurato (usa --online per testare)"))
    else:
        checks.append(Check("telegram", "warn", "TELEGRAM_BOT_TOKEN/CHAT_ID non impostati"))

    if own_store and store is not None:
        store.close()
    return checks


def _check_hackerone_online(config: Config) -> Check:
    try:
        from bbh_scanner.collectors.hackerone import HackerOneClient

        client = HackerOneClient(config.hackerone)
        body = client.get("programs", params={"page[number]": 1})
        n = len(body.get("data", []))
        return Check("hackerone-online", "ok", f"API raggiungibile ({n} programmi in pagina 1)")
    except Exception as e:
        return Check("hackerone-online", "warn", f"API non raggiungibile: {e}")


def has_blocking_failures(checks: List[Check]) -> bool:
    return any(c.level == "fail" for c in checks)
