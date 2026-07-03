# BBH-Scanner

Scanner **recon 24/7** per asset di programmi bug bounty, pensato per girare su una
singola macchina modesta (Acer Aspire 7, NixOS). Multi-piattaforma in prospettiva
(**HackerOne** ora; Bugcrowd/YesWeHack/Intigriti in seguito).

> **Rewrite v2 in corso.** Il nuovo codice vive in `bbh_scanner/`. Il vecchio MVP in
> `bbh_code/` è **congelato come riferimento** e verrà rimosso quando il nuovo path lo
> sostituisce. Progetto e razionale completo: [`Documentazione/architettura-v2.md`](Documentazione/architettura-v2.md).

**Fase attuale: recon-only** — nessuno scan attivo (nuclei) finché l'infrastruttura non è
solida e testata. Vedi le milestone in fondo al documento d'architettura.

---

## Cosa fa (v2)

1. **Collector** — sincronizza programmi e scope da HackerOne (Hacker API v1), in modo
   **incrementale** (filtro `updated_at` sugli structured scopes).
2. **Store** — SQLite ridisegnato (connessione unica, WAL, upsert batch) con tabelle
   `programs`, `scopes`, `assets`, `jobs`, `findings`, `events`, `sync_state`.
3. **Recon passivo** — `subfinder → dnsx → httpx` sui seed derivati dagli scope; produce
   asset scoperti e **delta** (nuovo sottodominio / nuovo host vivo) come findings.
4. **Scheduler** — orchestratore residente con **coda `jobs`** (enqueue→claim→esegui→
   complete/fail, dedup, backoff): sincronizza, prioritizza (asset nuovi/cambiati prima) ed
   esegue il recon entro il budget del governor. **Ripartibile dopo un crash**: i job rimasti
   a metà tornano in coda al riavvio.
5. **Scan attivo (nuclei)** — opt-in, gated dal governor e rate-limitato: cerca
   vulnerabilità sui bersagli in-scope e produce findings `vuln`.
6. **Notifiche Telegram** — findings, heartbeat, errori.

---

## Requisiti

- Python 3.11+
- Tool ProjectDiscovery per il recon: `subfinder`, `dnsx`, `httpx`
- Su NixOS: tutto gestito dal **flake** (dev shell + servizio systemd)

## Setup con Nix (consigliato su NixOS)

```bash
nix develop            # shell con python + subfinder/dnsx/httpx + pytest
bbh init               # crea/migra il DB
```

## Setup senza Nix

```bash
pip install -e .
# installare a parte subfinder/dnsx/httpx (ProjectDiscovery)
bbh init
```

## Configurazione (variabili d'ambiente)

| Variabile | Descrizione |
|-----------|-------------|
| `HACKERONE_API_USERNAME` | API token identifier (Hacker API v1) |
| `HACKERONE_API_TOKEN` | valore del token |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | notifiche (opzionali) |
| `BBH_ROOT`, `BBH_DATA_DIR`, `BBH_DB_PATH`, `BBH_LOGS_DIR` | path (default dedotti) |
| `BBH_MAX_CONCURRENCY`, `BBH_NICE`, `BBH_TOOL_TIMEOUT`, `BBH_RETENTION_DAYS` | budget risorse |
| `BBH_SYNC_INTERVAL`, `BBH_RECON_INTERVAL`, `BBH_HEARTBEAT_INTERVAL` | intervalli (secondi) |

Le credenziali della Hacker API si generano dalle impostazioni di un account HackerOne
(la **Community edition** è gratuita e sufficiente).

## Comandi

```bash
bbh init                       # crea/migra il database
bbh doctor                     # verifica pre-avvio (DB, credenziali, tool, sensori, Telegram)
bbh doctor --online            # + test raggiungibilità HackerOne e invio Telegram
bbh sync                       # sincronizza programmi/scope da HackerOne
bbh sync --only-handle acme    # solo un programma
bbh recon --limit 5            # recon passivo sui programmi dovuti (max 5)
bbh scan --limit 3             # scan attivo nuclei (opt-in, vedi sotto)
bbh findings --severity high,critical   # elenca i findings
bbh status                     # stato, statistiche, eventi recenti, modalità, coda
bbh jobs                       # coda dei job (queued/running/done/failed)
bbh jobs --state failed        # solo i job falliti
bbh sensors                    # temperature CPU/GPU, carico, regime deciso
bbh mode turbo                 # usa tutto il PC (es. quando esci di casa)
bbh mode powersave             # footprint minimo (stai usando il PC)
bbh mode auto                  # rileva l'attività e si adatta da solo
bbh run --once                 # un giro completo (sync + recon + notifiche)
bbh run                        # loop residente 24/7 (usato dal servizio systemd)
```

### Governor adattivo (PC di tutti i giorni)

Lo scanner si adatta perché gira sul tuo computer principale:

- **turbo** — imposti tu (`bbh mode turbo`) quando la macchina è libera: usa tutto il PC,
  l'unico freno è la **temperatura**.
- **powersave** — quando stai usando il PC: 1 thread, `nice` 19, ti lascia lavorare.
- **auto** — rileva l'attività dal carico di sistema e sceglie da solo.
- **pausa automatica** se la temperatura è critica (CPU ≥ 90°C o GPU ≥ 92°C), in qualsiasi modalità.

Soglie e regimi si regolano da env (default tarati per Ryzen 7 5700U + RTX 3050):
`BBH_CPU_HOT`, `BBH_CPU_CRITICAL`, `BBH_GPU_HOT`, `BBH_GPU_CRITICAL`,
`BBH_LOAD_BUSY`, `BBH_TURBO_CONC`, `BBH_PS_CONC`, `BBH_POWERSAVE_ON_BATTERY`.
Per la temperatura GPU serve `nvidia-smi` (arriva col driver NVIDIA su NixOS).

### Scan attivo (nuclei) — opt-in

A differenza del recon (passivo), lo scan attivo manda richieste ai bersagli, quindi è
**disattivato di default** e con paletti:

- Si abilita con `BBH_ACTIVE_SCAN=1`.
- Gira **solo in regime NORMAL/TURBO** (mai quando stai usando il PC o se scalda).
- È **rate-limitato** per la singola IP di casa e scansiona **solo bersagli in-scope**
  (scope url/api eleggibili + host vivi scoperti dal recon).
- I findings `vuln` arrivano su Telegram **solo da severità medium in su**; il resto si
  consulta con `bbh findings`.

Configurabile: `BBH_NUCLEI_RATE` (req/s), `BBH_NUCLEI_CONC`, `BBH_NUCLEI_SEVERITY`
(es. `medium,high,critical`), `BBH_NUCLEI_TEMPLATES`, `BBH_NUCLEI_ARGS`, `BBH_ACTIVE_INTERVAL`.

## 24/7 come servizio (modulo NixOS)

```nix
# flake dell'host
imports = [ bbh-scanner.nixosModules.default ];
services.bbh-scanner = {
  enable = true;
  environmentFile = "/run/secrets/bbh.env";   # HACKERONE_* e TELEGRAM_* qui
  settings.BBH_SYNC_INTERVAL = "21600";
  resources = { cpuQuota = "150%"; memoryMax = "1500M"; };
};
```

Il servizio gira con `Nice`, `IOSchedulingClass=idle`, `CPUQuota` e `MemoryMax` per non
saturare l'Acer, e riparte da solo (lo stato è nel DB).

---

## Sviluppo

```bash
python -m pytest -q      # 33 test: normalize, store, collector H1, queue, notify, recon
ruff check . && black .  # lint/format (pre-commit configurato)
```

## Struttura

```
bbh_scanner/
  config.py            normalize.py         logging_setup.py       cli.py
  db/       (schema.sql, store.py)
  collectors/ (base.py, hackerone.py, sync.py)
  recon/      (tools.py, passive.py)
  active/     (nuclei.py)                    # scan attivo (opt-in)
  resources/  (sensors.py, governor.py)     # governor termico/adattivo
  scheduler/  (queue.py, orchestrator.py)
  health.py   systemd.py                     # bbh doctor + sd_notify
  notify/     (base.py, telegram.py)
tests/                 nix/module.nix        flake.nix
Documentazione/architettura-v2.md
bbh_code/              # LEGACY, congelato come riferimento
```
