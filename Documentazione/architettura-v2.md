# BBH-Scanner — Architettura v2 (rewrite)

> Stato: **rewrite dello scheletro, trapianto della logica sana**. Obiettivo: scanner
> **24/7 su singola macchina** (Acer Aspire 7, NixOS), multi-piattaforma in prospettiva
> (HackerOne ora; Bugcrowd/YesWeHack/Intigriti dopo), **recon-only** in questa fase.

---

## 0) Decisioni prese

| Tema | Scelta | Note |
|------|--------|------|
| Postura scansione | **Recon-only** | Nessuno scan attivo (nuclei) finché l'infra non è solida e testata. |
| Ambiente | **Nix flake + modulo NixOS** | Env riproducibile, systemd dichiarativo, limiti risorse via cgroup. Immagine OCI generabile dal flake se serve portabilità (VPS). |
| Codebase | **Rewrite `bbh_scanner/`**, `bbh_code/` congelato come riferimento | Si trapiantano le funzioni pure (`normalize`, `reduce`) sotto test. `bbh_code/` verrà rimosso quando il nuovo path lo sostituisce. |
| Notifiche | **Telegram** | Findings, heartbeat, errori. `NullNotifier` di default se non configurato. |
| Store | **SQLite** (single-host) ridisegnato | Connessione unica, WAL, batch, nuove tabelle jobs/findings/events. |

**Assunzioni hardware (da confermare):** ~4 core, 8–16 GB RAM, SSD. Tutti i parametri
di concorrenza/retention/limiti sono in `config.py` e nel modulo NixOS: si regolano
coi numeri reali dell'Acer senza toccare il codice.

---

## 1) Perché rewrite e non refactor

Il vecchio MVP è fatto di **script one-shot** (`import_scopes` legge un file statico,
`runner` fa un giro e termina). Il target è un **servizio residente** con collector
live, scheduler, coda di job con macchina a stati e storage dei risultati. Non esiste
un modello `jobs`/`findings`/`events` in cui rifattorizzare: aggiungerlo accanto al
vecchio sarebbe una riscrittura travestita. La scelta recon-only inoltre mette da parte
proprio il modulo più grosso del vecchio codice (il runner attivo), quindi la superficie
da riscrivere ora è piccola.

Si **trapiantano verbatim** (e finalmente si testano) le parti pure che già funzionano:
`detect_and_normalize`, `normalize_url`/reduce, gestione wildcard.

---

## 2) Layout del package

```
bbh_scanner/
  __init__.py            # versione
  config.py              # Config da env + default (path, credenziali, budget risorse)
  logging_setup.py       # logging strutturato JSON + evento su DB
  normalize.py           # [TRAPIANTO] detect_and_normalize + helpers reduce (TESTATO)
  db/
    schema.sql           # DDL (user_version per migrazioni)
    store.py             # connessione unica, WAL, upsert batch, API tipizzata
  collectors/
    base.py              # Protocol Platform (list_programs / iter_scopes / sync)
    hackerone.py         # client Hacker API v1 + sync incrementale (updated_at cursor)
  recon/
    tools.py             # rilevazione tool + subprocess runner con timeout
    passive.py           # pipeline passiva: subfinder -> dnsx -> httpx (recon-only)
  scheduler/
    queue.py             # selezione/prioritizzazione job (PURA, TESTATA)
    orchestrator.py      # loop residente: sync quando dovuto, enqueue+esegui recon
  notify/
    base.py              # Notifier ABC + NullNotifier
    telegram.py          # Bot API
  cli.py                 # init | sync | recon | status | run(daemon) | version

tests/                   # pytest: normalize, store, hackerone(parse+sync), queue
nix/
  module.nix             # modulo NixOS: servizi systemd + timer + limiti risorse
flake.nix                # dev shell + package + immagine OCI opzionale
```

`bbh_code/` resta come **riferimento congelato** finché il nuovo path non lo sostituisce.

---

## 3) Modello dati (SQLite)

Chiave logica multi-piattaforma: quasi tutto è namespaced per `(platform, program_handle)`.

- **programs** — un record per programma. `platform, handle, name, url, offers_bounties,
  submission_state, state, open_scope, last_fetch_at, scope_count, scope_hash, enabled`.
  `enabled` = decidiamo noi se monitorarlo.
- **scopes** — asset dichiarati dal programma. `platform, program_handle, asset_identifier,
  asset_type, eligible_for_bounty, eligible_for_submission, max_severity, instruction,
  created_at, updated_at, normalized_type (url|api|domain|wildcard), normalized_value,
  first_seen_at, last_seen_at`.
- **assets** — asset **scoperti** dal recon (sottodomini, host vivi). `platform,
  program_handle, scope_id, kind (subdomain|host|url), value, source (subfinder|httpx|seed),
  alive, meta(json), first_seen_at, last_seen_at`.
- **jobs** — coda di lavoro con macchina a stati. `kind (sync|recon_passive), platform,
  program_handle, target, state (queued|running|done|failed), priority, attempts,
  next_due_at, sig, error, timestamps`. È ciò che rende il 24/7 **ripartibile**: se il
  processo muore, riprende dallo stato in DB.
- **findings** — delta di recon (per ora): `kind (new_subdomain|new_host|host_down|new_tech),
  fingerprint UNIQUE (dedup), severity, title, data(json), status (new|known|resolved),
  first_seen_at, last_seen_at, notified_at`. Estendibile ai findings nuclei in futuro.
- **events** — audit/osservabilità interrogabile: `ts, level, component, job_id,
  program_handle, message, data(json)`.
- **sync_state** — cursori incrementali: es. `hackerone:programs:page`,
  `hackerone:<handle>:scopes_updated_cursor`.

Migrazioni: `PRAGMA user_version`; `store.py` applica gli step in ordine.

---

## 4) Collector HackerOne (Hacker API v1)

- Base `https://api.hackerone.com/v1/hackers/`, **HTTP Basic** (token id = user, token = pass).
  Community edition (gratuita) è sufficiente.
- **Rate limit**: 600 req/min lettura → client con throttle + backoff su `429`.
- Flusso **sync incrementale**:
  1. `GET /hackers/programs` paginato → upsert `programs` filtrando `submission_state=open`,
     `offers_bounties=true`, `state` attivo.
  2. Per ogni programma dovuto: `GET /hackers/programs/{handle}/structured_scopes` con
     **`filter[updated_at__gt]=<cursor>`** (novità API 2026) → solo scope cambiati.
     Prima sync: full; successive: incrementali.
  3. Normalizzazione (`normalize.detect_and_normalize`) → upsert `scopes`, ricalcolo
     `scope_hash`, aggiornamento cursore in `sync_state`, log su `events`.
- Solo tipi di asset gestibili dal toolchain web (url/api/domain/wildcard); gli altri
  (CIDR, mobile, source) vengono registrati ma non schedulati per il recon.

Parsing separato dalla rete (`parse_program`, `parse_scope`) → testabile senza token.

---

## 5) Recon passivo (questa fase)

Pipeline per programma, **passiva** (nessuna richiesta intrusiva agli asset):

```
seeds (wildcard/domain)  ->  subfinder  ->  dnsx (risolve)  ->  httpx (probe vivo)
                                   \-> assets(kind=subdomain)      \-> assets(kind=host, alive)
```

- `subfinder` fa enumerazione passiva dei sottodomini dai seed wildcard/domain.
- `dnsx` risolve i sottodomini (scarta i morti).
- `httpx` verifica quali host rispondono (probe leggero, rate-limit basso).
- **Delta → findings**: nuovo sottodominio, nuovo host vivo, host caduto. Questi sono
  i segnali che vogliamo notificare (asset monitoring), la base su cui più avanti
  agganceremo nuclei.

Ogni step è guardato dalla disponibilità del tool (`recon/tools.py`); se un tool manca,
lo step viene saltato e loggato, non crasha.

---

## 6) Scheduler / 24-7

`orchestrator.tick()` (loop residente, invocato da systemd o auto-loop):
1. **Sync** collector se `now >= next_sync_due`.
2. **Enqueue**: per ogni programma `enabled` con `next_due_at <= now`, crea/aggiorna un
   job `recon_passive`.
3. **Esegui** i job in coda **entro il budget risorse** (concorrenza max, `nice`/`ionice`,
   rate-limit dei tool). Idempotenza via `sig` (hash dei seed+parametri): se invariato, skip.
4. **Backoff/retry** sui fallimenti; `next_due_at` ricalcolato (staleness + priorità).
5. **Heartbeat** periodico su Telegram + `events`.

Prioritizzazione (in `queue.py`, pura e testata): scope appena cambiati > programmi mai
scansionati > più stantii. Un asset nuovo = superficie non ancora testata.

---

## 7) Governance risorse (vincolo Acer)

Tre colli di bottiglia, progettati fin da subito:
- **CPU/RAM**: concorrenza limitata (`BBH_MAX_CONCURRENCY`), `nice`/`ionice`, e nel modulo
  NixOS `CPUQuota=`, `MemoryMax=`, `MemoryHigh=` sul servizio.
- **Disco**: gli output crescono in fretta. Retention configurabile (`BBH_RETENTION_DAYS`),
  compattazione, niente crawl pesanti in fase recon.
- **Rete**: singola IP di casa → throttle sui tool, probe leggeri, niente scan attivi
  (coerente con recon-only). Se in futuro serve intensità, si valuta VPS/proxy (l'immagine
  OCI dal flake rende il trasloco banale).

---

## 8) Osservabilità

- **Log strutturati JSON** su file (rotazione) + specchio degli eventi rilevanti su tabella
  `events` (interrogabile: `bbh status`, query SQL).
- **Metriche**: conteggi programmi/scope/asset, durate step, findings per kind.
- **Notifiche Telegram**: nuovi findings, heartbeat periodico, errori/health.
- **`bbh status`**: snapshot a colpo d'occhio (programmi, ultima sync, coda, findings recenti).

---

## 9) Milestone

- **M1 (questa)** — Fondamenta: config, DB+schema, normalize trapiantato+testato,
  collector H1 (parse+sync incrementale, testato con fake), notify Telegram, CLI
  (`init/sync/status/version`), flake+modulo NixOS, test verdi.
- **M2** — Recon passivo end-to-end sull'Acer: `subfinder→dnsx→httpx`, tabella `assets`,
  delta→`findings`, notifiche. Tuning budget risorse coi numeri reali.
- **M3** — Orchestratore residente 24/7 come servizio systemd + timer, heartbeat, retention.
- **M4** — Scan attivo opzionale (nuclei) gated per-policy; port dei quirk del vecchio runner.
- **M5** — Seconda piattaforma (Bugcrowd) dietro la stessa astrazione `collectors/base`.

---

## 10) Setup rapido (target NixOS)

```bash
# dev
nix develop            # shell con python + subfinder/dnsx/httpx + pytest
bbh init               # crea DB + schema
export HACKERONE_API_USERNAME=... HACKERONE_API_TOKEN=...
export TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...
bbh sync               # sincronizza programmi/scope H1
bbh status             # snapshot

# 24/7 (modulo NixOS)
services.bbh-scanner.enable = true;   # vedi nix/module.nix
```
