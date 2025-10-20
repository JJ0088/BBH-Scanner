# BBH-Scanner — Documento Tecnico (MVP)

> Stato: **MVP stabile lato dati** (import JSON → DB), pronto per Fase 2 (Filterer → liste operative). Obiettivo: scanner 24/7 su singolo dispositivo, idempotente e tracciabile.

---

## 1) Scopo del progetto
BBH-Scanner automatizza il ciclo del bug bounty su scope pubblici HackerOne:
- Scarica/aggiorna programmi e relativi scope (Collector).
- Normalizza/filtra asset e genera liste operative per tool esterni (Filterer).
- Orchestrazione degli scanner per tipo di asset (Orchestrator):
  - `url` → nuclei diretto
  - `api` → nuclei diretto
  - `domain` → katana + httpx + nuclei
  - `wildcard` → subfinder + httpx + katana + nuclei
- Gira 24/7, ripetendo i passaggi con idempotenza e stato persistente.

**Scopo formativo**: comprendere ogni riga e costruire un progetto manutenibile.

---

## 2) Architettura logica (MVP)
Componenti principali:
- **Store (SQLite)**: indice/stato del sistema (programs, scopes, scans in futuro). Persistente, transazionale, single-machine friendly.
- **Importer**: legge `data/H1-All-Scopes.json` e popola `store.db` con normalizzazione basilare.
- **(Fase successiva)** Filterer: dal DB produce liste per katana/httpx/nuclei.
- **(Fase successiva)** Orchestrator: consuma le liste, esegue i tools, registra risultati.

Flusso dati attuale: `H1-All-Scopes.json` → **import_scopes** → **store.db**.

---

## 3) Layout directory (attuale)
```
/home/jj/Desktop/Project/BBH-Scanner/
├─ bbh_code/                 # package Python
│  ├─ __init__.py
│  ├─ store.py               # DB layer (programs, scopes)
│  └─ import_scopes.py       # Import JSON → DB
├─ data/
│  ├─ store.db               # SQLite database
│  ├─ H1-All-Scopes.json     # dump del Collector (sorgente)
│  └─ backups/
├─ results/
│  ├─ filtered/              # (fase 2) liste generate dal Filterer
│  └─ queues/                # (fase 2) code prioritarie
├─ logs/
│  └─ bbh.log                # log applicativi (futuro)
├─ systemd/                  # unit & timer (futuro)
├─ .env                      # variabili (H1 API, ecc.)
├─ .gitignore
└─ README.md (TODO)
```

---

## 4) Ambiente & path dinamici
- **Python 3.11+**
- DB/Paths configurabili via **env**:
  - `BBH_ROOT` (root progetto; default: percorso dedotto)
  - `BBH_DATA_DIR` (default: `$BBH_ROOT/data`)
  - `BBH_DB_PATH` (default: `$BBH_DATA_DIR/store.db`)

Esempi:
```
BBH_DATA_DIR="/mnt/ssd/bbh-data" python -m bbh_code.store info
BBH_DB_PATH="/tmp/x.db"         python -m bbh_code.import_scopes -i data/H1-All-Scopes.json
```

---

## 5) Schema DB (MVP)
Tabelle create in `store.py`:
- **programs**: info sintetica per programma (handle, state, scope_count, scope_hash, last_fetch_at…)
- **scopes**: asset per programma, con `normalized_type` (`url|api|domain|wildcard`) e `normalized_value`.

Vincoli/indici:
- `UNIQUE(program_handle, asset_identifier)` evita duplicati.
- Indici su `asset_identifier`, `normalized_type`, `(program_handle, normalized_type)` per query veloci.

---

## 6) Importer — comportamento
Script: `bbh_code/import_scopes.py`.
- Accetta **3 formati** JSON: `{ programs: {…} }`, `{ programs: [ … ] }`, `[ … ]`.
- Normalizzazione asset:
  - `*.example.com` → `wildcard`
  - `https(s)://…` → `url` (o `api` se host/pattern corrisponde)
  - `domain` nudo → `https://domain/`
- **Performance**: transazione unica, `PRAGMA WAL`, `synchronous=NORMAL`, cache in RAM.
- **Progress log**: ogni N scope.
- **Flag CLI**:
  - `--dry-run` (parse-only),
  - `--only-handles a,b,c` (subset dei programmi),
  - `--progress N` (frequenza log progresso).
- **Post-import**: crea indici e chiama `ANALYZE` + `PRAGMA optimize`.

Comandi utili:
```
python -m bbh_code.import_scopes -i data/H1-All-Scopes.json --progress 1000
python -m bbh_code.store info
sqlite3 data/store.db "SELECT program_handle, COUNT(*) c FROM scopes GROUP BY 1 ORDER BY c DESC LIMIT 5;"
sqlite3 data/store.db "SELECT normalized_type, COUNT(*) FROM scopes GROUP BY 1 ORDER BY 2 DESC;"
```

Esempio risultato (tua macchina):
```
programs: 536
scopes:   42311
Top handle: fiserv, cbre, clarivate, john-deere, ion
Type counts: domain=34052, url=4560, wildcard=3203, api=496
```

---

## 7) Principi chiave già applicati
- **Idempotenza**: upsert su `programs`/`scopes` (stesse entry non si duplicano).
- **Atomicità**: unica transazione per import massivo.
- **Tracciabilità**: `scope_hash` e contatori.
- **Configurabilità**: env per spostare dati/DB senza patch di codice.

---

## 8) Roadmap (prossime mosse)
**Fase 2 — Filterer (dal DB → liste operative)**
- Leggi `scopes` filtrando per tipo.
- Genera:
  - `results/filtered/<handle>/nuclei_urls.txt` (url + api)
  - `results/filtered/<handle>/katana_seeds.txt` (domain)
  - `results/filtered/<handle>/subfinder_seeds.txt` (wildcard)
- Opzioni: `--only-handles`, `--min-changed-since`, `--rewrite/append`.
- Idempotenza: hash del contenuto scritto per evitare riscritture inutili.

**Fase 3 — Orchestrator (liste → scans)**
- Legge liste e lancia pipeline per tipo (tier1/2/3).
- Stato job (queued/running/done/failed) su DB (`jobs`/`scans`).
- Output strumenti in `results/scans/<handle>/<ts>/…` + `state.json`.

**Fase 4 — Runner 24/7 (systemd)**
- `bbh-collector.timer` (ogni 15–30 min) — quando integreremo H1 API.
- `bbh-orchestrator.service` (always-on o timer) con limiti CPU/RAM.

**Fase 5 — Observability**
- Log JSON in `logs/` con rotazione.
- Metriche Prometheus di base: `scopes_total`, `jobs_*`, `nuclei_findings_total{sev}`.

---

## 9) Scelte progettuali: perché così
- **SQLite**: zero-deps, transazionale, perfetto per single-host 24/7.
- **DB + file**: DB per orchestrazione/stato; file `.txt/.jsonl` per tool esterni (compatibilità massima).
- **Path dinamici via env**: portabilità senza toccare codice.
- **Idempotenza by design**: pipeline ripetibile senza effetti collaterali.

---

## 10) TODO immediati (se servono)
- `.gitignore` minimale:
```
__pycache__/
.venv/
*.pyc
logs/
data/*.db
data/backups/
results/
```
- `README.md` con:
  - setup, comandi base, struttura cartelle, variabili env
  - troubleshooting (fish vs bash, permessi, spazio disco)
- Script `validate_scopes.py` (opzionale) per controlli senza DB.

---

## 11) Note operative
- Fish shell: evita process substitution e heredoc bash; usa stringhe "in linea" o file `.sql`.
- Spazio disco: monitorare `data/` e `results/`; considerare backup `data/backups/` giornaliero.
- Sicurezza: non committare `.env` e file `*.db`.

---

## 12) Glossario rapido
- **Scope**: asset scansionabile (url, api, domain, wildcard) definito dal programma H1.
- **Idempotenza**: stessa operazione ripetuta produce lo stesso stato senza duplicati.
- **Upsert**: INSERT con fallback UPDATE su conflitto (non duplica).
- **WAL**: modalità journal SQLite che accelera le scritture concorrenti su single-host.

---

Fine documento (MVP). Prossimo capitolo: **Filterer**.

