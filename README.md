# BBH-Scanner — MVP (Fase 1 + Fase 2)

Scanner 24/7 per asset di programmi HackerOne.

**Stato attuale**
- **Fase 1 — Database**: import robusto del dump `H1-All-Scopes.json` in SQLite con normalizzazione `url|api|domain|wildcard`, indici, idempotenza, filtri incrementali.
- **Fase 2 — Filterer**: generazione dei file *seme* per subfinder/httpx/katana/nuclei, hashing per idempotenza, manifest per handle, logging timestampato, notifica Slack (opt‑in).

---

## Requisiti
- Python 3.11+ (ok anche 3.13)
- `sqlite3`
- (per fasi successive) ProjectDiscovery: `subfinder`, `httpx`, `katana`, `nuclei`
- Linux/Fedora target

## Struttura progetto (layout attuale)
```
.
├── bbh_code/
│   ├── __init__.py
│   ├── store.py            # layer DB (programs, scopes) + CLI init/info/list-*
│   ├── import_scopes.py    # import JSON → DB con filtri incrementali
│   └── filterer.py         # Fase 2: genera semi per PD tools + manifest + logging
├── data/
│   ├── H1-All-Scopes.json
│   └── store.db
├── results/
│   └── filtered/<handle>/  # output del filterer (file + .hash + .meta)
├── logs/
│   └── bbh_filtererYYYY.MM.DD-HH.MM.SS.log
└── README.md
```

## Variabili d'ambiente (path dinamici)
- `BBH_ROOT` (default: dedotto dal path dei sorgenti)
- `BBH_DATA_DIR` (default: `$BBH_ROOT/data`)
- `BBH_DB_PATH` (default: `$BBH_DATA_DIR/store.db`)
- `SLACK_WEBHOOK_URL` (opzionale; se presente invia un riepilogo al termine di import/filter)

Esempi:
```bash
BBH_DATA_DIR="/mnt/ssd/bbh-data" python -m bbh_code.store info
BBH_DB_PATH="/tmp/test.db"       python -m bbh_code.import_scopes -i data/H1-All-Scopes.json
```

---

## Fase 1 — Database (import)

### Setup schema
```bash
python -m bbh_code.store init
```

### Import del dump HackerOne
```bash
# import completo con log ogni 1000 scope
python -m bbh_code.import_scopes -i data/H1-All-Scopes.json --progress 1000

# dry-run: analizza senza scrivere
python -m bbh_code.import_scopes -i data/H1-All-Scopes.json --dry-run --progress 2000

# importa solo alcuni handle
python -m bbh_code.import_scopes -i data/H1-All-Scopes.json --only-handles foo,bar

# filtri incrementali
python -m bbh_code.import_scopes -i data/H1-All-Scopes.json \
  --skip-ineligible \
  --min-updated-since 2025-01-01 \
  --progress 2000
```

### Verifiche rapide
```bash
python -m bbh_code.store info
python -m bbh_code.store list-programs
python -m bbh_code.store list-scopes

# query utili
sqlite3 data/store.db "SELECT program_handle, COUNT(*) c FROM scopes GROUP BY 1 ORDER BY c DESC LIMIT 10;"
sqlite3 data/store.db "SELECT normalized_type, COUNT(*) FROM scopes GROUP BY 1 ORDER BY 2 DESC;"
```

---

## Fase 2 — Filterer (generazione file *seme*)

Genera file per i tool ProjectDiscovery, per **handle**:

- `subfinder_seeds.txt`  → **domain** + **wildcard→domain** (subfinder accetta anche `https://...`)
- `httpx_seeds.txt`      → **url + api + domain** (i domain sono in forma `https://host/`), **solo URL pulite**
- `katana_seeds.txt`     → **solo domain + wildcard→https://dom/** (**no url**; **API solo se contengono `*`**)
- `nuclei_urls.txt`      → **url + api**
- `nuclei_urls.jsonl`    → stessa lista in **JSONL** (una riga = `{ "url": "..." }`)

Per ogni file viene creato anche `.hash/<nome>.sha256` per evitare riscritture inutili.

### Manifest per handle
`results/filtered/<handle>/.meta/manifest.json` contiene:
- `last_scope_hash`, `scope_count` (dallo stato DB)
- `filterer_version`, `db_path`, `log_file`
- `started_at`, `finished_at`, `duration_sec`
- `files`: `count/written/hash` per ciascun file

### Logging & Slack
- Log timestampato: `logs/bbh_filterer<YYYY.MM.DD-HH.MM.SS>.log`
- Se `SLACK_WEBHOOK_URL` è impostato viene inviato un riepilogo finale.

### Comandi
```bash
# singolo handle, log progress
python -m bbh_code.filterer --only-handles fiserv --skip-empty --progress 1

# tutti gli handle, salta quelli invariati (scope_hash = manifest)
python -m bbh_code.filterer --skip-unchanged --progress 50

# forza riscrittura anche se hash invariato
python -m bbh_code.filterer --only-handles fiserv --overwrite
```

### Esempio di run (dal tuo ambiente)
```
[Filterer] v0.2.0 Handles=1 files_written=1 files_skipped=4 skip_unchanged=0 duration_sec=0.14 log=bbh_filterer2025.10.20-01.58.02.log
- fiserv
    subfinder_seeds.txt written=False count=9718
    httpx_seeds.txt    written=False count=10762
    katana_seeds.txt   written=False count=9715
    nuclei_urls.txt    written=False count=1051
    nuclei_urls.jsonl  written=True count=1051
```

### Sanity check
```bash
grep -n '^[[:space:]]*$' -R results/filtered/<handle>/*.txt || echo "ok: nessuna riga vuota"
awk 'index($0,"://")==0{print "NO_SCHEMA: "$0}' results/filtered/<handle>/httpx_seeds.txt | head
grep '^\*\.' results/filtered/<handle>/subfinder_seeds.txt && echo "ATT: wildcard rimaste" || echo "ok: no wildcard"
```

---

## Troubleshooting
- **fish shell**: evita process substitution `<(...)` e heredoc stile bash; usa stringhe inline o file `.sql`.
- **Import lento**: usa `--progress N` per tracciare. L’import fa transazione unica + PRAGMA.
- **Path di package**: la cartella deve chiamarsi `bbh_code/` e contenere `__init__.py`. Esegui dalla root del progetto.

---

## Roadmap immediata
- **Fase 3 — Runner/Orchestrator**: esecuzione periodica di subfinder → httpx → katana (headless, senza limit depth) → reduce → nuclei (output JSONL), con integrazione log durate e notifiche.
- **Collector API (HackerOne)**: fetch aggiornamenti, salva in formato compatibile e richiama `import_scopes`.

