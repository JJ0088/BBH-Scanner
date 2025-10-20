# Changelog


Tutte le modifiche rilevanti a **BBH-Scanner**.


## [0.2.0] - 2025-10-20
### Aggiunto
- **Fase 2 – Filterer**: `bbh_code/filterer.py` con output:
- `subfinder_seeds.txt`, `httpx_seeds.txt`, `katana_seeds.txt`
- `nuclei_urls.txt`, `nuclei_urls.jsonl` (input JSONL per nuclei)
- **Idempotenza** via hash per-file: `.hash/<file>.sha256`.
- **Manifest per handle**: `results/filtered/<handle>/.meta/manifest.json` con `last_scope_hash`, `scope_count`, timing, versione, contatori file.
- Flag **`--skip-unchanged`**: salta un handle se `scope_hash` (DB) coincide con `last_scope_hash` (manifest).
- **Logging** timestampato: `logs/bbh_filterer<YYYY.MM.DD-HH.MM.SS>.log` + messaggi Slack (opt‑in con `SLACK_WEBHOOK_URL`).


### Cambiato
- Normalizzazione e regole di selezione semi: `katana` riceve SOLO `domain` e `wildcard→domain` (root URL), le `api` solo se contengono `*`. `httpx` riceve sole URL pulite. `nuclei` usa input **JSONL**.


## [0.1.0] - 2025-10-20
### Aggiunto
- **Fase 1 – Database**:
- `bbh_code/store.py` (schema SQLite, CLI `init|info|list-*`).
- `bbh_code/import_scopes.py` (import JSON HackerOne → DB) con filtri:
- `--only-handles`, `--skip-ineligible`, `--min-updated-since`, `--dry-run`, `--progress`.
- Normalizzazione scope: `url | api | domain | wildcard`.
- Indici, transazione unica, `ANALYZE`/`PRAGMA optimize` post‑import.
