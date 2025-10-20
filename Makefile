# Makefile "tascabile" per BBH-Scanner
# Uso: make filter-one H=fiserv

PY := python
DB := data/store.db
JSON := data/H1-All-Scopes.json

.PHONY: db-init info list-programs list-scopes import import-inc filter-one filter-all filter-overwrite top10 sanity logs

db-init:
	$(PY) -m bbh_code.store init

info:
	$(PY) -m bbh_code.store info

list-programs:
	$(PY) -m bbh_code.store list-programs

list-scopes:
	$(PY) -m bbh_code.store list-scopes

import:
	$(PY) -m bbh_code.import_scopes -i $(JSON) --progress 2000

import-inc:
	$(PY) -m bbh_code.import_scopes -i $(JSON) --skip-ineligible --min-updated-since 2025-01-01 --progress 2000

filter-one:
	$(PY) -m bbh_code.filterer --only-handles $(H) --skip-empty --skip-unchanged --progress 1

filter-all:
	$(PY) -m bbh_code.filterer --skip-unchanged --progress 50

filter-overwrite:
	$(PY) -m bbh_code.filterer --only-handles $(H) --overwrite

top10:
	sqlite3 $(DB) "SELECT program_handle, COUNT(*) c FROM scopes GROUP BY 1 ORDER BY c DESC LIMIT 10;"

sanity:
	@grep -n '^[[:space:]]*$$' -R results/filtered/$(H)/*.txt || echo "ok: nessuna riga vuota"
	@awk 'index($$0,"://")==0{print "NO_SCHEMA: "$$0}' results/filtered/$(H)/httpx_seeds.txt | head || true
	@grep '^\*\.' results/filtered/$(H)/subfinder_seeds.txt && echo "ATT: wildcard rimaste" || echo "ok: no wildcard"

logs:
	@ls -1 logs/bbh_filterer*.log 2>/dev/null || echo "(nessun log filterer)"
