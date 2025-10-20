# Makefile "tascabile" per BBH-Scanner
# Uso esempi:
# make db-init
# make import
# make filter-one H=fiserv


PY := python
DB := data/store.db
JSON := data/H1-All-Scopes.json


.PHONY: db-init info list-programs list-scopes import import-inc filter-one filter-all filter-overwrite top10 sanity logs


# --- Fase 1: DB / Import ---


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


# Import incrementale (esempio):
import-inc:
$(PY) -m bbh_code.import_scopes -i $(JSON) --skip-ineligible --min-updated-since 2025-01-01 --progress 2000


# --- Fase 2: Filterer ---


# Singolo handle (H=fiserv), salta invariati e non crea file vuoti
filter-one:
$(PY) -m bbh_code.filterer --only-handles $(H) --skip-empty --skip-unchanged --progress 1
@ls -1 logs/bbh_filterer*.log 2>/dev/null || echo "(nessun log filterer)"
