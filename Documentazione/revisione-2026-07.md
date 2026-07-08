# Revisione del progetto — luglio 2026

Valutazione a mente fredda dopo il primo collaudo end-to-end sull'Acer (M1→M4 validate
su hardware reale: API HackerOne, tool PD, sensori CPU/GPU, Telegram). ~3000 righe,
81 test verdi. Obiettivo di questa nota: dire con onestà cosa è solido, cosa è debole,
e come rendere l'applicativo **più facile da usare**.

---

## 1) Stato: cosa funziona bene

- **Architettura a strati pulita**: `collectors / recon / active / resources / scheduler /
  notify / db`. Ogni dominio è isolato e sostituibile (aggiungere Bugcrowd non tocca lo scheduler).
- **Nucleo di logica pura e testata**: normalizzazione, `governor.decide`, `queue.select_due`,
  parser (HackerOne, nuclei) sono funzioni pure → 81 test senza rete né tool.
- **Store SQLite robusto**: connessione unica, WAL, upsert batch, migrazioni via `user_version`.
- **Coda job ripartibile**: enqueue→claim→esegui→complete/fail, dedup, backoff, requeue orfani.
- **Governor termico/adattivo**: la parte più originale, e **validata su hardware** (throttle
  reale su temperatura, turbo/powersave su presenza utente).
- **Sicurezza operativa**: scan attivo opt-in, rate-limitato, solo bersagli in-scope; segreti
  fuori dal repo; notifiche baseline-silent + raggruppate (niente spam).

## 2) Debolezze e rischi (onestà)

| Area | Problema | Impatto | Priorità |
|------|----------|---------|----------|
| `scheduler/orchestrator.py` | 528 righe, "god-object": sync+recon+scan+persistenza+notifiche+loop. `do_recon` e `do_active_scan` duplicano il drain della coda. | Manutenibilità | media |
| Config | ~40 variabili d'ambiente, 9 dataclass. Potente ma poco scopribile. | Usabilità | **alta** |
| Onboarding | Serviva `export` a ogni sessione; alias fish/bash; username=identifier non ovvio. | Usabilità | **alta** |
| Collector | `list_programs` scarica TUTTE le pagine a ogni sync (anche con `--only-handle`). | Efficienza | media |
| `bbh_code/` legacy | Ancora nel repo come riferimento. | Pulizia | bassa |
| GPU nel servizio | `nvidia-smi` non raggiungibile nel sandbox systemd hardened → GPU `n/d` (CPU ok). | Funzionale | bassa |
| Due DB | Dev shell e servizio usano DB diversi → confusione (mitigato da `bbh-ctl`). | Usabilità | media |
| Osservabilità | Log JSON + tabella events, ma nessuna rotazione dei log su file. | Operatività | bassa |

## 3) Fatto in questa revisione (usabilità)

- **Caricamento automatico `.env`** (`config.load_env_files`): metti le credenziali in un file
  `.env` (già gitignorato, vedi `.env.example`) e ogni comando `bbh` le carica da solo —
  **basta `export` a ogni sessione**. L'ambiente reale ha comunque la precedenza.
- **`bbh status` = dashboard**: una schermata con regime+temperature, programmi, scope per tipo,
  asset (sottodomini/host/vivi), findings (vuln per severità), coda job. `--events` per il log.
- **Help con esempi** + docstring aggiornata con tutti i comandi raggruppati per funzione.

## 4) Roadmap dei miglioramenti (proposta, in ordine di valore)

**Usabilità (continua)**
1. **`bbh setup`** — wizard: lancia `doctor`, se mancano credenziali offre di scrivere il `.env`,
   poi `init` + `sync`. Un solo comando per partire da zero.
2. **`bbh watch`** — vista live (dashboard che si aggiorna ogni N secondi) per seguire il 24/7.
3. **Colori/tabelle** condizionali (solo se TTY) per findings e jobs.
4. **`bbh programs enable/disable <handle>`** — per concentrarsi su un sottoinsieme.

**Qualità del codice**
5. **Unificare il drain della coda**: un `_run_jobs(kind, runner)` generico che `do_recon` e
   `do_active_scan` riusano → orchestrator più piccolo e una sola macchina a stati.
6. **Rimuovere `bbh_code/`** una volta che il nuovo path è pienamente in uso.
7. **Rotazione log** (RotatingFileHandler) + retention dei file, non solo degli eventi DB.

**Funzionalità**
8. **Collector più efficiente**: cache dell'elenco programmi + sync incrementale anche sulla
   lista (non solo sugli scope).
9. **M5 — Bugcrowd** dietro `collectors/base` (seconda piattaforma).
10. **M6 — frontend web**: dashboard read-only sopra lo Store (stato/coda/findings/temperature),
    poi controllo regime. API leggera su `db/store.py`.
11. **Arricchimento findings nuclei**: raccolta `curl`/request di riproduzione, export report.

## 5) Principio guida

Il valore non è "vedere i sottodomini una volta" (lo fa chiunque), ma **sorvegliare 24/7 e
avvisare solo sulle novità**. Ogni scelta di design e di UX dovrebbe servire questo: far sì che
lo scanner giri da solo, ceda il passo quando usi il PC, e ti disturbi solo quando c'è davvero
qualcosa di nuovo o una vulnerabilità.
