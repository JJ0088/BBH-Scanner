# BBH-Scanner — Guida completa

> Documento "so-tutto": cos'è, come funziona, come si usa, cosa c'è sotto e cosa manca.
> Pensato per riprendere in mano il progetto anche a distanza di tempo, senza ricordare i dettagli.

---

## 1) In una frase

Un **scanner di bug bounty automatico** che gira **24/7** sul tuo PC, sorveglia i programmi
di HackerOne, e ti avvisa su Telegram **solo quando trova qualcosa di nuovo o una vulnerabilità**.

## 2) La filosofia (perché esiste)

Chiunque può lanciare subfinder e "vedere i sottodomini una volta". Il valore non è quello.
Il valore è **sorvegliare centinaia di programmi in continuazione e accorgersi del *cambiamento*
nell'istante in cui accade**: un sottodominio nuovo = un deploy fresco = superficie che nessuno
ha ancora testato = dove si trovano i bug. Lo scanner lavora da solo mentre tu fai altro, e ti
disturba solo quando c'è un motivo.

Tre principi guida:
- **Silenzioso di default**: la prima mappatura di un programma non genera notifiche (è il
  "punto zero"); da lì in poi avvisa solo sui delta.
- **Cede il passo**: è il tuo PC di tutti i giorni, quindi rallenta quando lo usi e quando scalda.
- **Ripartibile**: se il PC si spegne, riprende da dove era (lo stato è nel database).

## 3) Come funziona (il flusso, spiegato semplice)

```
   HackerOne API
        │  (collector: scarica programmi e "scope" = domini/URL in-scope)
        ▼
   Database SQLite  ──────────────────────────────────────────────┐
        │                                                          │
        │  (scheduler: mette in coda i programmi "da fare",        │
        │   dando priorità ai nuovi e a quelli cambiati)           │
        ▼                                                          │
   RECON PASSIVO (non intrusivo)                                   │
   subfinder → dnsx → httpx                                        │
   (trova sottodomini → tiene quelli che risolvono → quali sono vivi)
        │                                                          │
        ├─► asset scoperti + DELTA (nuovo sottodominio / host / host caduto)
        │                                                          │
        ▼                                                          │
   SCAN ATTIVO (opt-in)                                            │
   nuclei sui bersagli in-scope → findings "vuln" con severità    │
        │                                                          │
        ▼                                                          │
   NOTIFICHE Telegram ◄───────────────────────────────────────────┘
   (riepilogo delta per programma + vuln da medium in su)
```

Il tutto è governato da un **governor termico/adattivo** che decide quanto spingere in base a
temperatura CPU/GPU e a quanto stai usando il PC.

## 4) Cosa fa OGGI (stato — v0.4.0)

✅ **Funziona e validato sull'Acer reale:**
- Collector HackerOne (sync incrementale: dopo la prima volta scarica solo ciò che è cambiato).
- Recon passivo completo (subfinder → dnsx → httpx), con delta → findings.
- Scan attivo nuclei (opt-in, rate-limitato, solo bersagli in-scope).
- Governor termico (turbo/normal/powersave/pausa) con sensori CPU+GPU reali.
- Notifiche Telegram + **bot a comandi** per interrogarlo dal vivo.
- Coda di lavoro ripartibile, retention, arresto pulito.
- 87 test automatici verdi.

## 5) Come si usa — cheat sheet dei comandi

Dentro `nix develop` (o dopo `pip install -e .`), il comando è `bbh`:

| Comando | Cosa fa |
|---|---|
| `bbh setup` | **Onboarding in un colpo**: crea `.env`, verifica tutto, inizializza, sincronizza |
| `bbh doctor --online` | Verifica che tutto sia pronto (DB, credenziali, tool, sensori, Telegram) |
| `bbh sync` | Scarica programmi/scope da HackerOne |
| `bbh run` | **Avvia il loop 24/7** (recon + scan + notifiche + bot Telegram) |
| `bbh status` | Dashboard: regime, temperatura, programmi, asset, findings, coda |
| `bbh watch` | Dashboard dal vivo (si aggiorna ogni N secondi) |
| `bbh findings --kind vuln` | Elenca i findings (filtrabili per tipo/severità) |
| `bbh jobs` | Stato della coda di lavoro |
| `bbh sensors` | Temperature CPU/GPU e regime deciso |
| `bbh mode turbo` | Cambia regime (auto / turbo / powersave / paused) |
| `bbh recon --limit 1` | Recon su un singolo programma (test manuale) |
| `bbh scan --limit 1` | Scan attivo su un singolo programma (test manuale) |

### Controllo da Telegram (mentre gira)
Scrivi al tuo bot: `/status` `/logs 20` `/findings high` `/jobs` `/sensors` `/mode turbo`
`/pause` `/resume` `/help`. Risponde solo a te (filtro sulla tua chat).

## 6) Configurazione (il file `.env`)

Copia `.env.example` in `.env`, riempi i valori una volta, e ogni comando li carica da solo.
Le variabili principali:

- `HACKERONE_API_USERNAME` = **l'identifier del token** (NON il tuo handle!), `HACKERONE_API_TOKEN`
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (notifiche + bot)
- `BBH_ACTIVE_SCAN=1` per accendere lo scan attivo
- `BBH_HEARTBEAT_INTERVAL` (secondi, default 43200 = 12h)
- Soglie governor: `BBH_CPU_HOT` (82), `BBH_CPU_CRITICAL` (90), `BBH_GPU_HOT` (85), `BBH_GPU_CRITICAL` (92)
- Intervalli: `BBH_SYNC_INTERVAL` (6h), `BBH_RECON_INTERVAL` (24h)

## 7) Sotto il cofano (architettura, per curiosità)

Package `bbh_scanner/`, a strati:
- `collectors/` — astrazione piattaforma + HackerOne (pronta per Bugcrowd/YesWeHack/Intigriti).
- `recon/` — tool passivi e pipeline.
- `active/` — nuclei.
- `resources/` — sensori + governor.
- `scheduler/` — coda (`queue`) + orchestratore (`orchestrator`, il "direttore d'orchestra").
- `notify/` + `telegram_bot.py` — notifiche e bot a comandi.
- `db/` — SQLite (tabelle: programs, scopes, assets, jobs, findings, events, sync_state).
- `config.py`, `health.py` (bbh doctor), `systemd.py`, `cli.py`.

Ambiente: **Nix flake** (dev shell + package + immagine Docker opzionale) e **modulo NixOS**
per il servizio 24/7 con limiti di risorsa. `bbh_code/` è il vecchio MVP, congelato come riferimento.

Sviluppo su branch `claude/repository-analysis-9rz3z1`, pull request #1.

## 8) La roadmap (cosa manca e prossimi passi)

### Decisioni prese (brainstorming luglio 2026)

**✅ Subdomain takeover** — CNAME "danglanti" verso servizi non reclamati. È il **prossimo
finding da aggiungere**: piccolo, autonomo, alta resa, basso rumore.

**⚠️ JS analysis — sì ma FATTO BENE, non a regex cieca.** La regex ingenua raccoglie tutte le
chiavi che sono *pubbliche per design* (Firebase web key, Google Maps, ecc.) → montagne di
ciarpame. Quindi, quando lo faremo:
  - priorità all'estrazione di **endpoint / route API / parametri** dai JS (alto valore, basso rumore);
  - i secret vanno **validati** (la chiave concede davvero accesso?) prima di notificare — niente
    alert su chiavi innocue.

**🟡 URL storici (gau/waybackurls)** — da valutare: endpoint vecchi e dimenticati. Utile ma
può portare rumore; lo aggiungeremo con filtri.

**💡 Punteggio di postura di sicurezza (idea da sviluppare, tua):** invece di buttare i findings
info/low, **aggregarli in uno "score di fragilità" per programma** (header di sicurezza mancanti,
tecnologie datate, pannelli esposti, numero di segnali info/low, takeover potenziali, ecc.).
Lo scanner **flagga i programmi più fragili**, e tu vai a testarli a mano. Trasforma il rumore
in un *segnale di targeting*. Da progettare: pesi dei segnali, soglia di "fragile", comando
`bbh score` / notifica dedicata.

### Milestone future
- **M5 — Altre piattaforme**: Bugcrowd, Intigriti, YesWeHack (dietro la stessa astrazione
  `collectors/base`, uno step alla volta). Raddoppia/quadruplica i programmi sorvegliati.
- **M6 — Frontend web**: dashboard leggibile sopra il database (stato/coda/findings/temperature),
  poi controllo del regime. Legge lo stesso SQLite.
- **Scalabilità multi-PC / multi-IP** (il salto grosso): coordinatore + worker che prendono job
  dalla coda condivisa (SQLite → Postgres), ogni worker con la sua IP. L'architettura è già
  pronta all'80% grazie alla coda `jobs` e alla separazione enqueue/drain. IP diverse = più
  copertura in parallelo e meno rischio di ban su una singola IP. **Attenzione**: coordinare il
  rate per-target sulla flotta.
- **Go?** No: il lavoro pesante lo fanno già i tool (subfinder/nuclei, che *sono* in Go); il
  nostro codice è solo orchestrazione I/O-bound, dove Python è perfetto. Eventuale unico uso di
  Go: un piccolo "worker agent" a binario singolo se andremo distribuiti. Ma non è una priorità.

### Altri stage di detection (futuri, come nuovi "job kind" sulla stessa spina dorsale)
Content discovery (ffuf), port scan non-web (naabu), tech-detect → check mirati, nuclei in
modalità DAST/fuzzing (XSS/SSRF/redirect sui parametri), screenshot (gowitness) per il triage
visivo. **Tutti gli stage intrusivi restano opt-in, rate-limited e rispettosi della policy del
singolo programma** (alcuni vietano l'automazione).

## 9) Glossario rapido

- **Scope / in-scope**: gli asset (domini, URL) che il programma autorizza a testare.
- **Recon passivo**: raccolta info senza "toccare" in modo intrusivo i bersagli (subfinder ecc.).
- **Scan attivo**: invio di richieste per cercare vulnerabilità (nuclei) — più aggressivo.
- **Delta / finding**: un cambiamento rilevato (nuovo sottodominio, host caduto, vulnerabilità).
- **Governor**: il "termostato" che decide quanto spingere in base a temperatura e uso del PC.
- **Coda job**: la lista di lavori da fare; rende il sistema ripartibile dopo un crash.
- **Baseline**: la prima mappatura di un programma (silenziosa, è il punto di partenza).
- **Subdomain takeover**: prendere il controllo di un sottodominio che punta a un servizio
  dismesso/non reclamato.
