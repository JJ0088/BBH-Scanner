# Verifica sul campo (Acer Aspire 7, NixOS)

Runbook per la prima esecuzione reale su hardware. Valida M3 (servizio 24/7) e M4
(scan attivo) con tool, sensori e API veri. Segui i passi in ordine; se qualcosa si
rompe, **incolla l'output del comando** e ti sblocco.

> Prerequisito: flakes abilitati. Se `nix develop` dà errore di "experimental-features",
> aggiungi `--extra-experimental-features 'nix-command flakes'` ai comandi `nix`.

---

## 0) Prendi il codice

```bash
git clone https://github.com/JJ0088/BBH-Scanner   # o: cd BBH-Scanner && git fetch
cd BBH-Scanner
git checkout claude/repository-analysis-9rz3z1
git pull
```

## 1) Entra nell'ambiente

```bash
nix develop
```

Deve stampare le righe di benvenuto e mettere `subfinder/dnsx/httpx/nuclei` nel PATH.
Dentro la shell puoi usare `bbh` (alias di `python -m bbh_scanner.cli`).

- ❌ Se `nix develop` fallisce nel build → incolla l'errore (probabile fix nel `flake.nix`).
- ✅ Verifica veloce: `which subfinder httpx nuclei && python -c "import psutil, requests; print('ok')"`

## 2) Credenziali (nella stessa shell)

```bash
export HACKERONE_API_USERNAME='...'      # API token identifier
export HACKERONE_API_TOKEN='...'
export TELEGRAM_BOT_TOKEN='8759194755:...'
export TELEGRAM_CHAT_ID='7138815460'
```

## 3) Doctor — il check che dice tutto

```bash
bbh init
bbh doctor --online
```

Atteso: quasi tutto ✅.
- **sensori**: dovrebbe leggere la temp CPU reale (`k10temp`). La GPU NVIDIA può risultare
  `n/d` se la dGPU è spenta (Optimus) — è normale, conta la CPU.
- **telegram**: `--online` invia un messaggio di test → controlla il telefono.
- **hackerone**: `--online` fa una chiamata reale all'API.
- ❌ Qualsiasi ⚠️/❌ inatteso → incolla l'output di `bbh doctor --online`.

## 4) Sensori e regime

```bash
bbh sensors
```

Deve mostrare temp CPU reale e il regime deciso. Prova gli override:

```bash
bbh mode turbo   && bbh sensors    # regime: turbo
bbh mode powersave && bbh sensors  # regime: powersave
bbh mode auto                       # torna automatico
```

## 5) Sync HackerOne (API reale)

> Nota: la prima `sync` scarica l'elenco completo dei programmi pubblici (può richiedere
> uno-due minuti); `--only-handle` limita il fetch degli scope a quello.

```bash
bbh sync --only-handle <un-programma>
bbh status
```

Atteso: `programs`/`scopes` > 0 nello status. ❌ Se 401/403 → token errato; incolla l'errore.

## 6) Recon passivo reale (subfinder → dnsx → httpx)

```bash
bbh recon --limit 1
bbh jobs                 # il job deve risultare 'done'
bbh findings             # nuovi sottodomini / host vivi
bbh status
```

Qui si validano i flag e il parsing dei tool su output vero. ❌ Se un job va 'failed' →
`bbh jobs --state failed` e incolla l'errore.

## 7) Scan attivo nuclei (M4) — opt-in

```bash
export BBH_ACTIVE_SCAN=1
export BBH_NUCLEI_SEVERITY=medium,high,critical   # opzionale: salta gli info
bbh mode turbo                                     # lo scan attivo gira solo in NORMAL/TURBO
bbh scan --limit 1
bbh findings --severity medium,high,critical
```

I findings `vuln` medium+ dovrebbero arrivare anche su Telegram.

## 8) Loop 24/7 (M3) — prova funzionale

```bash
bbh run --once           # un giro completo: sync + recon + scan + notifiche
bbh run                  # loop residente; Ctrl-C → arresto pulito ("arrestato")
```

## 9) (Deploy) Servizio systemd

Nel flake/configuration.nix dell'host:

```nix
imports = [ bbh-scanner.nixosModules.default ];
services.bbh-scanner = {
  enable = true;
  environmentFile = "/run/secrets/bbh.env";   # le stesse variabili del punto 2
  settings.BBH_ACTIVE_SCAN = "1";              # se vuoi lo scan attivo
};
```

Poi `sudo nixos-rebuild switch` e `systemctl status bbh-scanner` / `journalctl -u bbh-scanner -f`.

---

## Cosa incollarmi se qualcosa non torna

- output completo del comando che fallisce;
- per il recon/scan: `bbh jobs --state failed` e il log più recente in `logs/`;
- per i sensori: `bbh sensors` e, se utile, `cat /sys/class/hwmon/hwmon*/name`.
