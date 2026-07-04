# NixOS config — Workstation (jj)

Configurazione NixOS + Home Manager gestita con **flakes**, versionata in git.

## Struttura attuale

| File | Cosa fa |
|------|---------|
| `flake.nix` | Punto d'ingresso: pinna nixpkgs + home-manager e definisce l'host `Workstation`. |
| `configuration.nix` | Config di sistema (boot, NVIDIA, servizi, pacchetti, utente…). |
| `home.nix` | Config utente (Hyprland, Waybar, Fish, hyprlock…). |
| `hardware-configuration.nix` | **Placeholder** — da sostituire col tuo (vedi sotto). |

## Prima messa in funzione sulla tua macchina

Questi passaggi si fanno **una volta sola**. La config si builda dal repo, non
più da `/etc/nixos`.

1. **Clona il repo** (se non ce l'hai già in `~/BBH-Scanner`):
   ```bash
   git clone <url-del-repo> ~/BBH-Scanner
   cd ~/BBH-Scanner
   git checkout claude/nixos-configuration-vgjgd3
   ```

2. **Copia il tuo hardware-configuration.nix** (specifico della macchina):
   ```bash
   cp /etc/nixos/hardware-configuration.nix ~/BBH-Scanner/nixos/
   git -C ~/BBH-Scanner add nixos/hardware-configuration.nix
   ```

3. **Copia il .deb di NordVPN** e traccialo (i flake vedono solo file in git):
   ```bash
   cp /etc/nixos/nordvpn_4.4.0_amd64.deb ~/BBH-Scanner/nixos/
   git -C ~/BBH-Scanner add -f nixos/nordvpn_4.4.0_amd64.deb
   ```

4. **Controlla il canale** che usi oggi e allinea `flake.nix` se serve:
   ```bash
   nixos-version
   ```
   Se NON sei su unstable, cambia in `flake.nix` la riga `nixpkgs.url`
   (es. `nixos-25.05`) e allinea home-manager al branch `release-25.05`.

5. **Builda** (prima prova senza attivare, poi attiva):
   ```bash
   sudo nixos-rebuild build --flake ~/BBH-Scanner/nixos#Workstation   # prova
   sudo nixos-rebuild switch --flake ~/BBH-Scanner/nixos#Workstation  # attiva
   ```
   Se qualcosa va storto, riavvii e scegli la generazione precedente al boot.

## Uso quotidiano

- Modifichi i file nel repo (`conf` / `homeconf` aprono quelli giusti).
- Applichi con `rebuild` (la funzione fish ora punta al flake).
- `git commit` = il tuo backup / punto di ripristino.
- Aggiorni i pacchetti solo quando vuoi tu: `nix flake update` poi `rebuild`.

## Prossimi passi (roadmap rice)

- [x] **Stage 1** — migrazione a flake, sistema replicato 1:1.
- [ ] **Stage 2** — pulizia (swappy/satty, doppioni, python duplicato…).
- [ ] **Stage 3** — Stylix (theming adattivo dal wallpaper).
- [ ] **Stage 4** — rice Hyprland/Waybar/Rofi ispirato a ML4W.
- [ ] **Stage 5** — modularizzazione (split in `modules/`).
