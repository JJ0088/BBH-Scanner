# Modulo NixOS per far girare BBH-Scanner come servizio 24/7 con limiti di risorsa.
#
# Uso (in configuration.nix / flake dell'host):
#   imports = [ bbh-scanner.nixosModules.default ];
#   services.bbh-scanner = {
#     enable = true;
#     environmentFile = "/run/secrets/bbh.env";  # HACKERONE_* e TELEGRAM_* qui
#     settings = {
#       BBH_SYNC_INTERVAL = "21600";
#       # Governor termico/adattivo (default tarati per Ryzen 7 5700U + RTX 3050):
#       BBH_CPU_HOT = "82"; BBH_CPU_CRITICAL = "90";
#       BBH_GPU_HOT = "85"; BBH_GPU_CRITICAL = "92";
#       BBH_TURBO_CONC = "4"; BBH_PS_CONC = "1";
#     };
#     resources = { cpuQuota = "600%"; memoryMax = "2G"; };
#   };
#
# Nota: il CPUQuota di systemd è un tetto RIGIDO di sicurezza. La regolazione fine
# (turbo/normal/powersave/pausa in base a temperatura e attività utente) la fa il
# governor applicativo, quindi qui basta un tetto generoso per il turbo.
self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.bbh-scanner;
  pkg = self.packages.${pkgs.system}.default;
in
{
  options.services.bbh-scanner = {
    enable = lib.mkEnableOption "BBH-Scanner recon 24/7";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkg;
      description = "Il pacchetto bbh-scanner da eseguire.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "bbh";
      description = "Utente di sistema che esegue il servizio.";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/bbh-scanner";
      description = "Directory di stato (DB, log, output recon).";
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File con le variabili segrete (HACKERONE_API_USERNAME/TOKEN,
        TELEGRAM_BOT_TOKEN/CHAT_ID). NON metterle nel Nix store.
      '';
    };

    settings = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Variabili d'ambiente non segrete (BBH_*).";
    };

    resources = {
      cpuQuota = lib.mkOption {
        type = lib.types.str;
        default = "600%";
        description = ''
          CPUQuota systemd: tetto RIGIDO di sicurezza (es. '600%' = 6 core su 8).
          La regolazione dinamica la fa il governor applicativo; qui serve solo un
          tetto generoso per la modalità turbo.
        '';
      };
      memoryMax = lib.mkOption {
        type = lib.types.str;
        default = "2G";
        description = "Tetto rigido di memoria (MemoryMax). 16 GB totali sull'Acer.";
      };
      memoryHigh = lib.mkOption {
        type = lib.types.str;
        default = "1500M";
        description = "Soglia morbida di memoria (MemoryHigh).";
      };
    };

    tickSeconds = lib.mkOption {
      type = lib.types.int;
      default = 60;
      description = "Secondi tra un tick e l'altro dell'orchestratore.";
    };

    watchdogSec = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = ''
        Se >0 abilita il watchdog systemd (Type=notify + WatchdogSec). Il daemon manda
        READY all'avvio e WATCHDOG dopo ogni tick. IMPORTANTE: dev'essere più grande del
        tick più lungo (un recon può durare minuti), altrimenti systemd riavvia il servizio.
        Default 0 = disabilitato (consigliato finché non hai misurato le durate reali).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
      home = cfg.dataDir;
      createHome = true;
    };
    users.groups.${cfg.user} = { };

    # `bbh-ctl <cmd>`: esegue bbh come utente del servizio, sul DB del servizio.
    # Così `bbh-ctl status|jobs|findings|mode turbo|sensors` parlano col 24/7 residente.
    environment.systemPackages = [
      (pkgs.writeShellScriptBin "bbh-ctl" ''
        exec sudo -u ${cfg.user} \
          env BBH_ROOT=${cfg.dataDir} \
              BBH_DATA_DIR=${cfg.dataDir}/data \
              BBH_LOGS_DIR=${cfg.dataDir}/logs \
          ${cfg.package}/bin/bbh "$@"
      '')
    ];

    systemd.services.bbh-scanner = {
      description = "BBH-Scanner recon 24/7";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        BBH_ROOT = cfg.dataDir;
        BBH_DATA_DIR = "${cfg.dataDir}/data";
        BBH_LOGS_DIR = "${cfg.dataDir}/logs";
      } // cfg.settings;

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.user;
        WorkingDirectory = cfg.dataDir;
        ExecStartPre = "${cfg.package}/bin/bbh init";
        ExecStart = "${cfg.package}/bin/bbh run --tick ${toString cfg.tickSeconds}";
        Restart = "on-failure";
        RestartSec = 30;

        # --- Governance risorse (vincolo hardware Acer) ---
        Nice = 10;
        IOSchedulingClass = "idle";
        CPUQuota = cfg.resources.cpuQuota;
        MemoryHigh = cfg.resources.memoryHigh;
        MemoryMax = cfg.resources.memoryMax;

        # --- Hardening ---
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        StateDirectory = "bbh-scanner";
        ReadWritePaths = [ cfg.dataDir ];
      } // lib.optionalAttrs (cfg.environmentFile != null) {
        EnvironmentFile = cfg.environmentFile;
      } // lib.optionalAttrs (cfg.watchdogSec > 0) {
        Type = "notify";
        NotifyAccess = "main";
        WatchdogSec = toString cfg.watchdogSec;
      };
    };
  };
}
