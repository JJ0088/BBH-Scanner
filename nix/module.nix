# Modulo NixOS per far girare BBH-Scanner come servizio 24/7 con limiti di risorsa.
#
# Uso (in configuration.nix / flake dell'host):
#   imports = [ bbh-scanner.nixosModules.default ];
#   services.bbh-scanner = {
#     enable = true;
#     environmentFile = "/run/secrets/bbh.env";  # HACKERONE_* e TELEGRAM_* qui
#     settings = {
#       BBH_MAX_CONCURRENCY = "2";
#       BBH_SYNC_INTERVAL = "21600";
#     };
#     resources = { cpuQuota = "150%"; memoryMax = "1500M"; };
#   };
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
        default = "150%";
        description = "CPUQuota systemd (es. '150%' = 1.5 core su un Acer quad-core).";
      };
      memoryMax = lib.mkOption {
        type = lib.types.str;
        default = "1500M";
        description = "Tetto rigido di memoria (MemoryMax).";
      };
      memoryHigh = lib.mkOption {
        type = lib.types.str;
        default = "1200M";
        description = "Soglia morbida di memoria (MemoryHigh).";
      };
    };

    tickSeconds = lib.mkOption {
      type = lib.types.int;
      default = 60;
      description = "Secondi tra un tick e l'altro dell'orchestratore.";
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
      };
    };
  };
}
