# --- NIXOS CONFIGURATION ---
{ config, pkgs, ... }:

{
  # home-manager NON è più importato qui via canale: lo carica il flake.nix.
  imports = [ ./hardware-configuration.nix ];

# ==========================================
# 1. CORE SYSTEM
# ==========================================

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  networking = {
    hostName = "Workstation";
    networkmanager.enable = true;
    nameservers = [ "1.1.1.1" "9.9.9.9" ];
    firewall = { enable = true; allowPing = false; checkReversePath = "loose"; };
  };
  hardware.bluetooth.enable = true;
  services.blueman.enable = true;

  time.timeZone = "Europe/Berlin";
  console.keyMap = "it2";
  i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" "it_IT.UTF-8/UTF-8" ];  # nuovissimo

# ==========================================
# 2. HARDWARE & NVIDIA
# ==========================================

  hardware.graphics.enable = true;
  services.xserver.videoDrivers = [ "nvidia" ];

  hardware.nvidia = {
    modesetting.enable = true;
    powerManagement.enable = true;
    open = false;
    nvidiaSettings = true;
    package = config.boot.kernelPackages.nvidiaPackages.stable;

    prime = {
      offload.enable = true;
      offload.enableOffloadCmd = true;
      amdgpuBusId = "PCI:5:0:0";
      nvidiaBusId = "PCI:1:0:0";
    };
  };

# ==========================================
# 3. DESKTOP & LOGIN
# ==========================================

  services.xserver.enable = true;
  services.xserver.xkb = { layout = "it"; variant = ""; };
  fonts.fontDir.enable = true;

  services.displayManager.sddm = {
    enable = true;
    wayland.enable = true;
    package = pkgs.kdePackages.sddm;
    theme = "sddm-astronaut-theme";

    # I pacchetti SDDM vanno SOLO qui, non in systemPackages
    extraPackages = with pkgs; [
      sddm-astronaut
      kdePackages.qtmultimedia
      kdePackages.qtsvg
      kdePackages.qtvirtualkeyboard
    ];

    settings = {
      Theme = {
        Current = "sddm-astronaut-theme";
        CursorTheme = "Bibata-Modern-Ice";
        Font = "JetBrainsMono Nerd Font";
      };
    };
  };

  programs.hyprland = {
    enable = true;
    xwayland.enable = true;
  };

  environment.sessionVariables = {
    LIBVA_DRIVER_NAME = "nvidia";
    XDG_SESSION_TYPE = "wayland";
    GBM_BACKEND = "nvidia-drm";
    __GLX_VENDOR_LIBRARY_NAME = "nvidia";
    WLR_NO_HARDWARE_CURSORS = "1";
    NIXOS_OZONE_WL = "1";
  };

# ==========================================
# 4. SERVICES & FIXES
# ==========================================

  security.rtkit.enable = true;
  security.pam.services.hyprlock = {};
  security.pam.services.sddm.enableGnomeKeyring = true;

  virtualisation.docker.enable = true;
  # NOTA: virtualisation.docker.enable aggiunge già il CLI di docker al PATH.
  # Non serve aggiungere "docker" a systemPackages.

  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
  };
  services.pulseaudio.enable = false;

  services.gnome.gnome-keyring.enable = true;
  services.power-profiles-daemon.enable = true;
  services.resolved.enable = true;
  services.udisks2.enable = true;
  services.gvfs.enable = true;

  # XDG Desktop Portal — necessario per:
  #   • Dolphin "Apri con..." su Wayland (mostra le app disponibili)
  #   • Dialog file open/save nelle app GTK/Electron
  #   • Screen sharing (OBS, browser, ecc.)
  # Cosa impari: senza portal, le app Wayland non sanno come chiedere al
  # compositor di mostrare un file chooser o un app picker.
  xdg.portal = {
    enable = true;
    xdgOpenUsePortal = true;  # forza xdg-open a usare il portal
    extraPortals = with pkgs; [
      xdg-desktop-portal-hyprland  # screen share, screenshot portal
      xdg-desktop-portal-gtk       # file chooser e app picker (GTK)
    ];
  };

  boot.supportedFilesystems = [ "ntfs" "exfat" ];

  # ADB: dalla versione con systemd 258, le udev rules sono gestite
  # automaticamente dal sistema. Basta avere android-tools in systemPackages.

# ==========================================
# NORDVPN: FIX DIPENDENZE "FANTASMA" (4.4.0)
# ==========================================

  nixpkgs.overlays = [
    (self: super: {
      nordvpn = super.stdenv.mkDerivation {
        pname = "nordvpn";
        version = "4.4.0";
        # Path relativo al flake: metti il .deb in ~/BBH-Scanner/nixos/ e
        # traccialo in git (i flake "puri" vedono solo i file versionati):
        #   git -C ~/BBH-Scanner add -f nixos/nordvpn_4.4.0_amd64.deb
        src = ./nordvpn_4.4.0_amd64.deb;

        nativeBuildInputs = [
          pkgs.dpkg
          pkgs.makeWrapper
          pkgs.autoPatchelfHook
          pkgs.iptables
        ];

        buildInputs = [
          pkgs.glibc
          pkgs.libidn2
          pkgs.libxml2
          pkgs.zlib
          pkgs.libuuid
          pkgs.sqlite
          super.stdenv.cc.cc.lib
        ];

        unpackPhase = "dpkg-deb -x $src .";

        installPhase = ''
          mkdir -p $out/bin $out/share $out/lib

          [ -d usr/bin ]   && cp -r usr/bin/*   $out/bin/
          [ -d usr/sbin ]  && cp -r usr/sbin/*  $out/bin/
          [ -d usr/share ] && cp -r usr/share/* $out/share/

          find . -name "*.so*" -exec cp -t $out/lib/ {} +

          wrapProgram $out/bin/nordvpn  --prefix PATH : ${super.lib.makeBinPath [ super.iproute2 super.procps pkgs.iptables ]}
          wrapProgram $out/bin/nordvpnd --prefix PATH : ${super.lib.makeBinPath [ super.iproute2 super.procps pkgs.iptables ]}
        '';
      };
    })
  ];

  systemd.services.nordvpnd = {
    description = "NordVPN Daemon";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.nordvpn}/bin/nordvpnd";
      Restart = "always";
      RuntimeDirectory = "nordvpn";
      RuntimeDirectoryMode = "0770";
      Group = "nordvpn";
      UMask = "0007";
    };
  };

  nixpkgs.config.allowUnfree = true;

# ==========================================
# 5. USER & SHELL
# ==========================================

  programs.fish.enable = true;
  environment.shells = with pkgs; [ fish ];

  users.users.jj = {
    isNormalUser = true;
    # "adbusers" non serve più, systemd 258 gestisce le regole udev da solo
    extraGroups = [ "networkmanager" "wheel" "video" "nordvpn" "docker" "dialout" ];
    shell = pkgs.fish;
  };

  users.groups.nordvpn = {};

  programs.nix-ld.enable = true;
  programs.nix-ld.libraries = with pkgs; [
    stdenv.cc.cc.lib
    zlib
  ];
  services.flatpak.enable = true;

# ==========================================
# 6. PACKAGES
# ==========================================

  environment.systemPackages = with pkgs; [
    # Core
    firefox kitty git vim wget curl networkmanagerapplet
    kdePackages.dolphin dunst swww waypaper rofi pipx
    code-cursor flatpak

    # VPN & Rete
    nordvpn openvpn wireguard-tools wireguard-ui
    tor-browser mullvad-vpn dnsutils whois

    # Sicurezza / Pentest
    nmap masscan subfinder nuclei katana httpx tcpdump
    burpsuite ffuf gobuster ghidra-bin ltrace strace
    responder  evil-winrm
    hashcat john seclists sqlmap s3scanner
    thc-hydra frida-tools apktool jadx
    exploitdb joomscan
    gef gdb

    # Android
    android-tools android-studio genymotion

    # Dev
    go gopls delve nodejs_24 yarn gcc gnumake cmake
    openssl git glow kotlin
    (python3.withPackages (ps: with ps; [
      pandas requests pwntools scapy impacket pycryptodome aiohttp
    ]))

    # Media & Video
    obs-studio avidemux davinci-resolve shotcut mpv
    gst_all_1.gstreamer gst_all_1.gst-plugins-base
    gst_all_1.gst-plugins-good gst_all_1.gst-plugins-bad
    gst_all_1.gst-plugins-ugly gst_all_1.gst-libav
    imagemagick

    # Screenshot: satty (moderno, sostituisce swappy)
    satty

    # Desktop & UI
    waypaper nwg-look nwg-dock-hyprland wlogout
    blueman pavucontrol alsa-lib alsa-utils
    kdePackages.gwenview  # image viewer (integrato con Dolphin)

    # Storage
    usbutils udiskie ntfs3g exfat brightnessctl

    # Tools vari
    monero-gui qtox signal-desktop libreoffice
    kicad obsidian scanmem assaultcube
    file unzip htop btop fastfetch libnotify

    # Arduino / AVR
    avrdude arduino
    pkgsCross.avr.buildPackages.gcc
    pkgsCross.avr.libc

    # Samba
    samba

    # Wallust
    wallust

    # Fonts
    nerd-fonts.jetbrains-mono
    nerd-fonts.symbols-only
    ubuntu-classic
  ];

  programs.neovim = {
    enable = true;
    defaultEditor = true;
    viAlias = true;
    vimAlias = true;
    withNodeJs = true;
    withPython3 = true;
  };

# ==========================================
# 7. HOME MANAGER
# ==========================================

  home-manager.backupFileExtension = "backup";
  home-manager.users.jj = import ./home.nix;

  system.stateVersion = "24.11";
}
