# --- home.nix (Home Manager per l'utente jj) ---
# Gestito nel repo BBH-Scanner/nixos e caricato dal flake.
{ config, pkgs, ... }:

{


  home.username = "jj";
  home.homeDirectory = "/home/jj";

  # Versione della tua Home (non cambiarla)
  home.stateVersion = "24.11";

  # ==========================================
  # PACCHETTI UTENTE (ARREDAMENTO)
  # ==========================================
  home.packages = with pkgs; [
    grim           # Scatta
    slurp          # Seleziona
    swappy         # Edita
    wl-clipboard   # Copia
    libnotify      # Notifiche

     (python3.withPackages (ps: with ps; [
    pandas requests pwntools scapy impacket pycryptodome aiohttp
  ]))


  ];




  # 1. PROGRAMMI DA TERMINALE
  programs.eza = { enable = true; icons = "auto"; git = true; };
  programs.bat.enable = true;
  programs.zoxide = { enable = true; enableFishIntegration = true; };
  programs.fzf = { enable = true; enableFishIntegration = true; };

  # 2. LA TUA SHELL (Fish)
  programs.fish = {
      enable = true;
      interactiveShellInit = "set fish_greeting;";

      shellAliases = {
        webots = "flatpak run com.cyberbotics.webots & disown";
      	bbh = "~/BBH-Scanner/scripts/bbh";
        ls = "eza --icons";
        #rebuild = "sudo nixos-rebuild switch";
        conf = "nvim ~/BBH-Scanner/nixos/configuration.nix";
        homeconf = "nvim ~/BBH-Scanner/nixos/home.nix";
    };

    functions = {
      rebuild = ''
        # La config ora vive nel repo git (~/BBH-Scanner/nixos) ed è gestita
        # coi flake. Git è la tua cronologia/backup: se vuoi un punto di
        # ripristino, committa prima di ribuildare.
        set flake_dir "$HOME/BBH-Scanner/nixos"

        echo " Rebuild dal flake in $flake_dir ..."
        sudo nixos-rebuild switch --flake "$flake_dir#Workstation"
      '';
      # PERSONALIZZAZIONE PROMPT


    };
  };




  # 3. WAYBAR E HYPRLAND
  # (Taglia e incolla qui TUTTO il tuo blocco programs.waybar = { ... }; )
  programs.waybar = {
      enable = true;
      systemd.enable = true;
      settings = {
        mainBar = {
          layer = "top";
          position = "top"; height = 36; spacing = 4;
          margin-top = 5; margin-left = 10; margin-right = 10;

          modules-left = [ "hyprland/workspaces" ];
          modules-center = [ "clock" "custom/publicip" ];
          modules-right = [ "temperature" "custom/nordvpn" "network" "pulseaudio" "battery" "power-profiles-daemon" "custom/power" ];

          "power-profiles-daemon" = {
            format = "{icon}";
            tooltip-format = "Profilo: {profile}\nDriver: {driver}";
            tooltip = true;
            format-icons = {
              default = "";
              performance = "";
              balanced = "";
              power-saver = "";
            };
          };
          # --- CONFIGURAZIONE MODULI ---
          "hyprland/workspaces" = {
             format = "{name}";
             on-click = "activate";
             persistent-workspaces = { "*" = 5; };
          };

          "custom/launcher-term" = { format = ""; on-click = "kitty"; tooltip = "Terminale"; };
          "custom/launcher-web" = { format = ""; on-click = "firefox"; tooltip = "Web"; };
          "custom/launcher-files" = { format = ""; on-click = "dolphin"; tooltip = "Dolphin"; };

          "clock" = {
            format = " {:%H:%M  |   %d %b}";
            tooltip-format = "<tt><small>{calendar}</small></tt>";
          };

          "custom/publicip" = {
            format = " {}";
            interval = 3600;
            exec = "curl -s https://api.ipify.org";
            exec-if = "ping -c 1 8.8.8.8";
            on-click = "curl -s https://api.ipify.org";
            tooltip = false;
          };

          "temperature" = {
            critical-threshold = 80;
            format = "{icon} {temperatureC}°C";
            format-icons = ["" "" ""];
            tooltip = false;
          };

          "custom/nordvpn" = {
            exec = "vpn-status"; return-type = "json";
            interval = 5; format = "{}";
            on-click = "kitty --hold sh -c 'nordvpn connect'";
            on-click-right = "kitty --hold sh -c 'nordvpn disconnect'";
          };

          "network" = {
            # Punto 4: IP locale a sinistra del WiFi
            format-wifi = "{ipaddr} ";
            format-ethernet = "{ipaddr} ";
            format-disconnected = " Disconnected";
            tooltip-format = "{ifname} via {gwaddr}";
            tooltip-format-wifi = "{essid} ({signalStrength}%)";
            on-click = "kitty --hold sh -c 'nmtui'";
          };

          "pulseaudio" = {
            # Mostra Icona + Percentuale
            format = "{icon} {volume}%";

            # Formato speciale quando è mutato
            format-muted = " Muted";

            # Icone per i vari livelli (Basso, Medio, Alto)
            format-icons = { default = ["" "" ""]; };

            # Apre il mixer audio al click
            on-click = "pavucontrol";

            # Scroll per alzare/abbassare il volume
            scroll-step = 5;

            tooltip = false;
          };
          "battery" = {
            # Punto 2: Percentuale e Fulmine
            states = {
                critical = 10;
                warning = 30;
                medium = 50;
                good = 75;
            };
            format = "{icon} {capacity}%";
            format-charging = " {capacity}%"; # Fulmine quando carica
            format-plugged = " {capacity}%";
            format-icons = ["" "" "" "" ""];
            tooltip-format = "{timeTo}";
          };

          "custom/power" = {
            format = "";
            on-click = "sh $HOME/.config/rofi/powermenu/type-1/powermenu.sh";
            tooltip = false;
          };
        };
      };

      style = ''



        * { border: none; border-radius: 0; font-family: "JetBrainsMono Nerd Font";
            font-weight: bold; font-size: 14px; min-height: 0; }

        window#waybar { background: transparent; color: #ffffff; }

        /* CONTENITORI UNIFICATI */
        .modules-left, .modules-center, .modules-right {
            background: #1e1e1e;
            border: 1px solid #333333;
            border-radius: 12px;
            padding: 4px 10px;
            margin-top: 6px;
            opacity: 0.95;
        }

         /* PROFILI ENERGETICI */
        #power-profiles-daemon {
            padding: 0 10px;
            margin-right: 15px;
            border-radius: 8px;
            color: #ffffff;
        }

        /* Colori per ogni modalità */
        #power-profiles-daemon.performance {
            background-color: #ff0000; /* Turbo: Rosso */
            color: #ffffff;
        }

        #power-profiles-daemon.balanced {
            background-color: #2980b9; /* Normal: Blu */
            color: #ffffff;
        }

        #power-profiles-daemon.power-saver {
            background-color: #2ecc71; /* Eco: Verde */
            color: #ffffff;
        }

        /* Volume Normale */
        #pulseaudio {
            padding: 0 10px;
            color: #dddddd; /* Colore standard */
            margin-right: 5px;
        }

        /* Volume Mutato (Rosso Allarme) */
        #pulseaudio.muted {
            color: #ff0000;
            background-color: #2a0000; /* Sfondo scuro rossiccio opzionale */
            border-radius: 8px;
            padding: 0 15px;
        }

        #workspaces button { padding: 0 5px; color: #888888; }
        #workspaces button.active { color: #ff4400; }

        #custom-launcher-term, #custom-launcher-web, #custom-launcher-files {
            color: #ff4400; margin-left: 10px; font-size: 16px;
        }
        #custom-launcher-term:hover, #custom-launcher-web:hover, #custom-launcher-files:hover { color: white; }

        #clock { color: #ffffff; margin-right: 15px; }
        #custom-publicip { color: #00ff00; margin-left: 10px; }

        #temperature, #network, #pulseaudio, #custom-nordvpn { padding: 0 10px; color: #dddddd; }

        /* BATTERIA (Colori Dinamici richiesti) */
        #battery { padding: 0 10px; margin-right: 15px; color: #00ff00; } /* > 75% Verde Brillante (Default) */

        #battery.good { color: #99ff99; }      /* 50-75% Verde Chiaro */
        #battery.medium { color: #ffff00; }    /* 30-50% Giallo */
        #battery.warning { color: #ffaa00; }   /* 10-30% Arancione */
        #battery.critical { color: #ff0000; animation: blink 1s infinite; } /* < 10% Rosso */

        #battery.charging { color: #00ff00; } /* Quando carica sempre verde brillante o bianco se preferisci */

        @keyframes blink { to { color: #ffffff; } }

        #custom-power { background: #b30000; color: white; padding: 0 15px; margin-left: 5px; border-radius: 8px; }

        #custom-nordvpn.connected { color: #00ff00; }
        #custom-nordvpn.disconnected {
            color: #ffffff; background-color: #ff0000;
            padding: 0 15px; border-radius: 8px;
            animation: blinker 1s linear infinite;
        }
        @keyframes blinker { 50% { opacity: 0.3; } }
      '';
    };


    # ==========================================
  # HYPRLOCK (Schermata di sblocco)
  # ==========================================
  programs.hyprlock = {
    enable = true;
    settings = {
      general = {
        disable_loading_bar = true;
        hide_cursor = true;
        grace = 0;
      };

      # 1. LO SFONDO
      background = [
        {
          monitor = "";
          path = "/home/jj/Pictures/Wallpapers/black_and_white.png";
          blur_passes = 0; # Teniamo l'immagine nitida come volevi
        }
      ];

      # 2. TESTI (Solidi e leggibili con ombra di contrasto)
      label = [
        {
          # OROLOGIO GIGANTE
          monitor = "";
          text = "$TIME";

          # Testo bianco quasi solido
          color = "rgba(255, 255, 255, 0.95)";

          # Ombra nera marcata per far leggere il testo anche sulla neve
          shadow_passes = 3;
          shadow_size = 4;
          shadow_color = "rgba(0, 0, 0, 1.0)";

          font_size = 120;
          font_family = "JetBrainsMono Nerd Font Extrabold";
          position = "0, 150";
          halign = "center";
          valign = "center";
        }
        {
          # DATA
          monitor = "";
          text = "cmd[update:43200000] date +\"%A, %d %B %Y\"";
          color = "rgba(255, 255, 255, 0.95)";
          shadow_passes = 3;
          shadow_size = 3;
          shadow_color = "rgba(0, 0, 0, 1.0)";
          font_size = 22;
          font_family = "JetBrainsMono Nerd Font Bold";
          position = "0, 30";
          halign = "center";
          valign = "center";
        }
        {
          # SALUTO UTENTE (Senza razzo!)
          monitor = "";
          text = "Bentornato, $USER";
          color = "rgba(255, 255, 255, 0.95)";
          shadow_passes = 3;
          shadow_size = 3;
          shadow_color = "rgba(0, 0, 0, 1.0)";
          font_size = 18;
          font_family = "JetBrainsMono Nerd Font Bold";
          position = "0, -20";
          halign = "center";
          valign = "center";
        }
      ];

      # 3. BOX DELLA PASSWORD (Sfondo scuro per contrastare la neve)
      input-field = [
        {
          monitor = "";
          size = "300, 60";
          outline_thickness = 2;
          dots_size = 0.2;
          dots_spacing = 0.2;
          dots_center = true;

          # Box scuro e semi-trasparente, così la password bianca si legge benissimo
          outer_color = "rgba(0, 0, 0, 0.8)";
          inner_color = "rgba(0, 0, 0, 0.4)";
          font_color = "rgb(255, 255, 255)";
          check_color = "rgba(255, 68, 0, 0.8)"; # Il tuo arancione quando carica
          fail_color = "rgba(255, 0, 0, 0.8)";

          fade_on_empty = false;
          placeholder_text = "<i>Password...</i>";
          hide_input = false;

          position = "0, -120";
          halign = "center";
          valign = "center";
        }
      ];
    };
  };
  # ==========================================
  # HYPRIDLE (Gestione Sospensione/Coperchio)
  # ==========================================
  services.hypridle = {
    enable = true;
    settings = {
      general = {
        lock_cmd = "pidof hyprlock || hyprlock";
        before_sleep_cmd = "loginctl lock-session"; # Blocca SEMPRE prima di dormire
        after_sleep_cmd = "hyprctl dispatch dpms on"; # Riaccende lo schermo al risveglio
      };
      listener = [
        {
          timeout = 300; # 5 minuti di inattività -> Blocca lo schermo
          on-timeout = "loginctl lock-session";
        }
        {
          timeout = 330; # 5.5 minuti -> Spegne lo schermo (risparmio batteria)
          on-timeout = "hyprctl dispatch dpms off";
          on-resume = "hyprctl dispatch dpms on";
        }
        {
          timeout = 1800; # 30 minuti -> Mette il PC in Stop
          on-timeout = "systemctl suspend";
        }
      ];
    };
  };

  # ==========================================
  # CONFIGURAZIONE SWAPPY (SCREENSHOT)
  # ==========================================
  xdg.configFile."swappy/config".text = ''
    [Default]
    save_dir=/home/jj/Pictures/Screenshots
    save_filename_format=screenshot-%Y%m%d-%H%M%S.png
    show_panel=false
    line_size=5
    text_size=20
    text_font=sans-serif
    paint_mode=brush
    early_exit=true
    fill_shape=false
  '';

  # --- HYPRLAND CONFIG (Clean) ---
    wayland.windowManager.hyprland = {
      enable = true;
      extraConfig = ''
        # --- AVVIO SFONDO & BARRA ---
        # swww-daemon parte in background, poi imposta l'immagine
        exec-once = swww-daemon & sleep 1 && swww img /home/jj/Pictures/Wallpapers/black_and_white.png
        exec-once = nm-applet --indicator
        exec-once = dunst
	      exec-once = udiskie &

        # --- MONITOR ---
        monitor=,preferred,auto,1

	      # --- TASTI MULTIMEDIALI E LUMINOSITÀ ---
        # Volume (usa wpctl che è integrato in Pipewire)
        bindel = , XF86AudioRaiseVolume, exec, wpctl set-volume -l 1.5 @DEFAULT_AUDIO_SINK@ 5%+
        bindel = , XF86AudioLowerVolume, exec, wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-
        bindl = , XF86AudioMute, exec, wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle
        bindl = , XF86AudioMicMute, exec, wpctl set-mute @DEFAULT_AUDIO_SOURCE@ toggle

        # Luminosità (serve il pacchetto brightnessctl)
        bindel = , XF86MonBrightnessUp, exec, brightnessctl s 10%+
        bindel = , XF86MonBrightnessDown, exec, brightnessctl s 10%-

        # Player Musicale (Play/Pause/Next)
        bindl = , XF86AudioPlay, exec, playerctl play-pause
        bindl = , XF86AudioNext, exec, playerctl next
        bindl = , XF86AudioPrev, exec, playerctl previous

        # --- INPUT (Sintassi corretta) ---
        input {
            kb_layout = it
            follow_mouse = 1
            touchpad {
                natural_scroll = true
            }
        }

        # --- DECORAZIONI (NUOVA SINTASSI v0.45+) ---
        decoration {
            rounding = 25

            # Le ombre ora hanno il loro blocco dedicato (non più drop_shadow)
            shadow {
                enabled = true
                range = 20
                render_power = 3
                color = rgba(00000044)
            }

            blur {
                enabled = true
                size = 0

                passes = 0
            }
        }

        # --- GENERALE ---
        general {
            gaps_in = 5
            gaps_out = 10
            border_size = 2
            col.active_border = rgba(eeeeeeee) rgba(ccccccee) 45deg
            col.inactive_border = rgba(595959aa)
            layout = dwindle
        }

        # --- OPZIONI INPUT (Aggiunto per Punto 7) ---
        binds {
            # Questo abilita il "back and forth".
            # Se sei sul workspace 2 e premi Super+2, torni a quello precedente.
            workspace_back_and_forth = true
        }

        # --- DWINDLE (FIX TOGGLESPLIT) ---
        dwindle {
            pseudotile = true
            preserve_split = true # <--- FONDAMENTALE PER FAR FUNZIONARE IL TOGGLESPLIT
        }

        # --- ANIMAZIONI ---
        animations {
            enabled = yes
            bezier = myBezier, 0.05, 0.9, 0.1, 1.05
            animation = windows, 1, 7, myBezier
            animation = windowsOut, 1, 7, default, popin 80%
            animation = border, 1, 10, default
            animation = fade, 1, 7, default
            animation = workspaces, 1, 6, default
        }

        # --- TASTI (FULL CONFIG) ---
        $mainMod = SUPER

        # Applicazioni
        bind = $mainMod, Q, exec, kitty
        bind = $mainMod, B, exec, firefox
        bind = $mainMod, E, exec, dolphin
        bind = $mainMod, SPACE, exec, sh $HOME/.config/rofi/launchers/type-6/launcher.sh

        # Gestione Finestre
        bind = $mainMod, C, killactive,
        bind = $mainMod, M, exit,
        bind = $mainMod, F, fullscreen
        bind = $mainMod, T, togglefloating

	      bind = $mainMod, P, pseudo, # dwindle
        bind = $mainMod, J, togglesplit, # dwindle (cambia split orizzontale/verticale)
      	bind = $mainMod, S, swapnext
      	bind = $mainMod, L, exec, loginctl lock-session

      	# SUPER + SHIFT + S -> Seleziona area -> Apre Editor (Swappy)
        bind = SUPER SHIFT, S, exec, grim -g "$(slurp)" - | swappy -f -

	      # --- ALT TAB (Scorrimento finestre) ---
        bind = ALT, Tab, cyclenext,          # Passa alla successiva
        bind = ALT, Tab, bringactivetotop,   # Porta in primo piano quella selezionata

        # Focus (Frecce)
        bind = $mainMod, left, movefocus, l
        bind = $mainMod, right, movefocus, r
        bind = $mainMod, up, movefocus, u
        bind = $mainMod, down, movefocus, d

        # SPOSTARE FINESTRE (Shift + Frecce)
        bind = $mainMod SHIFT, left, movewindow, l
        bind = $mainMod SHIFT, right, movewindow, r
        bind = $mainMod SHIFT, up, movewindow, u
        bind = $mainMod SHIFT, down, movewindow, d

        # RESIZE FINESTRE (Alt + Frecce)
        binde = $mainMod ALT, right, resizeactive, 10 0
        binde = $mainMod ALT, left, resizeactive, -10 0
        binde = $mainMod ALT, up, resizeactive, 0 -10
        binde = $mainMod ALT, down, resizeactive, 0 10

        # Workspace (1-5)
        bind = $mainMod, 1, workspace, 1
        bind = $mainMod, 2, workspace, 2
        bind = $mainMod, 3, workspace, 3
        bind = $mainMod, 4, workspace, 4
        bind = $mainMod, 5, workspace, 5

        # Sposta finestra nel Workspace (Shift + 1-5)
        bind = $mainMod SHIFT, 1, movetoworkspace, 1
        bind = $mainMod SHIFT, 2, movetoworkspace, 2
        bind = $mainMod SHIFT, 3, movetoworkspace, 3
        bind = $mainMod SHIFT, 4, movetoworkspace, 4
        bind = $mainMod SHIFT, 5, movetoworkspace, 5

        # Mouse
        bindm = $mainMod, mouse:272, movewindow
        bindm = $mainMod, mouse:273, resizewindow
	    '';
    };
}
