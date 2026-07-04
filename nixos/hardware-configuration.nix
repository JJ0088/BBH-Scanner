# ============================================================================
# PLACEHOLDER — questo NON è il tuo vero hardware-configuration.nix
# ----------------------------------------------------------------------------
# hardware-configuration.nix è specifico della TUA macchina (dischi,
# filesystem, moduli del kernel) e viene generato da NixOS all'installazione.
# NON va scritto a mano.
#
# Sostituisci questo file col tuo, copiandolo dalla tua macchina:
#
#     cp /etc/nixos/hardware-configuration.nix ~/BBH-Scanner/nixos/
#     git -C ~/BBH-Scanner add nixos/hardware-configuration.nix
#
# Finché non lo fai, il build si ferma qui con il messaggio sotto (di proposito,
# così non rischi di buildare con un hardware sbagliato).
# ============================================================================
throw ''

  [BBH-Scanner/nixos] hardware-configuration.nix è ancora il PLACEHOLDER.
  Copia il tuo file reale prima di buildare:

      cp /etc/nixos/hardware-configuration.nix ~/BBH-Scanner/nixos/
      git -C ~/BBH-Scanner add nixos/hardware-configuration.nix
''
