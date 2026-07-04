{
  description = "NixOS + Home Manager — Workstation (jj)";

  # ==========================================================================
  # INPUTS = gli "ingredienti" con versione bloccata (vedi flake.lock).
  # Niente cambia sotto i piedi finché non lanci tu:  nix flake update
  # ==========================================================================
  inputs = {
    # NOTA IMPORTANTE:
    # Questa riga assume che il tuo sistema segua il canale "unstable"
    # (lo suggeriscono pacchetti come nodejs_24, code-cursor, ecc.).
    # Controlla con:  nixos-version
    # Se invece sei su un canale stabile, cambia in es.:
    #   nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    # e allinea home-manager al branch corrispondente (release-25.05).
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  # ==========================================================================
  # OUTPUTS = cosa produce il flake. Qui: la configurazione di "Workstation".
  # Si builda con:  sudo nixos-rebuild switch --flake .#Workstation
  # ==========================================================================
  outputs = { self, nixpkgs, home-manager, ... }@inputs: {
    nixosConfigurations."Workstation" = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = { inherit inputs; };

      modules = [
        # La tua configurazione di sistema (invariata).
        ./configuration.nix

        # Home Manager come modulo NixOS (sostituisce <home-manager/nixos>).
        home-manager.nixosModules.home-manager
        {
          # Home Manager usa lo STESSO pkgs del sistema (stessi overlay,
          # stesso allowUnfree). Mantiene il comportamento attuale 1:1.
          home-manager.useGlobalPkgs = true;
          home-manager.extraSpecialArgs = { inherit inputs; };
          # home-manager.users.jj e backupFileExtension restano definiti
          # dentro configuration.nix, esattamente come prima.
        }
      ];
    };
  };
}
