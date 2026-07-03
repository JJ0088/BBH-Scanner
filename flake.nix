{
  description = "BBH-Scanner — scanner recon 24/7 multi-piattaforma";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # Output non legati a un sistema specifico: il modulo NixOS.
      systemIndependent = {
        nixosModules.default = import ./nix/module.nix self;
        nixosModules.bbh-scanner = import ./nix/module.nix self;
      };
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python311;

        # I tool ProjectDiscovery usati dal recon passivo (in nixpkgs).
        reconTools = [ pkgs.subfinder pkgs.dnsx pkgs.httpx ];

        bbh-scanner = python.pkgs.buildPythonApplication {
          pname = "bbh-scanner";
          version = "0.4.0";
          src = ./.;
          pyproject = true;
          build-system = [ python.pkgs.setuptools python.pkgs.wheel ];
          dependencies = [ python.pkgs.requests ];
          # I tool recon devono essere nel PATH del comando `bbh`.
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postInstall = ''
            wrapProgram $out/bin/bbh \
              --prefix PATH : ${pkgs.lib.makeBinPath reconTools}
          '';
          # I test girano senza rete né tool: sicuri in sandbox.
          nativeCheckInputs = [ python.pkgs.pytest ];
          checkPhase = ''
            runHook preCheck
            ${python.pkgs.pytest}/bin/pytest -q
            runHook postCheck
          '';
        };
      in
      {
        packages = {
          default = bbh-scanner;
          bbh-scanner = bbh-scanner;

          # Immagine OCI generata dal flake (per un eventuale trasloco su VPS).
          docker = pkgs.dockerTools.buildLayeredImage {
            name = "bbh-scanner";
            tag = "latest";
            contents = [ bbh-scanner ] ++ reconTools;
            config.Entrypoint = [ "${bbh-scanner}/bin/bbh" ];
            config.Cmd = [ "run" ];
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [
            (python.withPackages (ps: [ ps.requests ps.pytest ps.ruff ps.black ]))
          ] ++ reconTools;
          shellHook = ''
            echo "BBH-Scanner dev shell — python $(python --version)"
            echo "tool: subfinder/dnsx/httpx disponibili nel PATH"
            export BBH_ROOT="$PWD"
          '';
        };

        checks.default = bbh-scanner;
      }
    ) // systemIndependent;
}
