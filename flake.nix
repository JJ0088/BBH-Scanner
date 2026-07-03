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

        # Tool ProjectDiscovery: recon passivo (subfinder/dnsx/httpx) + scan attivo (nuclei).
        reconTools = [ pkgs.subfinder pkgs.dnsx pkgs.httpx pkgs.nuclei ];

        bbh-scanner = python.pkgs.buildPythonApplication {
          pname = "bbh-scanner";
          version = "0.4.0";
          src = ./.;
          pyproject = true;
          build-system = [ python.pkgs.setuptools python.pkgs.wheel ];
          dependencies = [ python.pkgs.requests python.pkgs.psutil ];
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
            (python.withPackages (ps: [ ps.requests ps.psutil ps.pytest ps.ruff ps.black ]))
          ] ++ reconTools;
          shellHook = ''
            echo "BBH-Scanner dev shell — python $(python --version)"
            echo "tool: subfinder/dnsx/httpx/nuclei disponibili nel PATH"
            echo "nota: per la temperatura GPU serve 'nvidia-smi' dal driver NVIDIA"
            echo "comando: usa 'bbh <...>' (alias di 'python -m bbh_scanner.cli')"
            export BBH_ROOT="$PWD"
            alias bbh="python -m bbh_scanner.cli"
          '';
        };

        checks.default = bbh-scanner;
      }
    ) // systemIndependent;
}
