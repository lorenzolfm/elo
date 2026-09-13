{
  description = "A Bitcoin node written in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs @ {
    flake-parts,
    nixpkgs,
    rust-overlay,
    crane,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem = {
        system,
        pkgs,
        ...
      }: let
        craneLib = (crane.mkLib pkgs).overrideToolchain (
          p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml
        );

        toolchainFile = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);

        craneLibDev = (crane.mkLib pkgs).overrideToolchain (
          p:
            (p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
              extensions = toolchainFile.toolchain.components ++ ["rust-src"];
            }
        );

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
          CARGO_PROFILE = "dev";
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        releaseArgs =
          commonArgs
          // {
            CARGO_PROFILE = "release";
          };

        elo = craneLib.buildPackage (
          releaseArgs
          // {
            cargoArtifacts = craneLib.buildDepsOnly releaseArgs;

            pname = "elo";

            doCheck = false;

            meta = {
              description = "A Bitcoin node written in Rust";
              homepage = "https://github.com/lorenzolfm/elo";
              mainProgram = "elo";
            };
          }
        );

        gates = {
          inherit elo;

          elo-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );

          elo-test = craneLib.cargoTest (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoTestExtraArgs = "--all-targets";
              nativeCheckInputs = [pkgs.bitcoind];
            }
          );

          elo-fmt = craneLib.cargoFmt {inherit src;};

          # `nix fmt .` is the fixer; this is the check. Same formatter, so
          # the two cannot disagree.
          nix-fmt =
            pkgs.runCommand "nix-fmt" {
              nativeBuildInputs = [pkgs.alejandra];
              src = pkgs.lib.fileset.toSource {
                root = ./.;
                fileset = pkgs.lib.fileset.fileFilter (file: file.hasExt "nix") ./.;
              };
            } ''
              alejandra --check "$src"
              touch "$out"
            '';
        };
      in {
        _module.args.pkgs = import nixpkgs {
          inherit system;
          overlays = [(import rust-overlay)];
        };

        checks = gates;

        packages =
          gates
          // {
            default = elo;
          };

        apps.default = {
          type = "app";
          program = "${pkgs.lib.getExe elo}";
          meta.description = elo.meta.description;
        };

        devShells.default = craneLibDev.devShell {
          packages = with pkgs; [
            bitcoind
          ];

          shellHook = ''
            echo "  $(rustc --version)"
            echo "  $(bitcoind --version | head -n1)"
          '';
        };

        formatter = pkgs.alejandra;
      };
    };
}
