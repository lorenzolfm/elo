{
  description = "elo: a Bitcoin node daemon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
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
        "aarch64-darwin"
      ];

      perSystem = {
        system,
        pkgs,
        ...
      }: let
        craneLib =
          (crane.mkLib pkgs).overrideToolchain (p:
            p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml);

        # The gates build with the toolchain file as it is written: minimal. The
        # dev shell adds rust-src on top, because rust-analyzer reads the
        # documentation of the standard library from those sources. No gate
        # needs the sources, so they stay out of the build closure.
        #
        # `override` replaces the component list, it does not add to it. Read
        # the list from the toolchain file, so the dev shell keeps clippy,
        # rustfmt and rust-analyzer.
        toolchainFile = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);

        craneLibDev = (crane.mkLib pkgs).overrideToolchain (p:
          (p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
            extensions = toolchainFile.toolchain.components ++ ["rust-src"];
          });

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
        };

        # The L3 tests run the handshake against this bitcoind. Its version is
        # the one in their asserts.
        bitcoind = pkgs.lib.getExe' pkgs.bitcoind "bitcoind";

        # Build only the dependencies, so a change to the crate's own code does
        # not build them again.
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # The test gates run in the dev profile, as `cargo test` does in the
        # dev shell. The release profile turns off overflow checks and
        # `debug_assert!`. The dev profile needs its own build of the
        # dependencies.
        devArgs =
          commonArgs
          // {
            CARGO_PROFILE = "dev";
            cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {CARGO_PROFILE = "dev";});
          };

        elo = craneLib.buildPackage (commonArgs
          // {
            inherit cargoArtifacts;

            # The test gate runs the tests. Do not run them two times.
            doCheck = false;

            meta = {
              description = "A Bitcoin node daemon";
              homepage = "https://github.com/lorenzolfm/elo";
              mainProgram = "elo";
              platforms = pkgs.lib.platforms.unix;
            };
          });

        # One derivation for each gate. CI builds them in parallel, and
        # `nix flake check` runs all of them.
        gates = {
          inherit elo;

          elo-clippy = craneLib.cargoClippy (commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            });

          elo-test = craneLib.cargoNextest (devArgs
            // {
              BITCOIND = bitcoind;
              # The tests listen and connect on loopback. The macOS sandbox
              # blocks that without this flag.
              __darwinAllowLocalNetworking = true;
            });

          # nextest does not run doctests.
          elo-doctest = craneLib.cargoDocTest devArgs;

          elo-fmt = craneLib.cargoFmt {inherit src;};
        };
      in {
        _module.args.pkgs = import nixpkgs {
          inherit system;
          overlays = [(import rust-overlay)];
        };

        checks = gates;

        # Give each gate a package name, so CI can build one gate with
        # `nix build .#<gate>`.
        packages =
          gates
          // {
            default = elo;
          };

        apps.default = {
          type = "app";
          program = "${pkgs.lib.getExe elo}";
          meta.description = "A Bitcoin node daemon";
        };

        devShells.default = craneLibDev.devShell {
          packages = [pkgs.cargo-nextest];
          BITCOIND = bitcoind;
        };

        formatter = pkgs.alejandra;
      };
    };
}
