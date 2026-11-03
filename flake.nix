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

        # The fuzz gate replays the corpus, and the filter above drops those files.
        fuzzSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            craneLib.filterCargoSources path type
            || pkgs.lib.hasInfix "/fuzz/corpus/" path;
        };

        # The L3 tests run elo against this bitcoind. They use bitcoin-cli from
        # the same package to see when it is ready and to read its peer info.
        # Its version is the one in their asserts.
        bitcoind = pkgs.lib.getExe' pkgs.bitcoind "bitcoind";
        bitcoinCli = pkgs.lib.getExe' pkgs.bitcoind "bitcoin-cli";

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
              BITCOIN_CLI = bitcoinCli;
              # The tests listen and connect on loopback. The macOS sandbox
              # blocks that without this flag.
              __darwinAllowLocalNetworking = true;
            });

          # nextest does not run doctests.
          elo-doctest = craneLib.cargoDocTest devArgs;

          elo-fmt = craneLib.cargoFmt {inherit src;};

          # Builds each fuzz target and replays its committed corpus once, so an input
          # that crashed elo cannot crash it again. CI does no random run. The compiler
          # is stable and sanitizers need nightly, so the targets have no sanitizer.
          elo-fuzz = craneLib.mkCargoDerivation (commonArgs
            // {
              src = fuzzSrc;
              pnameSuffix = "-fuzz";
              cargoArtifacts = null;
              doInstallCargoArtifacts = false;
              # `fuzz/` is its own workspace, so it has its own lockfile.
              cargoVendorDir = craneLib.vendorMultipleCargoDeps {
                cargoLockList = [./Cargo.lock ./fuzz/Cargo.lock];
              };
              nativeBuildInputs = [pkgs.cargo-fuzz];
              buildPhaseCargoCommand = ''
                # The normal gates do not see these: `fuzz/` is outside their
                # workspace, and they build without `--cfg fuzzing`. Clippy checks
                # only the workspace it runs in, so it runs in both.
                cargo fmt --manifest-path fuzz/Cargo.toml --check
                RUSTFLAGS="--cfg fuzzing" cargo clippy --locked --all-targets -- --deny warnings
                RUSTFLAGS="--cfg fuzzing" cargo clippy --manifest-path fuzz/Cargo.toml \
                  --locked -- --deny warnings

                # The log shows only the `cargo` commands, so a `test` that fails must say
                # why. Without this, the log ends on the last `cargo` command, which passed.
                fail() { echo "elo-fuzz: $1" >&2; exit 1; }

                # The committed corpus is at most 1 MiB, so a clone stays small.
                corpus_size="$(du --summarize --bytes fuzz/corpus | cut --fields=1)"
                test "$corpus_size" -le 1048576 || fail "the corpus is $corpus_size bytes, above 1 MiB"

                # The targets build elo with the versions that elo ships. `--locked` checks
                # each lockfile alone, so it does not see an update of only one. With no
                # packages in the list, the comparison passes.
                packages() { sed --quiet '/^name = /{N;s/\n/ /;p}' "$1" | sort; }
                test -n "$(packages Cargo.lock)" || fail "found no packages in Cargo.lock"
                comm -23 <(packages Cargo.lock) <(packages fuzz/Cargo.lock) | tee only-in-root
                test ! -s only-in-root || fail "fuzz/Cargo.lock does not have the packages above"

                # With no targets, the loop runs zero times and the gate passes.
                targets="$(cargo fuzz list)"
                test -n "$targets" || fail "found no fuzz targets"
                for target in $targets; do
                  # `cargo fuzz run` makes a missing corpus, and an empty one passes.
                  test -n "$(ls --almost-all "fuzz/corpus/$target")" || fail "target $target has no corpus"
                  cargo fuzz run --sanitizer none "$target" -- -runs=0
                done
              '';
            });
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
          packages = [pkgs.cargo-nextest pkgs.cargo-fuzz];
          BITCOIND = bitcoind;
          BITCOIN_CLI = bitcoinCli;
        };

        formatter = pkgs.alejandra;
      };
    };
}
