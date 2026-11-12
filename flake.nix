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
              # The last step runs the tests, which listen and connect on loopback. The macOS
              # sandbox blocks that without this flag.
              __darwinAllowLocalNetworking = true;
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

                # A session reads at most 4096 bytes of an input: the `-max_len` of `session.sh`.
                # The replay below reads all of a seed, so a longer seed is not what passed here.
                long_seeds="$(find fuzz/corpus -type f -size +4096c)"
                test -z "$long_seeds" || fail "these seeds are above 4096 bytes: $long_seeds"

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

                # A target has one name in its manifest entry, file, entry point and corpus.
                # A copy that keeps an old name replays a corpus through another entry point,
                # and the replay passes.
                test "$(ls fuzz/corpus | sort)" = "$(sort <<< "$targets")" \
                  || fail "the corpus directories are not the targets"
                test "$(ls fuzz/fuzz_targets | sed 's/\.rs$//' | sort)" = "$(sort <<< "$targets")" \
                  || fail "the files in fuzz_targets are not the targets"
                # `packages` also prints each `[[bin]]`: its name and its path, on one line.
                manifest="$(packages fuzz/Cargo.toml)"
                for target in $targets; do
                  grep --fixed-strings --line-regexp --quiet \
                    "name = \"$target\" path = \"fuzz_targets/$target.rs\"" <<< "$manifest" \
                    || fail "target $target does not build fuzz_targets/$target.rs"
                  grep --fixed-strings --quiet "elo::fuzz::$target(data)" "fuzz/fuzz_targets/$target.rs" \
                    || fail "fuzz_targets/$target.rs does not call elo::fuzz::$target"
                done

                for target in $targets; do
                  # `cargo fuzz run` makes a missing corpus, and an empty one passes.
                  test -n "$(ls --almost-all "fuzz/corpus/$target")" || fail "target $target has no corpus"
                  cargo fuzz run --sanitizer none "$target" -- -runs=0
                done

                # The tests of `SEED_ENDS` have `cfg(fuzzing)`, so only this gate runs them. After
                # the replay, so a machine bug has its seed as the failing input. No filter, because
                # a filter that matches no test exits 0.
                RUSTFLAGS="--cfg fuzzing" cargo test --locked --lib
              '';
              # The bytes that the replay ran, so the image holds what passed this gate.
              installPhaseCommand = ''
                mkdir --parents "$out/targets"
                cp --recursive fuzz/corpus "$out/corpus"
                for target in $(cargo fuzz list); do
                  cp fuzz/target/*/release/"$target" "$out/targets/"
                done
              '';
            });
        };

        fuzzSession = pkgs.writeShellApplication {
          name = "session";
          runtimeInputs = [pkgs.coreutils pkgs.gnugrep];
          text = builtins.readFile ./fuzz/session.sh;
        };

        # The targets and the corpus of the gate. Panic locations and line tables name each store
        # path that the build read, so without this the image holds a compiler: 150 MB, not 42 MB.
        fuzzTargets = let
          kept = [pkgs.stdenv.cc.libc.out pkgs.stdenv.cc.cc.lib];
        in
          pkgs.runCommand "elo-fuzz-targets" {
            nativeBuildInputs = [pkgs.removeReferencesTo];
            # This sees only a path that the loop below cannot find. The load check holds the rest.
            allowedReferences = kept;
          } ''
            cp --recursive --no-preserve=mode ${gates.elo-fuzz} "$out"
            chmod +x "$out"/targets/*
            for path in $(grep --binary-files=text --only-matching --no-filename --extended-regexp \
              "$NIX_STORE/[0-9a-z]{32}-[^/[:cntrl:]]*" "$out"/targets/* | sort --unique); do
              case " ${toString kept} " in
                *" $path "*) ;;
                *) remove-references-to -t "$path" "$out"/targets/* ;;
              esac
            done

            # The loop removes each path outside `kept`, and a target can need one at run time. Then
            # no reference is left to stop the build, so load each target. The last line of a target
            # that does not load is the error of the loader.
            for target in "$out"/targets/*; do
              "$target" -help=1 2>&1 | tail --lines=1
            done
            # `session.sh` names these two targets.
            test -x "$out/targets/compact_size"
            test -x "$out/targets/machines"
          '';

        # A long run on a home machine. The session holds no secret and needs no network.
        elo-fuzz-image = pkgs.dockerTools.buildLayeredImage {
          name = "elo-fuzz";
          tag = "local";
          contents = [fuzzTargets fuzzSession];
          config = {
            Entrypoint = ["${pkgs.lib.getExe fuzzSession}"];
            User = "65534:65534";
            Env = [
              "ELO_COMMIT=${inputs.self.rev or "dirty"}"
              "RUST_BACKTRACE=1"
            ];
            Labels."org.opencontainers.image.source" = "https://github.com/lorenzolfm/elo";
          };
        };

        # The daemon. The deployment gives the arguments of elo: the network and the peer. elo is
        # PID 1. The kernel gives PID 1 no default action for a signal, so elo handles SIGTERM
        # itself, and a stop ends it at once. elo starts no child process, so no init needs to
        # reap one. The image needs no volume, no port and no writable path.
        elo-image = pkgs.dockerTools.buildLayeredImage {
          name = "elo";
          tag = "local";
          config = {
            Entrypoint = ["${pkgs.lib.getExe elo}"];
            User = "65534:65534";
            Env = ["RUST_BACKTRACE=1"];
            Labels = {
              "org.opencontainers.image.source" = "https://github.com/lorenzolfm/elo";
              "org.opencontainers.image.revision" = inputs.self.rev or "dirty";
            };
          };
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
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            inherit elo-fuzz-image elo-image;
          };

        apps.default = {
          type = "app";
          program = "${pkgs.lib.getExe elo}";
          meta.description = "A Bitcoin node daemon";
        };

        devShells.default = craneLibDev.devShell {
          packages = [pkgs.cargo-nextest pkgs.cargo-fuzz pkgs.cargo-mutants];
          BITCOIND = bitcoind;
          BITCOIN_CLI = bitcoinCli;
        };

        formatter = pkgs.alejandra;
      };
    };
}
