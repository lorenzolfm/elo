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

        fuzzSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            craneLib.filterCargoSources path type
            || pkgs.lib.hasInfix "/fuzz/corpus/" path;
        };

        bitcoind = pkgs.lib.getExe' pkgs.bitcoind "bitcoind";
        bitcoinCli = pkgs.lib.getExe' pkgs.bitcoind "bitcoin-cli";

        comments = ./.config/ast-grep/comments;
        runBlock = {
          kind = "block_node";
          inside = {
            kind = "block_mapping_pair";
            has = {
              field = "key";
              regex = "^run$";
            };
          };
        };
        commentsConfig = pkgs.writeText "comments.json" (builtins.toJSON {
          ruleDirs = ["${comments}/rules"];
          testConfigs = [{testDir = "${comments}/rule-tests";}];
          customLanguages.toml = {
            libraryPath = "${pkgs.tree-sitter-grammars.tree-sitter-toml}/parser";
            extensions = ["toml"];
          };
          languageGlobs.bash = [".envrc" ".gitignore"];
          languageInjections = [
            {
              hostLanguage = "nix";
              rule = {
                kind = "indented_string_expression";
                pattern = "$CONTENT";
              };
              injected = "bash";
            }
            {
              hostLanguage = "yaml";
              rule = {
                kind = "block_scalar";
                pattern = "$CONTENT";
                inside = runBlock;
              };
              injected = "bash";
            }
          ];
        });

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        devArgs =
          commonArgs
          // {
            CARGO_PROFILE = "dev";
            cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {CARGO_PROFILE = "dev";});
          };

        elo = craneLib.buildPackage (commonArgs
          // {
            inherit cargoArtifacts;

            doCheck = false;

            meta = {
              description = "A Bitcoin node daemon";
              homepage = "https://github.com/lorenzolfm/elo";
              mainProgram = "elo";
              platforms = pkgs.lib.platforms.unix;
            };
          });

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
              __darwinAllowLocalNetworking = true;
            });

          elo-fmt = craneLib.cargoFmt {inherit src;};

          elo-comments =
            pkgs.runCommand "elo-comments" {
              nativeBuildInputs = [pkgs.ast-grep];
            } ''
              cd ${./.}
              mapfile -d "" tree < <(find . -type f -print0)
              wait $!
              (( ''${#tree[@]} > 0 ))
              ast-grep test --config ${commentsConfig} --custom-languages allow
              ast-grep scan --config ${commentsConfig} --custom-languages allow -- "''${tree[@]}"
              touch "$out"
            '';

          elo-fuzz = craneLib.mkCargoDerivation (commonArgs
            // {
              src = fuzzSrc;
              pnameSuffix = "-fuzz";
              cargoArtifacts = null;
              doInstallCargoArtifacts = false;
              cargoVendorDir = craneLib.vendorMultipleCargoDeps {
                cargoLockList = [./Cargo.lock ./fuzz/Cargo.lock];
              };
              nativeBuildInputs = [pkgs.cargo-fuzz];
              __darwinAllowLocalNetworking = true;
              buildPhaseCargoCommand = ''
                cargo fmt --manifest-path fuzz/Cargo.toml --check
                RUSTFLAGS="--cfg fuzzing" cargo clippy --locked --all-targets -- --deny warnings
                RUSTFLAGS="--cfg fuzzing" cargo clippy --manifest-path fuzz/Cargo.toml \
                  --locked -- --deny warnings

                fail() { echo "elo-fuzz: $1" >&2; exit 1; }

                corpus_size="$(du --summarize --bytes fuzz/corpus | cut --fields=1)"
                test "$corpus_size" -le 1048576 || fail "the corpus is $corpus_size bytes, above 1 MiB"

                long_seeds="$(find fuzz/corpus -type f -size +4096c)"
                test -z "$long_seeds" || fail "these seeds are above 4096 bytes: $long_seeds"

                packages() { sed --quiet '/^name = /{N;s/\n/ /;p}' "$1" | sort; }
                test -n "$(packages Cargo.lock)" || fail "found no packages in Cargo.lock"
                comm -23 <(packages Cargo.lock) <(packages fuzz/Cargo.lock) | tee only-in-root
                test ! -s only-in-root || fail "fuzz/Cargo.lock does not have the packages above"

                targets="$(cargo fuzz list)"
                test -n "$targets" || fail "found no fuzz targets"

                test "$(ls fuzz/corpus | sort)" = "$(sort <<< "$targets")" \
                  || fail "the corpus directories are not the targets"
                test "$(ls fuzz/fuzz_targets | sed 's/\.rs$//' | sort)" = "$(sort <<< "$targets")" \
                  || fail "the files in fuzz_targets are not the targets"
                manifest="$(packages fuzz/Cargo.toml)"
                for target in $targets; do
                  grep --fixed-strings --line-regexp --quiet \
                    "name = \"$target\" path = \"fuzz_targets/$target.rs\"" <<< "$manifest" \
                    || fail "target $target does not build fuzz_targets/$target.rs"
                  grep --fixed-strings --quiet "elo::fuzz::$target(data)" "fuzz/fuzz_targets/$target.rs" \
                    || fail "fuzz_targets/$target.rs does not call elo::fuzz::$target"
                done

                for target in $targets; do
                  test -n "$(ls --almost-all "fuzz/corpus/$target")" || fail "target $target has no corpus"
                  cargo fuzz run --sanitizer none "$target" -- -runs=0
                done

                RUSTFLAGS="--cfg fuzzing" cargo test --locked --lib
              '';
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

        fuzzTargets = let
          kept = [pkgs.stdenv.cc.libc.out pkgs.stdenv.cc.cc.lib];
        in
          pkgs.runCommand "elo-fuzz-targets" {
            nativeBuildInputs = [pkgs.removeReferencesTo];
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

            for target in "$out"/targets/*; do
              "$target" -help=1 2>&1 | tail --lines=1
            done
            test -x "$out/targets/compact_size"
            test -x "$out/targets/machines"
          '';

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
