# elo

A Bitcoin node daemon. Work in progress: the binary dials one peer, does the
v1 `version`/`verack` handshake, prints the peer's `version` and exits.

```sh
elo <mainnet|testnet4|signet|regtest> <ip>[:port]    # IPv6 as [::1]:8333
```

## Build

Nix builds everything. `flake.lock` pins nixpkgs and the other inputs, and
`rust-toolchain.toml` pins the compiler.

```sh
nix build          # the binary, at ./result/bin/elo
nix flake check    # every CI gate: build, clippy, tests, doctests, rustfmt
nix develop        # a shell with the pinned toolchain (direnv: `direnv allow`)
```

## Reproducibility

```sh
nix build .#elo .#elo.cargoArtifacts              # the package and its dependencies
nix build --rebuild .#elo .#elo.cargoArtifacts    # builds both again, and fails if the bytes differ
```

`--rebuild` compares with an earlier build, so run the first command once.

CI runs this check on every pull request.
