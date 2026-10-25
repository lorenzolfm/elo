# elo

A Bitcoin node daemon. Work in progress: the binary does nothing yet.

## Build

Nix builds everything. `flake.lock` pins nixpkgs and the other inputs, and
`rust-toolchain.toml` pins the compiler.

```sh
nix build          # the binary, at ./result/bin/elo
nix flake check    # every CI gate: build, clippy, tests, rustfmt
nix develop        # a shell with the pinned toolchain (direnv: `direnv allow`)
```

## Reproducibility

```sh
nix build --rebuild    # builds again, and fails if the output bytes differ
```

CI runs this check on every pull request.
