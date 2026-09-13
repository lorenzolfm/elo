# Roadmap

The ladder to the first main goal. One line per pull request; tick it in the
pull request that completes it.

A step is done when its box is checked and its tests pass. A *milestone* is done
when the gate passes — and the gates are deliberately external, answered by
Bitcoin Core rather than by our own assertions.

Captured Core bytes are added by the step that first needs them.

## M1 — Handshake

- [x] 1. The message envelope: network magic, 12-byte NUL-padded command, LE
      payload length, `sha256d` checksum truncated to four bytes — and the
      length bound that stops a peer from making us allocate four gigabytes.
- [x] 2. The handshake: our `version` out, the peer's `version` and `verack`
      in, our `verack` back. Proven against a spawned `bitcoind -regtest`
      that lists us in `getpeerinfo`.
- [x] 3. `ping` → `pong`. The first message we answer after the handshake.
- [ ] 4. Reading the peer's `version`: `CompactSize`, the user agent, the
      height it claims.
      Parse inside the transition, not after it: `handshake::run` moves to
      "awaiting verack" only once the payload has parsed, and the parsed
      value lives in that state, so "verack sent, version never parsed" is
      unrepresentable. `run` then returns the parsed peer instead of `()`.
      While the signature moves anyway: take the stream by value and hand it
      back on `Ok`, so "stream reused after `Err`" is unrepresentable too
      (today a doc comment holds that rule; the mock in the unit tests must
      keep its own handle on the written bytes).

**Gate:** `bitcoin-cli getpeerinfo` on the homelab node lists elo by its
subversion string.

## M2 — Headers to tip

- [ ] 5. The 80-byte block header, and `sha256d` over it. Genesis must print
      `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` while
      the bytes on the wire run the other way.
- [ ] 6. `getheaders` and `headers`, including the vestigial zero
      transaction-count byte that follows each header on the wire.
- [ ] 7. The block locator: ten recent hashes, then exponential backoff — and
      why that shape finds a fork point fast.
- [ ] 8. The in-memory chain and the sync loop, capped at a couple of batches.
      When the peer/connection struct appears, `Network` goes in it and the
      per-call argument to `message::read`/`write` goes away: one stream
      with two magics is representable today, with no writer.
- [ ] 9. Proof of work: decoding `nBits` to a 256-bit target, and the
      comparison.
- [ ] 10. Difficulty retargeting across the 2016-block boundary. The timespan
      off-by-one, and the 4× clamps.
- [ ] 11. Median time past.
- [ ] 12. The full run from genesis.

**Gate:** our tip hash equals the homelab node's `getbestblockhash`, and our
height equals its `getblockcount`.

## After

Not designed for, not planned, listed only so nobody mistakes their absence for
an oversight: block download, a block store, chainstate and the UTXO set,
script and transaction validation, reorg handling, multi-peer, DNS seeding,
mempool, RPC.
