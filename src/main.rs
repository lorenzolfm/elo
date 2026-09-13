//! elo — a Bitcoin node, built one reviewable step at a time.
//!
//! Nothing runs yet. `ROADMAP.md` says what comes next.

// Read and written by the handshake in step 2; only the tests use it here.
#[allow(dead_code)]
mod message;
// Sent by the handshake; until then only the tests use it.
#[allow(dead_code)]
mod version;

fn main() {
    println!("elo {}", env!("CARGO_PKG_VERSION"));
}
