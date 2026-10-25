//! elo: a Bitcoin node daemon.

#![forbid(unsafe_code)]

mod chainparams;
mod protocol;
mod serialize;
mod transport;

#[cfg(test)]
mod fixtures;
