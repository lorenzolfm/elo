//! elo: a Bitcoin node daemon.

#![forbid(unsafe_code)]

pub mod chainparams;
pub mod protocol;
pub mod serialize;
pub mod transport;

#[cfg(test)]
mod fixtures;
