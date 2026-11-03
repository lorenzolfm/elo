//! elo: a Bitcoin node daemon.

#![forbid(unsafe_code)]

mod block;
mod chain;
pub mod chainparams;
pub mod net;
mod net_processing;
mod protocol;
mod serialize;
mod transport;

#[cfg(test)]
mod fixtures;
