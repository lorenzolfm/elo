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

/// The entry points of the fuzz targets in `fuzz/`. Only a build with `--cfg fuzzing` has this
/// module, so a normal build has no more `pub` items. The code of each entry point is in a `fuzz`
/// child of the module that it checks, as a test is, so it sees the private items of that module.
#[cfg(fuzzing)]
pub mod fuzz {
    pub use crate::net::fuzz::frame;
    pub use crate::protocol::fuzz::{headers, version};
    pub use crate::serialize::fuzz::compact_size;
}
