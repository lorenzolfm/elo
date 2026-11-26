#![forbid(unsafe_code)]

mod block;
pub mod chain;
pub mod chainparams;
mod headerssync;
mod http;
pub mod logging;
mod merkle;
pub mod metrics;
pub mod net;
mod net_processing;
mod pow;
mod protocol;
mod serialize;
mod transaction;
mod transport;
mod utxo;

#[cfg(test)]
mod fixtures;

#[cfg(fuzzing)]
pub mod fuzz {
    pub use crate::block::fuzz::block;
    pub use crate::net::fuzz::frame;
    pub use crate::net_processing::fuzz::machines;
    pub use crate::protocol::fuzz::{headers, version};
    pub use crate::serialize::fuzz::compact_size;
    pub use crate::utxo::fuzz::utxo;
}
