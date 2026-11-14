#![forbid(unsafe_code)]

mod block;
pub mod chain;
pub mod chainparams;
mod headerssync;
pub mod logging;
pub mod net;
mod net_processing;
mod pow;
mod protocol;
mod serialize;
mod transport;

#[cfg(test)]
mod fixtures;

#[cfg(fuzzing)]
pub mod fuzz {
    pub use crate::net::fuzz::frame;
    pub use crate::net_processing::fuzz::machines;
    pub use crate::protocol::fuzz::{headers, version};
    pub use crate::serialize::fuzz::compact_size;
}
