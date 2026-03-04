//! DHT integration compatibility surface for lib-network.
//! TODO (relocation pass): complete backend wiring in integration layer.

pub mod protocol;
pub mod integration;

pub use integration::*;
pub use lib_types::dht::*;
