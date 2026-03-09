//! DHT integration compatibility surface for lib-network.
//! TODO (relocation pass): complete backend wiring in integration layer.

pub mod integration;
pub mod protocol;

pub use integration::*;
pub use lib_types::dht::*;
