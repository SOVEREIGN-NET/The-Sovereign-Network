//! Temporary DHT stub to decouple lib-network from lib-storage.
//! TODO (relocation pass): move real DHT/backend wiring to the integration layer.

pub use crate::dht_stub::*;
pub use lib_types::dht::*;
