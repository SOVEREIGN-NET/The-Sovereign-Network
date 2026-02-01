//! Temporary DHT stub to decouple lib-network from lib-storage.
//! TODO (relocation pass): move real DHT/backend wiring to the integration layer.

pub mod protocol;

pub use crate::dht_stub::{DHTNetworkStatus, ZkDHTIntegration, DHTClient, call_native_dht_client};
pub use lib_types::dht::{types::*, message::*, transport::*};
