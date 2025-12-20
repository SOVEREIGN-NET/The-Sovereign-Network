pub mod long_range;
pub mod multi_hop;
pub mod message_routing;
pub mod global_coverage;
#[cfg(feature = "storage-integration")]
pub mod dht_router_adapter; // Ticket #154: DHT routing adapter

// Global routing and coverage functionality
