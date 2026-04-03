#[cfg(feature = "storage-integration")]
pub mod dht_router_adapter;
pub mod global_coverage;
pub mod long_range;
pub mod message_routing;
pub mod multi_hop; // Ticket #154: DHT routing adapter

// Global routing and coverage functionality
