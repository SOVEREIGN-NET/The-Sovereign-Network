//! Protocol Routers Module
//! 
//! Multi-protocol networking layer - extracted from unified_server.rs
//! 
//! ✅ PHASE 5 COMPLETE - All Protocol Routers Extracted:
//! - wifi.rs: ✅ WiFi Direct P2P router with mDNS discovery (173 lines)
//! - bluetooth_le.rs: ✅ BLE GATT mesh for phone connectivity (438 lines)
//! - bluetooth_classic.rs: ✅ RFCOMM high-throughput mesh (298 lines)
//! - bootstrap.rs: ✅ Service discovery and capability announcement (104 lines)
//!
//! Total: 1,013 lines extracted from 1,250-line protocol layer (81%)
//!
//! ## Protocol Comparison
//!
//! | Protocol           | Bandwidth  | Latency | Range  | Use Case                      |
//! |--------------------|------------|---------|--------|-------------------------------|
//! | WiFi Direct        | 25 Mbps    | 10ms    | 200m   | P2P mesh, mDNS discovery      |
//! | Bluetooth LE       | 250 KB/s   | 100ms   | 100m   | Phone sync, edge nodes        |
//! | Bluetooth Classic  | 375 KB/s   | 50ms    | 100m   | High-throughput mobile        |
//! | UDP Mesh           | 100 Mbps   | 5ms     | LAN    | Primary mesh protocol         |
//! | QUIC Mesh          | 100 Mbps   | 10ms    | WAN    | NAT traversal, encryption     |

pub mod wifi;
pub mod bluetooth_le;
pub mod bluetooth_classic;
// ❌ REMOVED: pub mod bootstrap; - Use lib-network::bootstrap instead

pub use wifi::WiFiRouter;
pub use bluetooth_le::BluetoothRouter;
pub use bluetooth_classic::{BluetoothClassicRouter, ClassicProtocol};
// ❌ REMOVED: pub use bootstrap::BootstrapRouter; - Use lib-network::bootstrap instead
