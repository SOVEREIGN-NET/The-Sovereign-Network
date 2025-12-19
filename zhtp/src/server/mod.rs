//! Server Module - Modular Server Components
//! 
//! ✅ COMPLETE REFACTORING - All components extracted from unified_server.rs
//! 
//! ## New Modular Structure:
//! 
//! ### Core Handlers (Phase 6 - NEW)
//! - `protocol_detection` - TCP/UDP protocol detection (100 lines)
//! - `tcp_handler` - TCP connection handling and routing (220 lines)
//! - `udp_handler` - UDP packet handling and mesh connections (270 lines)
//! - `api_registration` - HTTP API handler registration (180 lines)
//! 
//! ### HTTP Layer (Phase 2)
//! - `http::middleware` - CORS, rate limiting, authentication (200 lines)
//! - `http::router` - HTTP routing and protocol conversion (400 lines)
//! 
//! ### Monitoring Layer (Phase 3)
//! - `monitoring::reputation` - Peer reputation scoring (150 lines)
//! - `monitoring::metrics` - Performance metrics tracking (180 lines)
//! - `monitoring::alerts` - Alert generation and thresholds (120 lines)
//! 
//! ### Mesh Layer (Phase 4)
//! - `mesh::core` - MeshRouter struct and initialization (250 lines)
//! - `mesh::monitoring` - Performance tracking and alerting (400 lines)
//! - `mesh::blockchain_sync` - Block/transaction broadcast (350 lines)
//! - `mesh::udp_handler` - UDP message type handlers (1,000+ lines)
//! - ❌ `mesh::authentication` - Removed (477 lines) - uses lib-network::protocols::zhtp_auth
//! 
//! ### Protocol Layer (Phase 5)
//! - `protocols::wifi` - WiFi Direct P2P router (173 lines)
//! - `protocols::bluetooth_le` - BLE GATT for phones (438 lines)
//! - `protocols::bluetooth_classic` - RFCOMM high-throughput (298 lines)
//! - `protocols::bootstrap` - Service discovery (104 lines)
//! 
//! **Total Extracted: ~4,800 lines across 17 modules (Phase 2 reduced 477 lines)**

// Core handler modules (Phase 6)
pub mod protocol_detection;
// ❌ DELETED: tcp_handler.rs (220 lines) - replaced by quic_handler
// ❌ DELETED: udp_handler.rs (270 lines) - replaced by quic_handler
// ❌ DELETED: api_registration.rs - duplicate dead code (unified_server has the implementation)

// NEW: QUIC-native handler (replaces TCP/UDP) - ONLY ENTRY POINT
pub mod quic_handler;
pub mod zhtp;  // Native ZHTP protocol over QUIC

// HTTPS Gateway for browser-based Web4 access (Phase 4: TLS Strategy)
pub mod https_gateway;

// Layer modules (Phases 2-5)
pub mod http;
pub mod monitoring;
pub mod mesh;
pub mod protocols;

// Re-export for convenience
pub use protocol_detection::IncomingProtocol;
// ❌ DELETED: TcpHandler - Use QuicHandler instead
// ❌ DELETED: UdpHandler - Use QuicHandler instead
pub use quic_handler::QuicHandler;  // QUIC-native handler

// ❌ DELETED: HttpRouter - QUIC is the only entry point, HttpCompatibilityLayer converts HTTP → ZHTP
pub use http::middleware::{Middleware, CorsMiddleware, RateLimitMiddleware, AuthMiddleware};

pub use monitoring::reputation::{PeerReputation, PeerRateLimit, PeerPerformanceStats};
pub use monitoring::metrics::{SyncPerformanceMetrics, BroadcastMetrics, MetricsSnapshot, MetricsHistory};
pub use monitoring::alerts::{AlertLevel, SyncAlert, AlertThresholds};

pub use mesh::core::MeshRouter;

pub use protocols::{WiFiRouter, BluetoothRouter, BluetoothClassicRouter, ClassicProtocol};
// ❌ REMOVED: BootstrapRouter - Use lib-network::bootstrap instead

// HTTPS Gateway exports
pub use https_gateway::{HttpsGateway, GatewayTlsConfig, TlsMode};
