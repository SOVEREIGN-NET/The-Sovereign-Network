//! Server Module - Modular Server Components
//!
//! # QUIC-Only Architecture
//!
//! All entry points use QUIC (UDP port 9334). TCP, UDP, and HTTP are not supported as ingress.
//!
//! ## Module Structure
//!
//! ### Entry Point (NEW)
//! - `quic_handler` - QUIC connection acceptance and multiplexing
//! - `zhtp` - Native ZHTP protocol implementation
//!
//! ### HTTP Layer
//! - `http::middleware` - CORS, rate limiting, authentication (retained for internal use)
//! - `http::router` - HTTP routing (retained for backward compatibility)
//!
//! ### Monitoring Layer
//! - `monitoring::reputation` - Peer reputation scoring
//! - `monitoring::metrics` - Performance metrics tracking
//! - `monitoring::alerts` - Alert generation and thresholds
//!
//! ### Mesh Layer
//! - `mesh::core` - MeshRouter for peer management and routing
//! - `mesh::routing_errors` - Structured error classification
//! - `mesh::blockchain_sync` - Block/transaction broadcast
//! - `mesh::routing_integration` - Route message through identity verification
//!
//! ### Discovery Protocols
//! - `protocols::wifi` - WiFi Direct discovery
//! - `protocols::bluetooth_le` - BLE GATT peer discovery
//! - `protocols::bluetooth_classic` - Classic Bluetooth discovery
//!
//! ### HTTPS Gateway
//! - `https_gateway` - Browser-based Web4 access (TLS 1.3)

// Core entry point modules
pub mod protocol_detection;
pub mod quic_handler;
pub mod zhtp;

// HTTPS Gateway for browser-based Web4 access
pub mod https_gateway;

// Layer modules
pub mod http;
pub mod mesh;
pub mod monitoring;
pub mod protocols;

// Re-export for convenience
pub use http::middleware::{AuthMiddleware, CorsMiddleware, Middleware, RateLimitMiddleware};
pub use mesh::core::MeshRouter;
pub use monitoring::alerts::{AlertLevel, AlertThresholds, SyncAlert};
pub use monitoring::metrics::{
    BroadcastMetrics, MetricsHistory, MetricsSnapshot, SyncPerformanceMetrics,
};
pub use monitoring::reputation::{PeerPerformanceStats, PeerRateLimit, PeerReputation};
pub use protocol_detection::IncomingProtocol;
pub use protocols::{BluetoothClassicRouter, BluetoothRouter, ClassicProtocol, WiFiRouter};
pub use quic_handler::QuicHandler;

// HTTPS Gateway exports
pub use https_gateway::{GatewayTlsConfig, HttpsGateway, TlsMode};
