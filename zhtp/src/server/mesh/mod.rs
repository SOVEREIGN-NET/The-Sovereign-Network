//! Mesh Networking Module
//! 
//! Core mesh protocol handling - extracted from unified_server.rs
//! 
//! ✅ PHASE 4 COMPLETE - All Components Extracted:
//! - core.rs: ✅ Connection management, MeshRouter struct (250 lines)
//! - monitoring.rs: ✅ Performance metrics, alerts, reputation tracking (400 lines)
//! - blockchain_sync.rs: ✅ Block/transaction broadcast, sync management (350 lines)
//! - udp_handler.rs: ✅ UDP message handling - ALL message types (1,000+ lines)
//! - identity_api.rs: ✅ Identity API methods for mesh (1,400+ lines)
//! - helpers.rs: ✅ Helper methods (chunking, bridging, TCP handling) (300+ lines)
//!
//! ✅ PHASE 2 COMPLETE - Authentication Consolidation:
//! - authentication_wrapper.rs: ✅ Now uses lib-network::protocols::zhtp_auth (removed 477 lines)
//!
//! ✅ PHASE 7 COMPLETE - Routing Integration:
//! - routing_integration.rs: ✅ Multi-hop, relay, and long-range routing (+230 lines)
//!
//! Total: 3,930 lines (net: -247 lines from original 4,177)

pub mod core;
pub mod helpers;
pub mod monitoring;
pub mod blockchain_sync;
// udp_handler removed - using QUIC only
pub mod identity_api;
pub mod authentication_wrapper;
pub mod routing_integration;
pub mod rate_limiting;
pub mod identity_verification;