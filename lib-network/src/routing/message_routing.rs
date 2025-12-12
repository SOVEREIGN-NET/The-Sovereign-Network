//! Mesh Message Routing - **TICKET #153 MIGRATION**
//!
//! This 1,099-line module has been **ELIMINATED** and replaced with unified_router.rs.
//!
//! **Migration Path**:
//! ```rust
//! // OLD (REMOVED):
//! // use crate::routing::message_routing::MeshMessageRouter;
//!
//! // NEW:
//! use crate::routing::unified_router::UnifiedRouter;
//! ```
//!
//! All mesh routing functionality is now in UnifiedRouter which combines:
//! - Kademlia DHT routing
//! - Mesh topology routing (this module's original functionality)
//! - Graph-based pathfinding

// Re-export unified router
pub use super::unified_router::*;

/// **DEPRECATED:** Type alias for backward compatibility
///
/// **TICKET #153**: MeshMessageRouter has been replaced by UnifiedRouter.
/// This alias exists only for migration purposes and will be removed in v0.3.0.
#[deprecated(since = "0.2.0", note = "Use UnifiedRouter instead")]
pub type MeshMessageRouter = UnifiedRouter;
