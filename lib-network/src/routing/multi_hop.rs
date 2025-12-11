//! Multi-Hop Routing - **TICKET #153 MIGRATION**
//!
//! This 934-line module has been **ELIMINATED** and replaced with unified_router.rs.
//!
//! **Migration Path**:
//! ```rust
//! // OLD (REMOVED):
//! // use crate::routing::multi_hop::MultiHopRouter;
//!
//! // NEW:
//! use crate::routing::unified_router::UnifiedRouter;
//! ```
//!
//! All graph pathfinding functionality is now in UnifiedRouter which combines:
//! - Kademlia DHT routing
//! - Mesh topology routing
//! - Graph-based pathfinding (this module's original functionality)

// Re-export unified router
pub use super::unified_router::*;
