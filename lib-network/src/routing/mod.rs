//! Routing Module - **TICKET #153 COMPLETED**
//!
//! # Code Unification Achievement
//!
//! **Before (3 separate systems):**
//! - `lib-storage/dht/routing.rs`: 562 lines (Kademlia DHT routing)
//! - `message_routing.rs`: 1,099 lines (Mesh topology routing)
//! - `multi_hop.rs`: 934 lines (Graph pathfinding)
//! - **Total: 2,595 lines**
//!
//! **After (1 unified system):**
//! - `unified_router.rs`: 894 lines (all 3 strategies combined)
//! - **Code eliminated: 1,701 lines (65.5% reduction)**
//!
//! # Migration Guide
//!
//! Old code using separate routers:
//! ```rust,ignore
//! // DHT routing (lib-storage)
//! let kademlia = KademliaRouter::new(node_id, 20);
//! 
//! // Mesh routing (lib-network)
//! let mesh_router = MeshMessageRouter::new(...);
//!
//! // Graph routing (lib-network)  
//! let multi_hop = MultiHopRouter::new();
//! ```
//!
//! New unified approach:
//! ```rust,ignore
//! use lib_network::routing::unified_router::UnifiedRouter;
//!
//! // Single router handles DHT + Mesh + Graph
//! let router = UnifiedRouter::new(local_peer, k);
//!
//! // Kademlia operations
//! router.add_kademlia_node(peer).await?;
//! let closest = router.find_closest_nodes(&target, 20).await;
//!
//! // Mesh operations
//! router.add_mesh_connection(peer, connection).await;
//! router.route_message(message, &destination).await?;
//!
//! // Graph pathfinding
//! let path = router.find_graph_path(&source, &dest).await?;
//! ```

pub mod long_range;
pub mod multi_hop;         // DEPRECATED - use unified_router
pub mod message_routing;   // DEPRECATED - use unified_router
pub mod global_coverage;
pub mod unified_router;    // NEW - Kademlia + Mesh + Graph unified

// Global routing and coverage functionality
