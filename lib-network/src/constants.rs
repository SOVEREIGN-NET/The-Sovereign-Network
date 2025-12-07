//! Protocol constants for lib-network
//!
//! This module defines shared protocol constants used across the network layer.

/// Maximum handshake message size (1 MB)
///
/// This provides sufficient space for:
/// - Identity metadata: ~2-5 KB typical
/// - Large capabilities: ~100 KB
/// - Extensive custom fields: up to 1 MB
///
/// While preventing DoS attacks via memory exhaustion.
///
/// # Security (P1-2 FIX)
/// Consistent limit enforced across all UHP implementations:
/// - `lib-network/src/bootstrap/handshake.rs` - TCP bootstrap adapter
/// - `lib-network/src/handshake/core.rs` - Core UHP implementation
///
/// Previously bootstrap used 10 MB (too large, DoS risk) while core used 1 MB.
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
