//! Protocol constants for lib-network
//!
//! This module defines shared protocol constants used across the network layer.

// =============================================================================
// ALPN Protocol Identifiers
// =============================================================================
//
// ALPN (Application-Layer Protocol Negotiation) is used to select the protocol
// mode at connection time. This allows the server to handle different client
// types appropriately:
//
// - zhtp-uhp/1: Control plane with UHP handshake (CLI, Web4 deploy, admin)
// - zhtp-http/1: HTTP-only mode (mobile apps, browsers)
// - zhtp-mesh/1: Mesh peer-to-peer protocol
//
// Security: ALPN selection determines the initial protocol flow, but actual
// security comes from UHP authentication for control plane operations.

/// ALPN for control plane connections (CLI, Web4 deploy, admin APIs)
/// These connections perform UHP handshake FIRST, then send authenticated requests.
pub const ALPN_CONTROL_PLANE: &[u8] = b"zhtp-uhp/1";

/// ALPN for HTTP-compatible connections (mobile apps, browsers)
/// These connections send HTTP requests directly without UHP handshake.
/// Mutations require session tokens or other auth mechanisms.
pub const ALPN_HTTP_COMPAT: &[u8] = b"zhtp-http/1";

/// ALPN for mesh peer-to-peer connections (node-to-node)
/// These connections perform UHP handshake for peer authentication.
pub const ALPN_MESH: &[u8] = b"zhtp-mesh/1";

/// Legacy ALPN for backward compatibility
/// Treated as HTTP-compat mode for mobile app compatibility.
pub const ALPN_LEGACY: &[u8] = b"zhtp/1.0";

/// HTTP/3 ALPN for browser compatibility
pub const ALPN_H3: &[u8] = b"h3";

/// All supported server ALPNs (ordered by preference)
pub fn server_alpns() -> Vec<Vec<u8>> {
    vec![
        ALPN_CONTROL_PLANE.to_vec(),  // Preferred: control plane with UHP
        ALPN_MESH.to_vec(),            // Mesh protocol
        ALPN_HTTP_COMPAT.to_vec(),     // HTTP-compat mode
        ALPN_LEGACY.to_vec(),          // Legacy (treated as HTTP-compat)
        ALPN_H3.to_vec(),              // HTTP/3 browsers
    ]
}

/// Client ALPNs for control plane operations (CLI, Web4 deploy)
pub fn client_control_plane_alpns() -> Vec<Vec<u8>> {
    vec![
        ALPN_CONTROL_PLANE.to_vec(),   // Primary: control plane with UHP
    ]
}

/// Client ALPNs for HTTP-only operations (mobile apps)
pub fn client_http_alpns() -> Vec<Vec<u8>> {
    vec![
        ALPN_HTTP_COMPAT.to_vec(),     // HTTP-compat mode
        ALPN_LEGACY.to_vec(),          // Legacy fallback
        ALPN_H3.to_vec(),              // HTTP/3 fallback
    ]
}

// =============================================================================
// Handshake Constants
// =============================================================================

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
