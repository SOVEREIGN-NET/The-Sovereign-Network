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

/// ALPN for control plane connections v1 (CLI, Web4 deploy, admin APIs)
/// These connections perform UHP handshake FIRST, then send authenticated requests.
pub const ALPN_CONTROL_PLANE: &[u8] = b"zhtp-uhp/1";

/// ALPN for control plane connections v2 (CLI, mobile apps with v2 key schedule)
/// These connections perform UHP v2 handshake with:
/// - Explicit handshake_hash for key derivation
/// - HKDF labels: zhtp/v2/app_key_c2s, zhtp/v2/mac_key, etc.
/// - MAC format: HMAC-SHA3-256(mac_key, canonical_request || counter || session_id)
pub const ALPN_CONTROL_PLANE_V2: &[u8] = b"zhtp-uhp/2";

/// ALPN for public read-only connections (mobile apps, browsers reading public content)
/// These connections do NOT perform UHP handshake.
/// Only allows: domain resolution, manifest fetch, content/blob retrieval.
/// Rejects: deploy, domain registration, admin operations, any mutations.
pub const ALPN_PUBLIC: &[u8] = b"zhtp-public/1";

/// ALPN for HTTP-compatible connections (legacy mobile apps, browsers)
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
        ALPN_CONTROL_PLANE_V2.to_vec(), // Control plane v2 (preferred for new clients)
        ALPN_PUBLIC.to_vec(),           // Public read-only (mobile apps, browsers)
        ALPN_CONTROL_PLANE.to_vec(),    // Control plane v1 (CLI, deploy)
        ALPN_MESH.to_vec(),             // Mesh protocol
        ALPN_HTTP_COMPAT.to_vec(),      // HTTP-compat mode (legacy)
        ALPN_LEGACY.to_vec(),           // Legacy (treated as HTTP-compat)
        ALPN_H3.to_vec(),               // HTTP/3 browsers
    ]
}

/// Client ALPNs for control plane operations (CLI, Web4 deploy)
pub fn client_control_plane_alpns() -> Vec<Vec<u8>> {
    vec![
        ALPN_CONTROL_PLANE.to_vec(),   // Primary: control plane with UHP v1
    ]
}

/// Client ALPNs for control plane v2 operations (mobile apps with v2 key schedule)
pub fn client_control_plane_v2_alpns() -> Vec<Vec<u8>> {
    vec![
        ALPN_CONTROL_PLANE_V2.to_vec(), // Control plane v2 with HKDF-SHA3-256
    ]
}

/// Client ALPNs for public read-only operations (mobile apps reading content)
pub fn client_public_alpns() -> Vec<Vec<u8>> {
    vec![
        ALPN_PUBLIC.to_vec(),          // Public read-only (preferred)
    ]
}

/// Client ALPNs for HTTP-only operations (legacy mobile apps)
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

// =============================================================================
// Bluetooth LE Constants
// =============================================================================

/// BLE mesh service UUID (ZHTP mesh service).
pub const BLE_MESH_SERVICE_UUID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430ca";

/// BLE ZK authentication characteristic UUID.
pub const BLE_ZK_AUTH_CHAR_UUID: &str = "6ba7b811-9dad-11d1-80b4-00c04fd430ca";

/// BLE quantum routing characteristic UUID.
pub const BLE_QUANTUM_ROUTING_CHAR_UUID: &str = "6ba7b812-9dad-11d1-80b4-00c04fd430ca";

/// BLE mesh data characteristic UUID.
pub const BLE_MESH_DATA_CHAR_UUID: &str = "6ba7b813-9dad-11d1-80b4-00c04fd430ca";

/// BLE mesh coordination characteristic UUID.
pub const BLE_MESH_COORD_CHAR_UUID: &str = "6ba7b814-9dad-11d1-80b4-00c04fd430ca";
