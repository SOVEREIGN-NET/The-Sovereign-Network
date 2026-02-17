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

// =============================================================================
// INVARIANT: Transport Protocol Defaults (closes #982)
// =============================================================================
//
// These constants define the mandatory transport and encryption baseline for all
// ZHTP peer-to-peer connections. They are treated as invariants: no code path
// is permitted to negotiate weaker settings.
//
// Enforcement points:
//   - `lib-network/src/transport/mod.rs` - TransportManager::send() blocks TCP/UDP downgrade
//   - `lib-network/src/protocols/quic_encryption.rs` - Application-level AEAD on top of TLS 1.3
//   - `lib-network/src/handshake/security.rs` - Handshake security policy
//
// # Why QUIC?
//
// QUIC provides:
//   - TLS 1.3 as a mandatory, non-negotiable transport layer
//   - 0-RTT connection establishment to reduce latency (0-RTT data is replayable;
//     replay protection must be enforced at the application layer or limited to
//     idempotent operations)
//   - Built-in stream multiplexing (no head-of-line blocking)
//   - Connection migration support for mobile nodes
//   - Reduced handshake latency compared to TCP+TLS
//
// # Why TLS 1.3 minimum?
//
// TLS 1.2 and below contain known weaknesses (BEAST, POODLE, CRIME, etc.).
// TLS 1.3 removes all legacy cipher suites and mandates forward secrecy.
// QUIC embeds TLS 1.3 as its handshake layer; this constant documents that
// no TLS 1.2 or below downgrade will ever be accepted.
//
// # Why these cipher suites?
//
// All three suites provide:
//   - AEAD construction (authenticated encryption with associated data)
//   - 128-bit or higher security level
//   - Forward secrecy (ephemeral key exchange)
//   - Hardware acceleration on modern CPUs (AES-GCM) or software efficiency
//     on constrained devices (ChaCha20-Poly1305)
//
// Additional application-level encryption (ChaCha20Poly1305) is layered on
// top of QUIC/TLS by `QuicApplicationEncryption` for defence-in-depth.

/// The mandatory transport protocol for consensus-critical ZHTP node-to-node connections.
///
/// # Invariant
///
/// All consensus-relevant peer channels (consensus traffic, block propagation,
/// authenticated control-plane peer links) MUST use QUIC. Mesh overlays MAY
/// use additional bearer technologies for opportunistic or non-consensus links.
/// TCP and UDP are blocked as downgrade paths by `TransportManager::send()`. Any
/// attempt to negotiate TCP or UDP as a consensus peer transport is rejected with
/// an error.
pub const TRANSPORT_PROTOCOL: &str = "QUIC";

/// Minimum acceptable TLS version for the QUIC transport layer.
///
/// # Invariant
///
/// QUIC mandates TLS 1.3 per RFC 9001. This constant makes that requirement
/// explicit and machine-checkable. `validate_network_config()` asserts that no
/// configuration can lower this floor.
///
/// TLS 1.3 removes:
///   - RSA key exchange (replaced by ephemeral ECDH/X25519)
///   - CBC-mode cipher suites (padding oracle attacks)
///   - SHA-1 and MD5 in the handshake
///   - Compression (CRIME attack surface)
pub const MIN_TLS_VERSION: &str = "1.3";

/// Required TLS 1.3 cipher suites for QUIC connections.
///
/// # Invariant
///
/// Only AEAD cipher suites with forward secrecy are accepted. Any peer that
/// offers only non-AEAD or export-grade ciphers MUST be rejected.
///
/// Suite meanings:
///   - `TLS_AES_256_GCM_SHA384`       256-bit AES-GCM; preferred on hardware-AES platforms
///   - `TLS_AES_128_GCM_SHA256`       128-bit AES-GCM; minimum for standard nodes
///   - `TLS_CHACHA20_POLY1305_SHA256` ChaCha20-Poly1305; preferred on constrained/mobile nodes
pub const REQUIRED_CIPHER_SUITES: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
];

/// Network configuration that captures transport and encryption invariants.
///
/// Use `NetworkConfig::default()` to obtain the mandatory baseline, then pass
/// the value to `validate_network_config()` before starting any listener or
/// initiating any outbound connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Transport protocol in use (must equal `TRANSPORT_PROTOCOL`).
    pub transport_protocol: &'static str,
    /// Minimum TLS version (must equal `MIN_TLS_VERSION`).
    pub min_tls_version: &'static str,
    /// Accepted cipher suites (must be a subset of `REQUIRED_CIPHER_SUITES`
    /// and must contain at least one entry from that list).
    pub cipher_suites: &'static [&'static str],
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            transport_protocol: TRANSPORT_PROTOCOL,
            min_tls_version: MIN_TLS_VERSION,
            cipher_suites: REQUIRED_CIPHER_SUITES,
        }
    }
}

/// Validate a `NetworkConfig` against the mandatory transport and encryption invariants.
///
/// # Errors
///
/// Returns an error string describing the first invariant violation found.
/// Returns `Ok(())` when all invariants hold.
///
/// # Invariants checked
///
/// 1. `transport_protocol` must equal `TRANSPORT_PROTOCOL` ("QUIC").
/// 2. `min_tls_version` must equal `MIN_TLS_VERSION` ("1.3").
/// 3. `cipher_suites` must not be empty.
/// 4. Every entry in `cipher_suites` must appear in `REQUIRED_CIPHER_SUITES`.
///
/// # Example
///
/// ```rust
/// use lib_network::constants::{NetworkConfig, validate_network_config};
///
/// let cfg = NetworkConfig::default();
/// assert!(validate_network_config(&cfg).is_ok());
/// ```
pub fn validate_network_config(config: &NetworkConfig) -> Result<(), String> {
    // Invariant 1: transport protocol must be QUIC.
    if config.transport_protocol != TRANSPORT_PROTOCOL {
        return Err(format!(
            "INVARIANT VIOLATED: transport_protocol must be {:?}, got {:?}",
            TRANSPORT_PROTOCOL, config.transport_protocol
        ));
    }

    // Invariant 2: TLS version floor must be 1.3.
    if config.min_tls_version != MIN_TLS_VERSION {
        return Err(format!(
            "INVARIANT VIOLATED: min_tls_version must be {:?}, got {:?}",
            MIN_TLS_VERSION, config.min_tls_version
        ));
    }

    // Invariant 3: cipher suite list must not be empty.
    if config.cipher_suites.is_empty() {
        return Err(
            "INVARIANT VIOLATED: cipher_suites must not be empty".to_string()
        );
    }

    // Invariant 4: every configured suite must be in the approved list.
    for suite in config.cipher_suites {
        if !REQUIRED_CIPHER_SUITES.contains(suite) {
            return Err(format!(
                "INVARIANT VIOLATED: cipher suite {:?} is not in REQUIRED_CIPHER_SUITES",
                suite
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[test]
    fn default_config_passes_validation() {
        let cfg = NetworkConfig::default();
        assert!(
            validate_network_config(&cfg).is_ok(),
            "Default NetworkConfig must satisfy all invariants"
        );
    }

    #[test]
    fn wrong_transport_protocol_fails() {
        let cfg = NetworkConfig {
            transport_protocol: "TCP",
            ..NetworkConfig::default()
        };
        let result = validate_network_config(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("transport_protocol"));
    }

    #[test]
    fn wrong_tls_version_fails() {
        let cfg = NetworkConfig {
            min_tls_version: "1.2",
            ..NetworkConfig::default()
        };
        let result = validate_network_config(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("min_tls_version"));
    }

    #[test]
    fn empty_cipher_suites_fails() {
        let cfg = NetworkConfig {
            cipher_suites: &[],
            ..NetworkConfig::default()
        };
        let result = validate_network_config(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cipher_suites must not be empty"));
    }

    #[test]
    fn unapproved_cipher_suite_fails() {
        let cfg = NetworkConfig {
            cipher_suites: &["TLS_RSA_WITH_AES_128_CBC_SHA"],
            ..NetworkConfig::default()
        };
        let result = validate_network_config(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in REQUIRED_CIPHER_SUITES"));
    }

    #[test]
    fn transport_protocol_constant_is_quic() {
        assert_eq!(TRANSPORT_PROTOCOL, "QUIC");
    }

    #[test]
    fn min_tls_version_constant_is_1_3() {
        assert_eq!(MIN_TLS_VERSION, "1.3");
    }

    #[test]
    fn required_cipher_suites_contains_expected_suites() {
        assert!(REQUIRED_CIPHER_SUITES.contains(&"TLS_AES_256_GCM_SHA384"));
        assert!(REQUIRED_CIPHER_SUITES.contains(&"TLS_AES_128_GCM_SHA256"));
        assert!(REQUIRED_CIPHER_SUITES.contains(&"TLS_CHACHA20_POLY1305_SHA256"));
    }
}
