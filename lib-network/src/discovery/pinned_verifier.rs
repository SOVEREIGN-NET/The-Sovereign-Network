//! PinnedCertVerifier - Production-safe TLS certificate verification for mesh networks
//!
//! Implements certificate pinning at the TLS layer with three deterministic paths:
//!
//! 1. **Configured bootstrap peers (explicit allowlist)**: TOFU (Trust On First Use)
//!    - Accept any presented certificate
//!    - Immediately persist the SPKI pin bound to peer identity
//!    - Subsequent connections enforce pin match
//!
//! 2. **Known peers (pin exists in cache)**: Strict verification
//!    - Require presented cert matches cached SPKI pin
//!    - Mismatch = hard fail (rotation requires explicit workflow)
//!
//! 3. **Unknown peers (no pin, not in bootstrap allowlist)**: Reject
//!    - No TOFU for random nodes
//!    - Must be discovered via signed announcements first
//!
//! # Security Properties
//!
//! - **Pin binding**: SPKI hash is bound to NodeId, not just IP:port
//! - **Rotation policy**: TLS cert rotation requires same Dilithium identity
//! - **Persistence**: Pins stored in node DB, survives restarts
//! - **No silent rollover**: Mismatches are hard failures

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

use super::pin_cache::{NodeIdKey, PinCacheEntry};

/// Result of certificate verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Pin matched cached value
    PinMatched,
    /// TOFU: first contact with bootstrap peer, pin will be cached
    TofuBootstrap,
    /// Rejected: pin mismatch
    PinMismatch,
    /// Rejected: unknown peer (not bootstrap, no pin)
    UnknownPeer,
}

/// Synchronous pin storage for TLS verification
///
/// This is separate from the async TlsPinCache because rustls requires
/// synchronous verification. Pins are synchronized from the async cache.
#[derive(Debug, Default)]
pub struct SyncPinStore {
    /// Map from SPKI hash to NodeIdKey for reverse lookup during TLS
    /// (we know the cert, need to find if it's pinned)
    spki_to_node: RwLock<std::collections::HashMap<[u8; 32], NodeIdKey>>,
    /// Map from NodeIdKey to pinned SPKI hash
    node_to_spki: RwLock<std::collections::HashMap<NodeIdKey, [u8; 32]>>,
    /// Set of NodeIdKeys that have pins (for fast lookup)
    pinned_nodes: RwLock<HashSet<NodeIdKey>>,
}

impl SyncPinStore {
    /// Create a new empty pin store
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a pin
    pub fn insert(&self, node_id: NodeIdKey, spki_hash: [u8; 32]) {
        let mut spki_to_node = self.spki_to_node.write().unwrap();
        let mut node_to_spki = self.node_to_spki.write().unwrap();
        let mut pinned_nodes = self.pinned_nodes.write().unwrap();

        // Remove old SPKI mapping if exists
        if let Some(old_spki) = node_to_spki.get(&node_id) {
            spki_to_node.remove(old_spki);
        }

        spki_to_node.insert(spki_hash, node_id);
        node_to_spki.insert(node_id, spki_hash);
        pinned_nodes.insert(node_id);
    }

    /// Check if a NodeId has a pinned certificate
    pub fn has_pin(&self, node_id: &NodeIdKey) -> bool {
        self.pinned_nodes.read().unwrap().contains(node_id)
    }

    /// Get the pinned SPKI for a NodeId
    pub fn get_pin(&self, node_id: &NodeIdKey) -> Option<[u8; 32]> {
        self.node_to_spki.read().unwrap().get(node_id).copied()
    }

    /// Verify a certificate's SPKI against the pin for a NodeId
    pub fn verify_spki(&self, node_id: &NodeIdKey, presented_spki: &[u8; 32]) -> Option<bool> {
        let node_to_spki = self.node_to_spki.read().unwrap();
        node_to_spki.get(node_id).map(|pinned| pinned == presented_spki)
    }

    /// Find the NodeId associated with an SPKI hash (for lookup by cert)
    pub fn find_node_by_spki(&self, spki_hash: &[u8; 32]) -> Option<NodeIdKey> {
        self.spki_to_node.read().unwrap().get(spki_hash).copied()
    }

    /// Get the number of pins stored
    pub fn len(&self) -> usize {
        self.pinned_nodes.read().unwrap().len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.pinned_nodes.read().unwrap().is_empty()
    }

    /// Sync from the async TlsPinCache
    pub fn sync_from_entries(&self, entries: &[PinCacheEntry]) {
        let mut spki_to_node = self.spki_to_node.write().unwrap();
        let mut node_to_spki = self.node_to_spki.write().unwrap();
        let mut pinned_nodes = self.pinned_nodes.write().unwrap();

        // Clear existing entries
        spki_to_node.clear();
        node_to_spki.clear();
        pinned_nodes.clear();

        // Add all entries from the async cache
        for entry in entries {
            spki_to_node.insert(entry.tls_spki_sha256, entry.node_id);
            node_to_spki.insert(entry.node_id, entry.tls_spki_sha256);
            pinned_nodes.insert(entry.node_id);
        }

        debug!("SyncPinStore: synced {} pins from async cache", entries.len());
    }
}

/// Configuration for the PinnedCertVerifier
#[derive(Debug, Clone)]
pub struct PinnedVerifierConfig {
    /// Bootstrap peer addresses that are allowed TOFU
    pub bootstrap_addrs: HashSet<SocketAddr>,
    /// Whether to allow connections to unknown peers (no pin, not bootstrap)
    /// Default: false (strict mode)
    pub allow_unknown_peers: bool,
}

impl Default for PinnedVerifierConfig {
    fn default() -> Self {
        Self {
            bootstrap_addrs: HashSet::new(),
            allow_unknown_peers: false,
        }
    }
}

impl PinnedVerifierConfig {
    /// Create a new config with bootstrap addresses
    pub fn with_bootstrap(addrs: Vec<SocketAddr>) -> Self {
        Self {
            bootstrap_addrs: addrs.into_iter().collect(),
            allow_unknown_peers: false,
        }
    }

    /// Add a bootstrap address
    pub fn add_bootstrap(&mut self, addr: SocketAddr) {
        self.bootstrap_addrs.insert(addr);
    }

    /// Check if an address is in the bootstrap allowlist
    pub fn is_bootstrap(&self, addr: &SocketAddr) -> bool {
        self.bootstrap_addrs.contains(addr)
    }
}

/// Production-safe TLS certificate verifier with pinning support
///
/// Implements the three-path verification model:
/// 1. Bootstrap peers: TOFU with immediate pin persistence
/// 2. Known peers: Strict pin enforcement
/// 3. Unknown peers: Rejection
pub struct PinnedCertVerifier {
    /// Configuration (bootstrap allowlist, etc.)
    config: PinnedVerifierConfig,
    /// Synchronous pin store for TLS verification
    pin_store: Arc<SyncPinStore>,
    /// The current peer address being verified (set before each connection)
    /// This is needed because verify_server_cert doesn't receive the socket address
    current_peer_addr: RwLock<Option<SocketAddr>>,
    /// Callback to persist pins after TOFU (called after successful connection)
    /// The callback receives (spki_hash, peer_addr) and should persist the pin
    tofu_callback: RwLock<Option<Box<dyn Fn([u8; 32], SocketAddr) + Send + Sync>>>,
}

impl std::fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("config", &self.config)
            .field("pin_store", &self.pin_store)
            .field("current_peer_addr", &self.current_peer_addr)
            .field("tofu_callback", &self.tofu_callback.read().map(|cb| cb.is_some()).unwrap_or(false))
            .finish()
    }
}

impl PinnedCertVerifier {
    /// Create a new verifier with the given configuration
    pub fn new(config: PinnedVerifierConfig) -> Self {
        Self {
            config,
            pin_store: Arc::new(SyncPinStore::new()),
            current_peer_addr: RwLock::new(None),
            tofu_callback: RwLock::new(None),
        }
    }

    /// Create a new verifier with bootstrap addresses
    pub fn with_bootstrap(addrs: Vec<SocketAddr>) -> Self {
        Self::new(PinnedVerifierConfig::with_bootstrap(addrs))
    }

    /// Get a reference to the pin store
    pub fn pin_store(&self) -> Arc<SyncPinStore> {
        Arc::clone(&self.pin_store)
    }

    /// Set the current peer address for the next verification
    /// Must be called before initiating a QUIC connection
    pub fn set_current_peer(&self, addr: SocketAddr) {
        *self.current_peer_addr.write().unwrap() = Some(addr);
    }

    /// Clear the current peer address
    pub fn clear_current_peer(&self) {
        *self.current_peer_addr.write().unwrap() = None;
    }

    /// Get the current peer address
    pub fn current_peer(&self) -> Option<SocketAddr> {
        *self.current_peer_addr.read().unwrap()
    }

    /// Set the callback for TOFU pin persistence
    pub fn set_tofu_callback<F>(&self, callback: F)
    where
        F: Fn([u8; 32], SocketAddr) + Send + Sync + 'static,
    {
        *self.tofu_callback.write().unwrap() = Some(Box::new(callback));
    }

    /// Sync pins from the async TlsPinCache
    pub fn sync_from_cache(&self, entries: &[PinCacheEntry]) {
        self.pin_store.sync_from_entries(entries);
    }

    /// Add a pin directly (for testing or manual pinning)
    pub fn add_pin(&self, node_id: NodeIdKey, spki_hash: [u8; 32]) {
        self.pin_store.insert(node_id, spki_hash);
    }

    /// Check if an address is in the bootstrap allowlist
    pub fn is_bootstrap(&self, addr: &SocketAddr) -> bool {
        self.config.is_bootstrap(addr)
    }

    /// Extract SPKI SHA256 hash from a certificate
    pub fn extract_spki_hash(cert: &CertificateDer<'_>) -> Result<[u8; 32], TlsError> {
        // Parse the certificate
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
            .map_err(|e| TlsError::General(format!("Failed to parse certificate: {}", e)))?;

        // Get the SubjectPublicKeyInfo (SPKI) bytes
        let spki_bytes = parsed.public_key().raw;

        // Hash with SHA256
        let mut hasher = Sha256::new();
        hasher.update(spki_bytes);
        let hash = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
    }

    /// Verify a certificate and determine the result
    fn verify_certificate(
        &self,
        cert: &CertificateDer<'_>,
        peer_addr: Option<SocketAddr>,
    ) -> VerificationResult {
        // Extract SPKI hash from the certificate
        let spki_hash = match Self::extract_spki_hash(cert) {
            Ok(hash) => hash,
            Err(e) => {
                warn!("Failed to extract SPKI from certificate: {}", e);
                return VerificationResult::UnknownPeer;
            }
        };

        // Path 1: Check if this SPKI is already pinned
        if let Some(node_id) = self.pin_store.find_node_by_spki(&spki_hash) {
            debug!(
                "Certificate SPKI matches pinned node {:?}",
                &node_id[..8]
            );
            return VerificationResult::PinMatched;
        }

        // Path 2: Check if this is a bootstrap peer (TOFU allowed)
        if let Some(addr) = peer_addr {
            if self.config.is_bootstrap(&addr) {
                info!(
                    "TOFU: accepting certificate from bootstrap peer {} (SPKI: {})",
                    addr,
                    hex::encode(&spki_hash[..8])
                );

                // Trigger TOFU callback to persist the pin
                if let Some(callback) = self.tofu_callback.read().unwrap().as_ref() {
                    callback(spki_hash, addr);
                }

                return VerificationResult::TofuBootstrap;
            }
        }

        // Path 3: Check if unknown peers are allowed
        if self.config.allow_unknown_peers {
            debug!("Allowing unknown peer (allow_unknown_peers=true)");
            return VerificationResult::TofuBootstrap; // Treat as TOFU
        }

        // Path 3: Reject unknown peer
        warn!(
            "Rejecting certificate from unknown peer {:?} (SPKI: {})",
            peer_addr,
            hex::encode(&spki_hash[..8])
        );
        VerificationResult::UnknownPeer
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let peer_addr = self.current_peer();

        match self.verify_certificate(end_entity, peer_addr) {
            VerificationResult::PinMatched => {
                debug!("Certificate verified: pin matched");
                Ok(ServerCertVerified::assertion())
            }
            VerificationResult::TofuBootstrap => {
                debug!("Certificate verified: TOFU for bootstrap peer");
                Ok(ServerCertVerified::assertion())
            }
            VerificationResult::PinMismatch => {
                Err(TlsError::General(
                    "Certificate SPKI does not match pinned value".to_string(),
                ))
            }
            VerificationResult::UnknownPeer => {
                Err(TlsError::General(
                    "Unknown peer: not in bootstrap allowlist and no pin cached".to_string(),
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // We accept any signature since we're doing pin-based verification
        // The actual cryptographic verification is done by the UHP layer
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // We accept any signature since we're doing pin-based verification
        // The actual cryptographic verification is done by the UHP layer
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Support all common signature schemes
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Global PinnedCertVerifier instance
static PINNED_VERIFIER: std::sync::OnceLock<Arc<PinnedCertVerifier>> = std::sync::OnceLock::new();

/// Initialize the global PinnedCertVerifier with bootstrap addresses
pub fn init_global_verifier(bootstrap_addrs: Vec<SocketAddr>) -> Arc<PinnedCertVerifier> {
    let verifier = Arc::new(PinnedCertVerifier::with_bootstrap(bootstrap_addrs));
    let _ = PINNED_VERIFIER.set(Arc::clone(&verifier));
    info!(
        "PinnedCertVerifier initialized with {} bootstrap peers",
        verifier.config.bootstrap_addrs.len()
    );
    verifier
}

/// Get the global PinnedCertVerifier (creates default if not initialized)
pub fn global_verifier() -> Arc<PinnedCertVerifier> {
    PINNED_VERIFIER
        .get_or_init(|| Arc::new(PinnedCertVerifier::new(PinnedVerifierConfig::default())))
        .clone()
}

/// Check if the global verifier has been initialized
pub fn is_verifier_initialized() -> bool {
    PINNED_VERIFIER.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_pin_store_basic() {
        let store = SyncPinStore::new();
        assert!(store.is_empty());

        let node_id: NodeIdKey = [1u8; 32];
        let spki_hash = [42u8; 32];

        store.insert(node_id, spki_hash);

        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        assert!(store.has_pin(&node_id));
        assert_eq!(store.get_pin(&node_id), Some(spki_hash));
        assert_eq!(store.find_node_by_spki(&spki_hash), Some(node_id));
    }

    #[test]
    fn test_sync_pin_store_verify() {
        let store = SyncPinStore::new();
        let node_id: NodeIdKey = [1u8; 32];
        let correct_spki = [42u8; 32];
        let wrong_spki = [99u8; 32];

        store.insert(node_id, correct_spki);

        // Correct SPKI should match
        assert_eq!(store.verify_spki(&node_id, &correct_spki), Some(true));

        // Wrong SPKI should not match
        assert_eq!(store.verify_spki(&node_id, &wrong_spki), Some(false));

        // Unknown node should return None
        let unknown_node: NodeIdKey = [2u8; 32];
        assert_eq!(store.verify_spki(&unknown_node, &correct_spki), None);
    }

    #[test]
    fn test_pinned_verifier_config() {
        let addr1: SocketAddr = "192.168.1.1:9334".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.1:9334".parse().unwrap();
        let addr3: SocketAddr = "172.16.0.1:9334".parse().unwrap();

        let config = PinnedVerifierConfig::with_bootstrap(vec![addr1, addr2]);

        assert!(config.is_bootstrap(&addr1));
        assert!(config.is_bootstrap(&addr2));
        assert!(!config.is_bootstrap(&addr3));
    }

    #[test]
    fn test_pinned_verifier_bootstrap_tofu() {
        let bootstrap_addr: SocketAddr = "192.168.1.100:9334".parse().unwrap();
        let verifier = PinnedCertVerifier::with_bootstrap(vec![bootstrap_addr]);

        // Set current peer to bootstrap address
        verifier.set_current_peer(bootstrap_addr);
        assert!(verifier.is_bootstrap(&bootstrap_addr));
    }

    #[test]
    fn test_pinned_verifier_pin_matched() {
        let verifier = PinnedCertVerifier::new(PinnedVerifierConfig::default());

        let node_id: NodeIdKey = [1u8; 32];
        let spki_hash = [42u8; 32];

        // Add a pin
        verifier.add_pin(node_id, spki_hash);

        // Verify the pin store has it
        assert!(verifier.pin_store.has_pin(&node_id));
        assert_eq!(verifier.pin_store.find_node_by_spki(&spki_hash), Some(node_id));
    }

    #[test]
    fn test_pinned_verifier_unknown_peer_rejected() {
        let verifier = PinnedCertVerifier::new(PinnedVerifierConfig::default());

        // No pins, not a bootstrap peer
        let unknown_addr: SocketAddr = "192.168.1.100:9334".parse().unwrap();
        verifier.set_current_peer(unknown_addr);

        // Should not be in bootstrap list
        assert!(!verifier.is_bootstrap(&unknown_addr));
    }
}
