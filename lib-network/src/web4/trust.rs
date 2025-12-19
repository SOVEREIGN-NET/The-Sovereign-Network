//! Web4 Trust Management
//!
//! Implements secure-by-default trust for ZHTP nodes:
//! - SPKI pinning (production)
//! - TOFU (Trust On First Use) with persistent storage
//! - Node DID binding after UHP handshake
//!
//! # Trust Model
//!
//! ZHTP uses a two-layer trust model:
//! 1. TLS layer: SPKI pinning or TOFU for transport security
//! 2. UHP layer: Dilithium signatures for identity verification
//!
//! Both layers must succeed. The node's DID (from UHP) must match
//! any configured expectation (--node-did or trustdb entry).

use anyhow::{anyhow, Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{info, warn, debug};
use x509_parser::prelude::*;
#[cfg(unix)]
use libc;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::{DigitallySignedStruct, SignatureScheme, Error as TlsError};

/// Trust policy for a node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustPolicy {
    /// Explicitly pinned (highest trust)
    Pinned,
    /// Trust on first use (persisted after first connection)
    Tofu,
    /// Bootstrap mode (dev only, no persistence)
    Bootstrap,
}

/// Trust anchor entry for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchor {
    /// Node address (ip:port or hostname:port)
    pub node_addr: String,
    /// Node DID (verified via UHP handshake)
    pub node_did: Option<String>,
    /// SPKI SHA-256 hash (base64 encoded)
    pub spki_sha256: String,
    /// Certificate fingerprint (for display/audit)
    pub cert_fingerprint: String,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Trust policy
    pub policy: TrustPolicy,
}

/// Trust database for persistent storage
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustDb {
    /// Version for forward compatibility
    pub version: u32,
    /// Trust anchors by node address
    pub anchors: HashMap<String, TrustAnchor>,
}

/// Audit log entry for TOFU acceptance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAuditEntry {
    pub timestamp: u64,
    pub node_addr: String,
    pub node_did: Option<String>,
    pub spki_sha256: String,
    pub tool_version: String,
}

impl TrustDb {
    /// Create empty trust database
    pub fn new() -> Self {
        Self {
            version: 1,
            anchors: HashMap::new(),
        }
    }

    /// Load from file, or create new if not exists
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::validate_permissions(path)?;
            let data = std::fs::read_to_string(path)
                .context("Failed to read trustdb")?;
            let db: TrustDb = serde_json::from_str(&data)
                .context("Failed to parse trustdb")?;
            Ok(db)
        } else {
            Ok(Self::new())
        }
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        // Enforce strict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    /// Append audit entry
    pub fn append_audit_entry(path: &Path, entry: &TrustAuditEntry) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let line = serde_json::to_string(entry)? + "\n";
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(line.as_bytes())
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Validate permissions on trustdb (fail closed in production)
    fn validate_permissions(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(path)
                .context("Failed to stat trustdb")?;
            let mode = meta.mode() & 0o777;

            // Only owner rw allowed
            if mode & 0o077 != 0 {
                return Err(anyhow!(
                    "Insecure permissions on trustdb {:?} (mode {:o}). Set to 0600",
                    path, mode
                ));
            }

            // Owner must be current user
            let uid = meta.uid();
            let current_uid = unsafe { libc::geteuid() } as u32;
            if uid != current_uid {
                return Err(anyhow!(
                    "Trustdb {:?} is owned by uid {}, expected {}",
                    path, uid, current_uid
                ));
            }
        }
        Ok(())
    }

    /// Get anchor for node address
    pub fn get(&self, node_addr: &str) -> Option<&TrustAnchor> {
        self.anchors.get(node_addr)
    }

    /// Add or update anchor
    pub fn set(&mut self, anchor: TrustAnchor) {
        self.anchors.insert(anchor.node_addr.clone(), anchor);
    }

    /// Remove anchor
    pub fn remove(&mut self, node_addr: &str) -> Option<TrustAnchor> {
        self.anchors.remove(node_addr)
    }
}

/// Trust configuration for a connection
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// Pinned SPKI hash (base64 SHA-256)
    pub pin_spki: Option<String>,
    /// Expected node DID
    pub node_did: Option<String>,
    /// Allow TOFU (trust on first use)
    pub allow_tofu: bool,
    /// Bootstrap mode (insecure, dev only)
    pub bootstrap_mode: bool,
    /// Path to trust database
    pub trustdb_path: Option<PathBuf>,
    /// Path to audit log
    pub audit_log_path: Option<PathBuf>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            pin_spki: None,
            node_did: None,
            allow_tofu: false,
            bootstrap_mode: false,
            trustdb_path: None,
            audit_log_path: None,
        }
    }
}

impl TrustConfig {
    /// Create config for bootstrap mode (dev only)
    pub fn bootstrap() -> Self {
        Self {
            bootstrap_mode: true,
            ..Default::default()
        }
    }

    /// Create config with SPKI pin
    pub fn with_pin(spki_sha256: String) -> Self {
        Self {
            pin_spki: Some(spki_sha256),
            ..Default::default()
        }
    }

    /// Create config with TOFU enabled
    pub fn with_tofu(trustdb_path: PathBuf) -> Self {
        Self {
            allow_tofu: true,
            trustdb_path: Some(trustdb_path),
            audit_log_path: Some(Self::default_audit_path()),
            ..Default::default()
        }
    }

    /// Set expected node DID
    pub fn expect_node_did(mut self, did: String) -> Self {
        self.node_did = Some(did);
        self
    }

    /// Get default trustdb path
    pub fn default_trustdb_path() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("Could not determine home directory")?;
        Ok(PathBuf::from(home).join(".zhtp").join("trustdb.json"))
    }

    /// Get default audit log path (same dir as trustdb)
    pub fn default_audit_path() -> PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".zhtp").join("trust_audit.log")
    }
}

/// Verification result from TLS layer
#[derive(Debug, Clone)]
pub struct TlsVerificationResult {
    /// SPKI SHA-256 hash of the certificate
    pub spki_sha256: String,
    /// Certificate fingerprint (for display)
    pub cert_fingerprint: String,
    /// Whether this was a TOFU acceptance
    pub tofu_accepted: bool,
}

/// ZHTP Node Certificate Verifier
///
/// Implements the trust model:
/// 1. If pin_spki provided: require exact match
/// 2. Else if trustdb has entry: require match
/// 3. Else if TOFU enabled: accept and store
/// 4. Else if bootstrap: accept (insecure)
/// 5. Else: reject with actionable error
#[derive(Debug)]
pub struct ZhtpTrustVerifier {
    /// Trust configuration
    config: TrustConfig,
    /// Trust database (loaded at creation, saved on TOFU)
    trustdb: Arc<RwLock<TrustDb>>,
    /// Node address being connected to
    node_addr: String,
    /// Verification result (set after successful verify)
    result: Arc<RwLock<Option<TlsVerificationResult>>>,
}

impl ZhtpTrustVerifier {
    /// Create a new verifier for the given node address
    pub fn new(node_addr: String, config: TrustConfig) -> Result<Self> {
        // Load trustdb if path provided
        let trustdb = if let Some(ref path) = config.trustdb_path {
            TrustDb::load_or_create(path)?
        } else {
            TrustDb::new()
        };

        Ok(Self {
            config,
            trustdb: Arc::new(RwLock::new(trustdb)),
            node_addr,
            result: Arc::new(RwLock::new(None)),
        })
    }

    /// Get verification result after successful TLS handshake
    pub fn verification_result(&self) -> Option<TlsVerificationResult> {
        self.result.read().ok()?.clone()
    }

    /// Compute SPKI hash from certificate (no fallback)
    ///
    /// Fails if SPKI cannot be extracted, per security requirements.
    fn compute_spki_hash(cert: &CertificateDer<'_>) -> Result<String> {
        let (_, parsed_cert) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| anyhow!("Failed to parse X.509 certificate for SPKI extraction: {}", e))?;

        // DER-encoded SubjectPublicKeyInfo
        let spki_bytes = parsed_cert.public_key().raw;

        let hash = lib_crypto::hash_blake3(spki_bytes);
        Ok(hex::encode(hash))
    }

    /// Compute certificate fingerprint for display (full cert hash)
    fn compute_fingerprint(cert: &CertificateDer<'_>) -> String {
        let hash = lib_crypto::hash_blake3(cert.as_ref());
        hex::encode(&hash[..16])
    }

    /// Store TOFU anchor after successful verification
    fn store_tofu_anchor(&self, spki_hash: &str, fingerprint: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let anchor = TrustAnchor {
            node_addr: self.node_addr.clone(),
            node_did: None, // Will be set after UHP handshake
            spki_sha256: spki_hash.to_string(),
            cert_fingerprint: fingerprint.to_string(),
            first_seen: now,
            last_seen: now,
            policy: TrustPolicy::Tofu,
        };

        {
            let mut db = self.trustdb.write()
                .map_err(|_| anyhow!("Failed to lock trustdb"))?;
            db.set(anchor);
        }

        // Save to disk if path configured
        if let Some(ref path) = self.config.trustdb_path {
            let db = self.trustdb.read()
                .map_err(|_| anyhow!("Failed to lock trustdb"))?;
            db.save(path)?;
        }

        // Append audit log entry
        let audit_path = self.config.audit_log_path.clone().unwrap_or_else(|| TrustConfig::default_audit_path());
        if self.config.allow_tofu || self.config.bootstrap_mode {
            let entry = TrustAuditEntry {
                timestamp: now,
                node_addr: self.node_addr.clone(),
                node_did: None,
                spki_sha256: spki_hash.to_string(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            if let Err(e) = TrustDb::append_audit_entry(&audit_path, &entry) {
                warn!("Failed to append TOFU audit log: {}", e);
            }
        }

        Ok(())
    }

    /// Update anchor with verified node DID (called after UHP handshake)
    pub fn bind_node_did(&self, node_did: &str) -> Result<()> {
        let mut db = self.trustdb.write()
            .map_err(|_| anyhow!("Failed to lock trustdb"))?;

        if let Some(anchor) = db.anchors.get_mut(&self.node_addr) {
            // Verify DID matches if already set
            if let Some(ref existing_did) = anchor.node_did {
                if existing_did != node_did {
                    return Err(anyhow!(
                        "Node DID mismatch: expected {}, got {}",
                        existing_did, node_did
                    ));
                }
            } else {
                // First time seeing DID, store it
                anchor.node_did = Some(node_did.to_string());
                anchor.last_seen = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            }
        }

        // Save if path configured
        drop(db);
        if let Some(ref path) = self.config.trustdb_path {
            let db = self.trustdb.read()
                .map_err(|_| anyhow!("Failed to lock trustdb"))?;
            db.save(path)?;
        }

        Ok(())
    }

    /// Verify node DID matches configuration
    pub fn verify_node_did(&self, node_did: &str) -> Result<()> {
        // Check explicit --node-did flag
        if let Some(ref expected) = self.config.node_did {
            if expected != node_did {
                return Err(anyhow!(
                    "Node DID mismatch: expected {} (from --node-did), got {}",
                    expected, node_did
                ));
            }
        }

        // Check trustdb entry
        let db = self.trustdb.read()
            .map_err(|_| anyhow!("Failed to lock trustdb"))?;

        if let Some(anchor) = db.get(&self.node_addr) {
            if let Some(ref stored_did) = anchor.node_did {
                if stored_did != node_did {
                    return Err(anyhow!(
                        "Node DID mismatch: trusted {} but node presented {}",
                        stored_did, node_did
                    ));
                }
            }
        }

        Ok(())
    }
}

impl ServerCertVerifier for ZhtpTrustVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let spki_hash = Self::compute_spki_hash(end_entity)
            .map_err(|e| TlsError::General(format!("{}", e).into()))?;
        let fingerprint = Self::compute_fingerprint(end_entity);

        debug!(
            server_name = ?server_name,
            spki_hash = %spki_hash,
            fingerprint = %fingerprint,
            "Verifying ZHTP node certificate"
        );

        // 1. Check explicit pin
        if let Some(ref pin) = self.config.pin_spki {
            if &spki_hash == pin {
                info!(
                    fingerprint = %fingerprint,
                    "Certificate verified via SPKI pin"
                );
                if let Ok(mut result) = self.result.write() {
                    *result = Some(TlsVerificationResult {
                        spki_sha256: spki_hash,
                        cert_fingerprint: fingerprint,
                        tofu_accepted: false,
                    });
                }
                return Ok(ServerCertVerified::assertion());
            } else {
                return Err(TlsError::General(format!(
                    "SPKI pin mismatch: expected {}, got {}",
                    pin, spki_hash
                ).into()));
            }
        }

        // 2. Check trustdb
        if let Ok(db) = self.trustdb.read() {
            if let Some(anchor) = db.get(&self.node_addr) {
                if anchor.spki_sha256 == spki_hash {
                    info!(
                        fingerprint = %fingerprint,
                        policy = ?anchor.policy,
                        "Certificate verified via trustdb"
                    );
                    if let Ok(mut result) = self.result.write() {
                        *result = Some(TlsVerificationResult {
                            spki_sha256: spki_hash,
                            cert_fingerprint: fingerprint,
                            tofu_accepted: false,
                        });
                    }
                    return Ok(ServerCertVerified::assertion());
                } else {
                    return Err(TlsError::General(format!(
                        "Certificate changed! Trusted fingerprint: {}, presented: {}. \
                        If this is expected, remove the old entry with: zhtp trust remove {}",
                        anchor.cert_fingerprint, fingerprint, self.node_addr
                    ).into()));
                }
            }
        }

        // 3. Check TOFU
        if self.config.allow_tofu {
            // Print fingerprint prominently for user awareness
            warn!("╔══════════════════════════════════════════════════════════════╗");
            warn!("║  TOFU: Trusting certificate on first use                     ║");
            warn!("╠══════════════════════════════════════════════════════════════╣");
            warn!("║  Node: {:<52} ║", &self.node_addr);
            warn!("║  Fingerprint: {:<46} ║", &fingerprint);
            warn!("║  SPKI Hash: {}...  ║", &spki_hash[..32]);
            warn!("╠══════════════════════════════════════════════════════════════╣");
            warn!("║  This certificate is now trusted for future connections.     ║");
            warn!("║  If this is unexpected, your connection may be compromised!  ║");
            warn!("║  To reset: delete ~/.zhtp/trustdb.json                       ║");
            warn!("╚══════════════════════════════════════════════════════════════╝");

            // Store anchor
            if let Err(e) = self.store_tofu_anchor(&spki_hash, &fingerprint) {
                warn!("Failed to store TOFU anchor: {}", e);
            }

            if let Ok(mut result) = self.result.write() {
                *result = Some(TlsVerificationResult {
                    spki_sha256: spki_hash,
                    cert_fingerprint: fingerprint,
                    tofu_accepted: true,
                });
            }
            return Ok(ServerCertVerified::assertion());
        }

        // 4. Check bootstrap mode
        if self.config.bootstrap_mode {
            // Log fingerprint even in bootstrap mode for debugging/auditing
            warn!("╔══════════════════════════════════════════════════════════════╗");
            warn!("║  INSECURE: Bootstrap mode - accepting ANY certificate        ║");
            warn!("╠══════════════════════════════════════════════════════════════╣");
            warn!("║  Node: {:<52} ║", &self.node_addr);
            warn!("║  Fingerprint: {:<46} ║", &fingerprint);
            warn!("║  SPKI Hash: {}...  ║", &spki_hash[..32]);
            warn!("╠══════════════════════════════════════════════════════════════╣");
            warn!("║  WARNING: No verification performed! Vulnerable to MITM!     ║");
            warn!("║  For production, use: --pin-spki {} ║", &spki_hash[..32]);
            warn!("╚══════════════════════════════════════════════════════════════╝");

            if let Ok(mut result) = self.result.write() {
                *result = Some(TlsVerificationResult {
                    spki_sha256: spki_hash,
                    cert_fingerprint: fingerprint,
                    tofu_accepted: false,
                });
            }
            return Ok(ServerCertVerified::assertion());
        }

        // 5. No trust anchor - reject with actionable error
        Err(TlsError::General(format!(
            "No trust anchor for node {}. Options:\n\
            1. Pin the certificate: --pin-spki {}\n\
            2. Trust on first use: --tofu\n\
            3. Specify expected node: --node-did <did>\n\
            4. Development only: --trust-node (insecure)",
            self.node_addr, spki_hash
        ).into()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trustdb_new() {
        let db = TrustDb::new();
        assert_eq!(db.version, 1);
        assert!(db.anchors.is_empty());
    }

    #[test]
    fn test_trustdb_operations() {
        let mut db = TrustDb::new();

        let anchor = TrustAnchor {
            node_addr: "127.0.0.1:9334".to_string(),
            node_did: Some("did:zhtp:abc123".to_string()),
            spki_sha256: "base64hash".to_string(),
            cert_fingerprint: "abcd1234".to_string(),
            first_seen: 1234567890,
            last_seen: 1234567890,
            policy: TrustPolicy::Pinned,
        };

        db.set(anchor.clone());
        assert!(db.get("127.0.0.1:9334").is_some());
        assert!(db.get("127.0.0.1:9999").is_none());

        db.remove("127.0.0.1:9334");
        assert!(db.get("127.0.0.1:9334").is_none());
    }

    #[test]
    fn test_trust_config_defaults() {
        let config = TrustConfig::default();
        assert!(!config.bootstrap_mode);
        assert!(!config.allow_tofu);
        assert!(config.pin_spki.is_none());
        assert!(config.node_did.is_none());
    }

    #[test]
    fn test_trust_config_bootstrap() {
        let config = TrustConfig::bootstrap();
        assert!(config.bootstrap_mode);
    }
}
