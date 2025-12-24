//! Authentication schemes, cipher suites, and post-quantum cryptography modes

use serde::{Deserialize, Serialize};

/// Authentication scheme supported by a protocol
///
/// Note: `Unauthenticated` is intentionally excluded from the default enum.
/// Use `UnsafeAuthScheme` for testing/debugging scenarios requiring no auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthScheme {
    /// Pre-shared key authentication (minimum acceptable security)
    PreSharedKey,
    /// Mutual handshake with identity verification (e.g., UHP) - recommended
    MutualHandshake,
    /// Certificate-based authentication
    Certificate,
    /// Post-quantum resistant mutual authentication using a PQC signature scheme.
    ///
    /// The concrete post-quantum algorithm is implementation-defined and selected by
    /// the underlying transport/handshake layer (for example, an ML-DSA (Dilithium)
    /// or SLH-DSA (SPHINCS+) signature scheme), rather than being fixed by this enum.
    PostQuantumMutual,
}

/// Unsafe authentication schemes - explicit opt-in required
///
/// SECURITY WARNING: These should only be used for testing, debugging,
/// or legacy protocol compatibility. Never use in production.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsafeAuthScheme {
    /// No authentication (DANGEROUS - testing only)
    Unauthenticated {
        /// Reason for using unauthenticated mode (for audit trail)
        reason: String,
    },
}

/// Encryption cipher suite
///
/// Note: `Plaintext` is intentionally excluded from the default enum.
/// Use `UnsafeCipherSuite` for testing/debugging scenarios requiring no encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256-GCM (minimum acceptable)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (recommended for software implementations)
    ChaCha20Poly1305,
    /// Kyber-768 + AES-256-GCM (hybrid PQC)
    KyberAes256,
    /// Kyber-1024 + ChaCha20 (hybrid PQC - preferred)
    KyberChaCha20,
    /// Full post-quantum encryption (future)
    FullPostQuantum,
}

impl CipherSuite {
    /// Get the required key size for this cipher suite
    pub fn key_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
            CipherSuite::KyberAes256 => 32,
            CipherSuite::KyberChaCha20 => 32,
            CipherSuite::FullPostQuantum => 32,
        }
    }
}

/// Unsafe cipher suites - explicit opt-in required
///
/// SECURITY WARNING: These should only be used for testing, debugging,
/// or legacy protocol compatibility. Never use in production.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsafeCipherSuite {
    /// Integrity-only with HMAC (no confidentiality)
    IntegrityOnly,
    /// Plaintext transport (DANGEROUS - testing only)
    Plaintext {
        /// Reason for using plaintext mode (for audit trail)
        reason: String,
    },
}

/// Post-quantum cryptography mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcMode {
    /// No post-quantum protection (classical only)
    None,
    /// Hybrid classical + PQC (Kyber KEM + classical AEAD)
    Hybrid,
    /// Full post-quantum (future - when standards mature)
    FullPqc,
}
