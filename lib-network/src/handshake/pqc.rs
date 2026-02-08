//! Post-quantum handshake helpers (Kyber1024 + Dilithium5)
//!
//! Provides helper types and functions to negotiate PQC capabilities,
//! exchange Kyber1024 keys, and validate Dilithium5 signatures. Hybrid
//! mode mixes PQC secrets with classical session keys for defense in depth.

use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use sha3::Sha3_256;
use serde::{Serialize, Deserialize};

use lib_crypto::{
    post_quantum::{
        kyber1024_keypair, kyber1024_encapsulate, kyber1024_decapsulate,
        dilithium5_keypair, dilithium_sign, dilithium_verify,
    },
};

fn fp8(label: &'static str, bytes: &[u8]) -> String {
    // Debug fingerprint only (non-secret): blake3(data) prefix.
    // Never log raw key material.
    format!("{}:{}", label, hex::encode(&lib_crypto::hash_blake3(bytes)[..8]))
}

/// Supported PQC capability suites
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PqcCapability {
    /// No PQC support
    None,
    /// Full PQC: Kyber1024 KEM + Dilithium5 signatures
    Kyber1024Dilithium5,
    /// Hybrid: Classical (Ed25519) + Dilithium5 signatures
    HybridEd25519Dilithium5,
}

impl Default for PqcCapability {
    fn default() -> Self {
        PqcCapability::None
    }
}

impl PqcCapability {
    /// Returns true if PQC is enabled
    pub fn is_enabled(&self) -> bool {
        !matches!(self, PqcCapability::None)
    }

    /// String representation for signing/diagnostics
    pub fn as_str(&self) -> &'static str {
        match self {
            PqcCapability::None => "none",
            PqcCapability::Kyber1024Dilithium5 => "kyber1024+dilithium5",
            PqcCapability::HybridEd25519Dilithium5 => "hybrid-ed25519+dilithium5",
        }
    }

    /// Negotiate the strongest common capability
    pub fn negotiate(local: PqcCapability, remote: PqcCapability) -> PqcCapability {
        use PqcCapability::*;
        match (local, remote) {
            (Kyber1024Dilithium5, Kyber1024Dilithium5) => Kyber1024Dilithium5,
            (HybridEd25519Dilithium5, HybridEd25519Dilithium5) => HybridEd25519Dilithium5,
            (Kyber1024Dilithium5, HybridEd25519Dilithium5) |
            (HybridEd25519Dilithium5, Kyber1024Dilithium5) => HybridEd25519Dilithium5,
            _ => None,
        }
    }
}

/// Public PQC offer transmitted during handshake
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcHandshakeOffer {
    /// Selected PQC suite
    pub suite: PqcCapability,
    /// Kyber public key (1024 variant)
    pub kyber_public_key: Vec<u8>,
    /// Dilithium5 public key
    pub dilithium_public_key: Vec<u8>,
    /// Dilithium5 signature binding suite + Kyber key
    pub signature: Vec<u8>,
}

/// Ephemeral state kept locally (never transmitted)
#[derive(Debug, Clone)]
pub struct PqcHandshakeState {
    pub suite: PqcCapability,
    pub kyber_secret_key: Vec<u8>,
    pub dilithium_secret_key: Vec<u8>,
}

/// Create a PQC offer and local state for the initiator
pub fn create_pqc_offer(suite: PqcCapability) -> Result<(PqcHandshakeOffer, PqcHandshakeState)> {
    if !suite.is_enabled() {
        return Err(anyhow!("PQC suite is disabled"));
    }

    let (kyber_pk, kyber_sk) = kyber1024_keypair();
    let (dilithium_pk, dilithium_sk) = dilithium5_keypair();

    let kyber_pk_vec = kyber_pk.to_vec();
    tracing::debug!(
        kyber_pk = %fp8("kyber_pk", &kyber_pk_vec),
        kyber_sk = %fp8("kyber_sk", &kyber_sk),
        "PQC offer created (ephemeral keypair)"
    );
    eprintln!(
        "PQC offer created debug {} {}",
        fp8("kyber_pk", &kyber_pk_vec),
        fp8("kyber_sk", &kyber_sk)
    );

    let binder = binder_bytes(suite.as_str(), &kyber_pk_vec);
    let signature = dilithium_sign(&binder, &dilithium_sk)?;

    let offer = PqcHandshakeOffer {
        suite: suite.clone(),
        kyber_public_key: kyber_pk_vec,
        dilithium_public_key: dilithium_pk.clone(),
        signature,
    };

    let state = PqcHandshakeState {
        suite,
        kyber_secret_key: kyber_sk,
        dilithium_secret_key: dilithium_sk,
    };

    Ok((offer, state))
}

/// Verify a PQC offer (Dilithium signature over binder)
pub fn verify_pqc_offer(offer: &PqcHandshakeOffer) -> Result<()> {
    println!("verify_pqc_offer: pk_len={}, sig_len={}, kyber_pk_len={}",
        offer.dilithium_public_key.len(),
        offer.signature.len(),
        offer.kyber_public_key.len()
    );
    if !offer.suite.is_enabled() {
        println!("verify_pqc_offer: FAILED - suite disabled");
        return Err(anyhow!("Peer PQC suite disabled"));
    }

    let binder = binder_bytes(offer.suite.as_str(), &offer.kyber_public_key);
    println!("verify_pqc_offer: binder_len={}, calling dilithium_verify", binder.len());
    let valid = dilithium_verify(&binder, &offer.signature, &offer.dilithium_public_key)?;
    if !valid {
        println!("verify_pqc_offer: FAILED - dilithium_verify returned false");
        return Err(anyhow!("Invalid Dilithium signature on PQC offer (pk_len={})", offer.dilithium_public_key.len()));
    }
    println!("verify_pqc_offer: SUCCESS");
    Ok(())
}

/// Encapsulate a Kyber shared secret to the peer's PQC offer
///
/// ✅ FIX: Use consistent KDF info for encapsulation/decapsulation pair
pub fn encapsulate_pqc(offer: &PqcHandshakeOffer) -> Result<(Vec<u8>, [u8; 32])> {
    if !offer.suite.is_enabled() {
        return Err(anyhow!("PQC not enabled for encapsulation"));
    }
    let kdf_info = b"ZHTP-KEM-v2.0";
    let result = kyber1024_encapsulate(&offer.kyber_public_key, kdf_info)?;
    tracing::debug!(
        kyber_pk = %fp8("kyber_pk", &offer.kyber_public_key),
        ciphertext = %fp8("ct", &result.0),
        pqc_shared_prefix = ?hex::encode(&result.1[..8]),
        ciphertext_len = result.0.len(),
        "PQC encapsulate (initiator)"
    );
    eprintln!(
        "PQC encapsulate debug {} {} shared_prefix={}",
        fp8("kyber_pk", &offer.kyber_public_key),
        fp8("ct", &result.0),
        hex::encode(&result.1[..8])
    );
    Ok(result)
}

/// Decapsulate a Kyber shared secret using local state
pub fn decapsulate_pqc(ciphertext: &[u8], state: &PqcHandshakeState) -> Result<[u8; 32]> {
    if !state.suite.is_enabled() {
        return Err(anyhow!("PQC not enabled for decapsulation"));
    }
    let kdf_info = b"ZHTP-KEM-v2.0";
    let shared = kyber1024_decapsulate(ciphertext, &state.kyber_secret_key, kdf_info)?;
    tracing::debug!(
        kyber_sk = %fp8("kyber_sk", &state.kyber_secret_key),
        ciphertext = %fp8("ct", ciphertext),
        pqc_shared_prefix = ?hex::encode(&shared[..8]),
        ciphertext_len = ciphertext.len(),
        "PQC decapsulate (responder)"
    );
    eprintln!(
        "PQC decapsulate debug {} {} shared_prefix={}",
        fp8("kyber_sk", &state.kyber_secret_key),
        fp8("ct", ciphertext),
        hex::encode(&shared[..8])
    );
    Ok(shared)
}

/// Derive a hybrid session key that mixes PQC and classical secrets
pub fn derive_hybrid_session_key(pqc_shared: &[u8; 32], classical_session_key: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha3_256>::new(Some(classical_session_key), pqc_shared);
    let mut out = [0u8; 32];
    hk.expand(b"ZHTP-HYBRID-SESSION", &mut out)
        .map_err(|_| anyhow!("HKDF expansion failed"))?;
    tracing::debug!(
        pqc_shared_prefix = ?hex::encode(&pqc_shared[..8]),
        classical_key_prefix = ?hex::encode(&classical_session_key[..8]),
        hybrid_key_prefix = ?hex::encode(&out[..8]),
        "derive_hybrid_session_key"
    );
    Ok(out)
}

fn binder_bytes(suite_str: &str, kyber_public: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(suite_str.as_bytes());
    buf.extend_from_slice(&(kyber_public.len() as u32).to_le_bytes());
    buf.extend_from_slice(kyber_public);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_offer_and_handshake() -> Result<()> {
        let (offer, state_initiator) = create_pqc_offer(PqcCapability::Kyber1024Dilithium5)?;
        verify_pqc_offer(&offer)?;

        let (ciphertext, shared_initiator) = encapsulate_pqc(&offer)?;
        let shared_responder = decapsulate_pqc(&ciphertext, &state_initiator)?;

        assert_eq!(shared_initiator, shared_responder);

        let classical = [0xAAu8; 32];
        let hybrid1 = derive_hybrid_session_key(&shared_initiator, &classical)?;
        let hybrid2 = derive_hybrid_session_key(&shared_responder, &classical)?;
        assert_eq!(hybrid1, hybrid2);
        Ok(())
    }

    #[test]
    fn test_pqc_negotiation_priority() {
        use PqcCapability::*;
        assert_eq!(PqcCapability::negotiate(Kyber1024Dilithium5, Kyber1024Dilithium5), Kyber1024Dilithium5);
        assert_eq!(PqcCapability::negotiate(HybridEd25519Dilithium5, Kyber1024Dilithium5), HybridEd25519Dilithium5);
        assert_eq!(PqcCapability::negotiate(HybridEd25519Dilithium5, HybridEd25519Dilithium5), HybridEd25519Dilithium5);
        assert_eq!(PqcCapability::negotiate(None, HybridEd25519Dilithium5), None);
    }
}
