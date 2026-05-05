//! Kyber KEM session negotiation for encrypted messaging.
//!
//! A messaging session is established between two DIDs. The initiator
//! encapsulates a shared secret with the recipient's Kyber public key.
//! The recipient decapsulates to derive the same shared secret. From
//! this, the key ratchet derives per-message encryption keys.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// KDF info constant for messaging sessions — must be identical on both sides.
const MSG_KDF_INFO: &[u8] = b"zhtp-pq-msg-session-v1";

/// A messaging session between two DIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingSession {
    /// Our DID
    pub local_did: String,
    /// Their DID
    pub remote_did: String,
    /// Shared secret (32 bytes) — derived from Kyber KEM
    #[serde(with = "hex_bytes")]
    pub shared_secret: [u8; 32],
    /// Kyber ciphertext sent to/received from the peer (for session init)
    pub kem_ciphertext: Vec<u8>,
    /// Whether we initiated (encapsulated) or responded (decapsulated)
    pub is_initiator: bool,
    /// Session creation timestamp
    pub created_at: u64,
    /// Current ratchet epoch (increments on re-key)
    pub epoch: u32,
}

/// Session initiation request — sent from initiator to recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInitMessage {
    /// Initiator's DID
    pub sender_did: String,
    /// Recipient's DID
    pub recipient_did: String,
    /// Kyber ciphertext — recipient decapsulates to get shared secret
    pub kem_ciphertext: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Dilithium signature over hash(sender_did || recipient_did || kem_ciphertext || timestamp)
    pub signature: Vec<u8>,
}

/// Initiate a session: encapsulate shared secret with recipient's Kyber public key.
pub fn initiate_session(
    local_did: &str,
    remote_did: &str,
    remote_kyber_pk: &[u8],
) -> Result<MessagingSession> {
    if remote_kyber_pk.is_empty() {
        return Err(anyhow!(
            "Recipient {} has no Kyber public key — cannot establish encrypted session",
            &remote_did[..20.min(remote_did.len())]
        ));
    }

    let (ciphertext, shared_secret) =
        lib_crypto::post_quantum::kyber::kyber1024_encapsulate(remote_kyber_pk, MSG_KDF_INFO)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(MessagingSession {
        local_did: local_did.to_string(),
        remote_did: remote_did.to_string(),
        shared_secret,
        kem_ciphertext: ciphertext,
        is_initiator: true,
        created_at: now,
        epoch: 0,
    })
}

/// Accept a session: decapsulate shared secret from initiator's ciphertext.
pub fn accept_session(
    local_did: &str,
    remote_did: &str,
    kem_ciphertext: &[u8],
    local_kyber_sk: &[u8],
) -> Result<MessagingSession> {
    let shared_secret =
        lib_crypto::post_quantum::kyber::kyber1024_decapsulate(kem_ciphertext, local_kyber_sk, MSG_KDF_INFO)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(MessagingSession {
        local_did: local_did.to_string(),
        remote_did: remote_did.to_string(),
        shared_secret,
        kem_ciphertext: kem_ciphertext.to_vec(),
        is_initiator: false,
        created_at: now,
        epoch: 0,
    })
}

/// Re-key a session with fresh Kyber encapsulation (post-compromise security).
pub fn rekey_session(
    session: &mut MessagingSession,
    remote_kyber_pk: &[u8],
) -> Result<Vec<u8>> {
    let (ciphertext, new_secret) =
        lib_crypto::post_quantum::kyber::kyber1024_encapsulate(remote_kyber_pk, MSG_KDF_INFO)?;

    // Mix new secret into existing shared secret via HKDF
    let mixed = lib_crypto::hash_blake3(
        &[&session.shared_secret[..], &new_secret[..]].concat(),
    );
    session.shared_secret = mixed;
    session.kem_ciphertext = ciphertext.clone();
    session.epoch += 1;

    Ok(ciphertext)
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}
