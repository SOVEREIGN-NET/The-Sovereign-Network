//! Post-quantum encrypted messaging — client-side helpers.
//!
//! Mobile apps and other clients use these functions for all messaging crypto.
//! No external crypto libraries needed — everything is provided here.
//!
//! ```
//! use lib_client::messaging::*;
//!
//! // Session setup
//! let (ciphertext, session) = initiate_session("did:zhtp:me", recipient_kyber_pk)?;
//! // Send ciphertext to recipient as KeyExchange message
//!
//! // Encrypt a message
//! let envelope = seal_text_message(&mut session, "did:zhtp:them", "Hello!")?;
//! // Sign it
//! let signed = sign_envelope(envelope, &my_dilithium_sk)?;
//! // Hex-encode for /msg/send
//! let hex = encode_envelope(&signed)?;
//! ```

use crate::crypto::{Blake3, ChaCha20Poly1305Cipher, Dilithium5, Kyber1024};
use crate::error::{ClientError, Result};
use serde::{Deserialize, Serialize};

// ── Session ────────────────────────────────────────────────────────

/// A messaging session with a remote DID.
#[derive(Clone, Serialize, Deserialize)]
pub struct MessagingSession {
    pub local_did: String,
    pub remote_did: String,
    pub chain_key: [u8; 32],
    pub counter: u64,
    pub epoch: u32,
}

/// Initiate a session: Kyber encapsulate → shared secret → ratchet.
/// Returns (kyber_ciphertext, session). Send ciphertext to recipient.
pub fn initiate_session(
    local_did: &str,
    remote_did: &str,
    remote_kyber_pk: &[u8],
) -> Result<(Vec<u8>, MessagingSession)> {
    let (shared_secret, ciphertext) = Kyber1024::encapsulate(remote_kyber_pk)?;

    let chain_key = Blake3::hash(&[&shared_secret, b"zhtp-msg-chain-v1" as &[u8]].concat());

    Ok((
        ciphertext,
        MessagingSession {
            local_did: local_did.to_string(),
            remote_did: remote_did.to_string(),
            chain_key,
            counter: 0,
            epoch: 0,
        },
    ))
}

/// Accept a session: Kyber decapsulate → shared secret → ratchet.
pub fn accept_session(
    local_did: &str,
    remote_did: &str,
    kyber_ciphertext: &[u8],
    local_kyber_sk: &[u8],
) -> Result<MessagingSession> {
    let shared_secret = Kyber1024::decapsulate(kyber_ciphertext, local_kyber_sk)?;

    let chain_key = Blake3::hash(&[&shared_secret, b"zhtp-msg-chain-v1" as &[u8]].concat());

    Ok(MessagingSession {
        local_did: local_did.to_string(),
        remote_did: remote_did.to_string(),
        chain_key,
        counter: 0,
        epoch: 0,
    })
}

/// Re-key a session with fresh Kyber encapsulation (post-compromise security).
/// Returns kyber_ciphertext to send to the peer as a KeyRatchet message.
pub fn rekey_session(
    session: &mut MessagingSession,
    remote_kyber_pk: &[u8],
) -> Result<Vec<u8>> {
    let (new_secret, ciphertext) = Kyber1024::encapsulate(remote_kyber_pk)?;

    session.chain_key =
        Blake3::hash(&[&session.chain_key[..], &new_secret, b"rekey" as &[u8]].concat());
    session.epoch += 1;
    session.counter = 0;

    Ok(ciphertext)
}

/// Accept a re-key from a peer.
pub fn accept_rekey(
    session: &mut MessagingSession,
    kyber_ciphertext: &[u8],
    local_kyber_sk: &[u8],
) -> Result<()> {
    let new_secret = Kyber1024::decapsulate(kyber_ciphertext, local_kyber_sk)?;

    session.chain_key =
        Blake3::hash(&[&session.chain_key[..], &new_secret, b"rekey" as &[u8]].concat());
    session.epoch += 1;
    session.counter = 0;

    Ok(())
}

// ── Envelope ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentType {
    Text,
    Image,
    File,
    Voice,
    KeyExchange,
    KeyRatchet,
    ReadReceipt,
    GroupInvite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub version: u8,
    pub sender_did: String,
    pub recipient_did: String,
    pub timestamp: u64,
    pub epoch: u32,
    pub sequence: u64,
    pub content_type: ContentType,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageContent {
    content_type: ContentType,
    body: Vec<u8>,
}

/// Derive a message key + nonce from the session ratchet. Advances the ratchet.
fn next_message_key(session: &mut MessagingSession) -> ([u8; 32], [u8; 12], u32, u64) {
    let counter = session.counter;
    let epoch = session.epoch;

    let msg_key = Blake3::hash(
        &[&session.chain_key[..], b"msg", &counter.to_le_bytes()].concat(),
    );

    let nonce_full = Blake3::hash(
        &[&session.chain_key[..], b"nonce", &counter.to_le_bytes()].concat(),
    );
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);

    // Advance ratchet — old key gone (forward secrecy)
    session.chain_key = Blake3::hash(
        &[&session.chain_key[..], b"next", &counter.to_le_bytes()].concat(),
    );
    session.counter += 1;

    (msg_key, nonce, epoch, counter)
}

/// Derive a message key for decryption (stateless — doesn't advance ratchet).
fn derive_key_at(chain_key: &[u8; 32], counter: u64) -> ([u8; 32], [u8; 12]) {
    let msg_key = Blake3::hash(
        &[chain_key.as_slice(), b"msg", &counter.to_le_bytes()].concat(),
    );
    let nonce_full = Blake3::hash(
        &[chain_key.as_slice(), b"nonce", &counter.to_le_bytes()].concat(),
    );
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    (msg_key, nonce)
}

/// Seal a text message into an encrypted envelope. Advances the ratchet.
pub fn seal_text_message(
    session: &mut MessagingSession,
    text: &str,
) -> Result<MessageEnvelope> {
    let content = MessageContent {
        content_type: ContentType::Text,
        body: text.as_bytes().to_vec(),
    };
    seal_message(session, content)
}

/// Seal a binary message (image, file, voice) into an encrypted envelope.
pub fn seal_binary_message(
    session: &mut MessagingSession,
    content_type: ContentType,
    data: Vec<u8>,
) -> Result<MessageEnvelope> {
    let content = MessageContent {
        content_type,
        body: data,
    };
    seal_message(session, content)
}

/// Seal a KeyExchange message (send Kyber ciphertext to initiate session).
pub fn seal_key_exchange(
    sender_did: &str,
    recipient_did: &str,
    kyber_ciphertext: Vec<u8>,
) -> Result<MessageEnvelope> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(MessageEnvelope {
        version: 1,
        sender_did: sender_did.to_string(),
        recipient_did: recipient_did.to_string(),
        timestamp: now,
        epoch: 0,
        sequence: 0,
        content_type: ContentType::KeyExchange,
        ciphertext: kyber_ciphertext,
        signature: Vec::new(),
    })
}

fn seal_message(
    session: &mut MessagingSession,
    content: MessageContent,
) -> Result<MessageEnvelope> {
    let (msg_key, nonce, epoch, counter) = next_message_key(session);

    let plaintext = bincode::serialize(&content)
        .map_err(|e| ClientError::CryptoError(format!("Serialize failed: {}", e)))?;

    let ciphertext = ChaCha20Poly1305Cipher::encrypt(
        &plaintext,
        &msg_key,
        &nonce,
        session.local_did.as_bytes(),
    )?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(MessageEnvelope {
        version: 1,
        sender_did: session.local_did.clone(),
        recipient_did: session.remote_did.clone(),
        timestamp: now,
        epoch,
        sequence: counter,
        content_type: content.content_type,
        ciphertext,
        signature: Vec::new(), // sign with sign_envelope()
    })
}

/// Open (decrypt) a received envelope. Returns the plaintext body bytes.
pub fn open_envelope(
    envelope: &MessageEnvelope,
    chain_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let (msg_key, nonce) = derive_key_at(chain_key, envelope.sequence);

    let plaintext = ChaCha20Poly1305Cipher::decrypt(
        &envelope.ciphertext,
        &msg_key,
        &nonce,
        envelope.sender_did.as_bytes(),
    )?;

    let content: MessageContent = bincode::deserialize(&plaintext)
        .map_err(|e| ClientError::CryptoError(format!("Deserialize failed: {}", e)))?;

    Ok(content.body)
}

// ── Signing ────────────────────────────────────────────────────────

fn envelope_signing_hash(envelope: &MessageEnvelope) -> [u8; 32] {
    Blake3::hash(
        &[
            &[envelope.version],
            envelope.sender_did.as_bytes(),
            envelope.recipient_did.as_bytes(),
            &envelope.timestamp.to_le_bytes(),
            &envelope.epoch.to_le_bytes(),
            &envelope.sequence.to_le_bytes(),
            &bincode::serialize(&envelope.content_type).unwrap_or_default(),
            &envelope.ciphertext,
        ]
        .concat(),
    )
}

/// Sign an envelope with a Dilithium5 secret key.
pub fn sign_envelope(
    mut envelope: MessageEnvelope,
    dilithium_sk: &[u8],
) -> Result<MessageEnvelope> {
    let hash = envelope_signing_hash(&envelope);
    envelope.signature = Dilithium5::sign(&hash, dilithium_sk)?;
    Ok(envelope)
}

/// Verify an envelope's Dilithium5 signature.
pub fn verify_envelope(
    envelope: &MessageEnvelope,
    dilithium_pk: &[u8],
) -> Result<bool> {
    let hash = envelope_signing_hash(envelope);
    Dilithium5::verify(&hash, &envelope.signature, dilithium_pk)
}

// ── Wire format ────────────────────────────────────────────────────

/// Encode an envelope to hex string for the /msg/send API.
pub fn encode_envelope(envelope: &MessageEnvelope) -> Result<String> {
    let bytes = bincode::serialize(envelope)
        .map_err(|e| ClientError::CryptoError(format!("Serialize failed: {}", e)))?;
    Ok(hex::encode(bytes))
}

/// Decode an envelope from hex string (from /msg/receive API).
pub fn decode_envelope(hex_str: &str) -> Result<MessageEnvelope> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ClientError::CryptoError("Invalid hex".into()))?;
    bincode::deserialize(&bytes)
        .map_err(|e| ClientError::CryptoError(format!("Deserialize failed: {}", e)))
}
