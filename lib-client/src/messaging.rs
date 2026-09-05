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
use std::collections::HashMap;

/// Maximum number of skipped message keys a session will buffer for out-of-order
/// delivery before refusing to ratchet further. Bounds memory and rate-limits a
/// peer that floods with high sequence numbers to force key derivation.
pub const MAX_SKIPPED_KEYS_PER_EPOCH: usize = 1024;

// ── Session ────────────────────────────────────────────────────────

/// A messaging session with a remote DID.
///
/// `chain_key` and `counter` advance in lockstep with the peer's matching
/// session: the sender advances on `seal_*`, the receiver advances on
/// `open_envelope_with_session`. Each session is therefore directional in
/// practice — full-duplex callers maintain two sessions per peer.
///
/// `skipped_keys` buffers `(msg_key, nonce)` pairs for sequences the
/// receiver had to walk past to decrypt a later message that arrived
/// first. Both halves are needed because the sender derives the nonce
/// from the chain key (which is discarded once we ratchet past it), so
/// the receiver can't reconstruct the nonce later from the message key
/// alone. Cleared on `rekey` / `accept_rekey`. Bounded by
/// `MAX_SKIPPED_KEYS_PER_EPOCH`. `#[serde(skip)]` keeps the bincode wire
/// format identical to v1 so previously persisted sessions deserialise
/// unchanged.
#[derive(Clone, Serialize, Deserialize)]
pub struct MessagingSession {
    pub local_did: String,
    pub remote_did: String,
    pub chain_key: [u8; 32],
    pub counter: u64,
    pub epoch: u32,
    #[serde(skip)]
    pub skipped_keys: HashMap<u64, ([u8; 32], [u8; 12])>,
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
            skipped_keys: HashMap::new(),
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
        skipped_keys: HashMap::new(),
    })
}

/// Re-key a session with fresh Kyber encapsulation (post-compromise security).
/// Returns kyber_ciphertext to send to the peer as a KeyRatchet message.
pub fn rekey_session(session: &mut MessagingSession, remote_kyber_pk: &[u8]) -> Result<Vec<u8>> {
    let (new_secret, ciphertext) = Kyber1024::encapsulate(remote_kyber_pk)?;

    session.chain_key =
        Blake3::hash(&[&session.chain_key[..], &new_secret, b"rekey" as &[u8]].concat());
    session.epoch += 1;
    session.counter = 0;
    session.skipped_keys.clear();

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
    session.skipped_keys.clear();

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

    let msg_key = Blake3::hash(&[&session.chain_key[..], b"msg", &counter.to_le_bytes()].concat());

    let nonce_full =
        Blake3::hash(&[&session.chain_key[..], b"nonce", &counter.to_le_bytes()].concat());
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);

    // Advance ratchet — old key gone (forward secrecy)
    session.chain_key =
        Blake3::hash(&[&session.chain_key[..], b"next", &counter.to_le_bytes()].concat());
    session.counter += 1;

    (msg_key, nonce, epoch, counter)
}

/// Derive a message key for decryption (stateless — doesn't advance ratchet).
fn derive_key_at(chain_key: &[u8; 32], counter: u64) -> ([u8; 32], [u8; 12]) {
    let msg_key = Blake3::hash(&[chain_key.as_slice(), b"msg", &counter.to_le_bytes()].concat());
    let nonce_full =
        Blake3::hash(&[chain_key.as_slice(), b"nonce", &counter.to_le_bytes()].concat());
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    (msg_key, nonce)
}

/// Seal a text message into an encrypted envelope. Advances the ratchet.
pub fn seal_text_message(session: &mut MessagingSession, text: &str) -> Result<MessageEnvelope> {
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

/// Open (decrypt) a received envelope using a raw chain key. **Stateless** —
/// does not advance any ratchet. The caller must supply the chain key that
/// matches `envelope.sequence`, i.e. `chain_key_N` where
/// `chain_key_{i+1} = H(chain_key_i || "next" || i)`. Useful for
/// KeyExchange / first-contact envelopes or for callers that manage the
/// chain key out-of-band; otherwise prefer `open_envelope_with_session`
/// which mirrors the sender's ratchet and handles out-of-order delivery.
pub fn open_envelope(envelope: &MessageEnvelope, chain_key: &[u8; 32]) -> Result<Vec<u8>> {
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

/// Advance `chain_key` one ratchet step — exact inverse of the step
/// performed in `next_message_key`. Used by the receive ratchet to walk
/// forward over delivered or skipped sequences.
fn ratchet_chain_key(chain_key: &[u8; 32], counter: u64) -> [u8; 32] {
    Blake3::hash(&[&chain_key[..], b"next", &counter.to_le_bytes()].concat())
}

/// Open (decrypt) a received envelope using a session, advancing the
/// receive ratchet in lockstep with the sender's send ratchet.
///
/// Behaviour:
/// - `envelope.sequence == session.counter` → derive `msg_key` at the
///   current state, decrypt, then advance chain key + counter.
/// - `envelope.sequence > session.counter` → ratchet forward, buffering
///   message keys for skipped sequences in `session.skipped_keys` so they
///   can still be opened if they arrive later. Skip distance is bounded
///   by `MAX_SKIPPED_KEYS_PER_EPOCH` to prevent DoS.
/// - `envelope.sequence < session.counter` → look up the message key in
///   `session.skipped_keys`. Hit means out-of-order delivery, decrypt and
///   evict the entry. Miss means replay or pre-rekey traffic — error.
///
/// `envelope.epoch` must match `session.epoch`; cross-epoch envelopes
/// require a rekey first.
///
/// On decrypt failure the session is left untouched (clone-then-commit).
pub fn open_envelope_with_session(
    session: &mut MessagingSession,
    envelope: &MessageEnvelope,
) -> Result<Vec<u8>> {
    if envelope.epoch != session.epoch {
        return Err(ClientError::CryptoError(format!(
            "envelope epoch {} != session epoch {}",
            envelope.epoch, session.epoch
        )));
    }

    // Out-of-order: a previously skipped sequence is being delivered now.
    if envelope.sequence < session.counter {
        let (msg_key, nonce) = session
            .skipped_keys
            .get(&envelope.sequence)
            .copied()
            .ok_or_else(|| {
                ClientError::CryptoError(format!(
                    "sequence {} below counter {} and not in skipped buffer (replay or pre-rekey)",
                    envelope.sequence, session.counter
                ))
            })?;
        let plaintext = ChaCha20Poly1305Cipher::decrypt(
            &envelope.ciphertext,
            &msg_key,
            &nonce,
            envelope.sender_did.as_bytes(),
        )?;
        let content: MessageContent = bincode::deserialize(&plaintext)
            .map_err(|e| ClientError::CryptoError(format!("Deserialize failed: {}", e)))?;
        // Only evict on full success so a malformed payload doesn't lose the key.
        session.skipped_keys.remove(&envelope.sequence);
        return Ok(content.body);
    }

    // In-order or skip-forward. Reject runaway skips and counter overflow
    // before doing any work. The previous form
    //   `skipped_keys.len() as u64 + skip > MAX as u64`
    // wraps silently in release builds when an attacker picks
    // `envelope.sequence` near `u64::MAX`, which would (a) bypass the cap,
    // (b) cause `Vec::with_capacity(skip as usize)` to abort with OOM, and
    // (c) wrap `envelope.sequence + 1` back to 0 in the commit. Rewrite as
    // a subtraction-direction comparison and require sequence < u64::MAX
    // so the post-decrypt `+ 1` cannot overflow either.
    if envelope.sequence == u64::MAX {
        return Err(ClientError::CryptoError(
            "envelope sequence u64::MAX is not allowed (counter would overflow)".into(),
        ));
    }
    let skip = envelope.sequence - session.counter; // safe: seq >= counter on this branch
    let buf_used = session.skipped_keys.len() as u64;
    let max = MAX_SKIPPED_KEYS_PER_EPOCH as u64;
    if skip > max.saturating_sub(buf_used) {
        return Err(ClientError::CryptoError(format!(
            "skip of {} sequences would exceed max skipped-key buffer ({})",
            skip, MAX_SKIPPED_KEYS_PER_EPOCH
        )));
    }
    // At this point `skip <= MAX_SKIPPED_KEYS_PER_EPOCH` so the cast to
    // usize cannot truncate on any platform we support, and the allocation
    // is bounded by a small constant rather than by an attacker.
    let skip_cap = skip as usize;

    // Walk a local copy forward so a decrypt failure leaves the session intact.
    let mut chain_key = session.chain_key;
    let mut ctr = session.counter;
    let mut pending_skipped: Vec<(u64, [u8; 32], [u8; 12])> = Vec::with_capacity(skip_cap);
    while ctr < envelope.sequence {
        let (msg_key, nonce, _epoch, leaf_counter) = derive_step(&chain_key, ctr);
        pending_skipped.push((leaf_counter, msg_key, nonce));
        chain_key = ratchet_chain_key(&chain_key, ctr);
        ctr += 1;
    }

    let (msg_key, nonce, _epoch, _ctr) = derive_step(&chain_key, ctr);
    let plaintext = ChaCha20Poly1305Cipher::decrypt(
        &envelope.ciphertext,
        &msg_key,
        &nonce,
        envelope.sender_did.as_bytes(),
    )?;
    let content: MessageContent = bincode::deserialize(&plaintext)
        .map_err(|e| ClientError::CryptoError(format!("Deserialize failed: {}", e)))?;

    // Decrypt succeeded — commit the walk.
    for (seq, key, nonce) in pending_skipped {
        session.skipped_keys.insert(seq, (key, nonce));
    }
    session.chain_key = ratchet_chain_key(&chain_key, ctr);
    session.counter = envelope.sequence + 1;

    Ok(content.body)
}

/// Same derivation `next_message_key` performs but without mutating
/// session state — used by the receive walk. Returns
/// `(msg_key, nonce, epoch_placeholder, counter)`; the epoch isn't read
/// at this call site but the tuple shape mirrors `next_message_key`
/// for symmetry.
fn derive_step(chain_key: &[u8; 32], counter: u64) -> ([u8; 32], [u8; 12], u32, u64) {
    let msg_key = Blake3::hash(&[chain_key.as_slice(), b"msg", &counter.to_le_bytes()].concat());
    let nonce_full =
        Blake3::hash(&[chain_key.as_slice(), b"nonce", &counter.to_le_bytes()].concat());
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    (msg_key, nonce, 0, counter)
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
pub fn verify_envelope(envelope: &MessageEnvelope, dilithium_pk: &[u8]) -> Result<bool> {
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
    let bytes = hex::decode(hex_str).map_err(|_| ClientError::CryptoError("Invalid hex".into()))?;
    bincode::deserialize(&bytes)
        .map_err(|e| ClientError::CryptoError(format!("Deserialize failed: {}", e)))
}

/// Stable node `message_id` for an envelope (hex blake3 of wire bytes).
/// Matches server `message_id_for_envelope` — use for ack and client-side dedupe.
pub fn message_id_for_envelope(envelope: &MessageEnvelope) -> Result<String> {
    let bytes = bincode::serialize(envelope)
        .map_err(|e| ClientError::CryptoError(format!("Serialize failed: {}", e)))?;
    Ok(message_id_for_envelope_bytes(&bytes))
}

/// Stable node `message_id` from raw envelope bytes (hex blake3).
pub fn message_id_for_envelope_bytes(envelope_bytes: &[u8]) -> String {
    hex::encode(Blake3::hash(envelope_bytes))
}

/// JSON body for `POST /api/v1/msg/ack` after the client has persisted mail.
///
/// Delivery model (BUBL):
/// - `POST /msg/send` returns `status`: `"queued"` | `"pushed"` (never `"delivered"`).
/// - `GET /msg/receive` and inbound stream **peek** only; mail stays until ack.
/// - Client must `POST /msg/ack` with these ids after durable local store.
pub fn ack_request_body(message_ids: &[String]) -> Result<String> {
    #[derive(Serialize)]
    struct Body<'a> {
        message_ids: &'a [String],
    }
    serde_json::to_string(&Body { message_ids })
        .map_err(|e| ClientError::CryptoError(format!("ack body serialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Kyber1024;

    fn pair() -> (MessagingSession, MessagingSession) {
        let (recipient_pk, recipient_sk) = Kyber1024::generate_keypair().unwrap();
        let (ct, send) = initiate_session("did:zhtp:alice", "did:zhtp:bob", &recipient_pk).unwrap();
        let recv = accept_session("did:zhtp:bob", "did:zhtp:alice", &ct, &recipient_sk).unwrap();
        (send, recv)
    }

    #[test]
    fn stateful_open_handles_multiple_in_order_messages() {
        let (mut send, mut recv) = pair();

        for n in 0..5 {
            let msg = format!("hello {}", n);
            let env = seal_text_message(&mut send, &msg).unwrap();
            assert_eq!(env.sequence, n as u64);

            let body = open_envelope_with_session(&mut recv, &env).unwrap();
            assert_eq!(body, msg.as_bytes());
            assert_eq!(recv.counter, (n + 1) as u64);
        }
    }

    #[test]
    fn stateful_open_handles_skipped_then_delivered() {
        let (mut send, mut recv) = pair();

        let e0 = seal_text_message(&mut send, "zero").unwrap();
        let e1 = seal_text_message(&mut send, "one").unwrap();
        let e2 = seal_text_message(&mut send, "two").unwrap();

        // Deliver out of order: 0, 2, 1.
        assert_eq!(open_envelope_with_session(&mut recv, &e0).unwrap(), b"zero");
        assert_eq!(open_envelope_with_session(&mut recv, &e2).unwrap(), b"two");
        assert_eq!(recv.counter, 3);
        assert_eq!(recv.skipped_keys.len(), 1);

        assert_eq!(open_envelope_with_session(&mut recv, &e1).unwrap(), b"one");
        assert!(recv.skipped_keys.is_empty());
    }

    #[test]
    fn stateful_open_rejects_replay_of_consumed_sequence() {
        let (mut send, mut recv) = pair();
        let e0 = seal_text_message(&mut send, "first").unwrap();
        let _ = open_envelope_with_session(&mut recv, &e0).unwrap();
        let err = open_envelope_with_session(&mut recv, &e0).unwrap_err();
        assert!(format!("{}", err).contains("not in skipped buffer"));
    }

    #[test]
    fn stateful_open_rejects_epoch_mismatch() {
        let (mut send, mut recv) = pair();
        let mut e0 = seal_text_message(&mut send, "x").unwrap();
        e0.epoch = 99;
        let err = open_envelope_with_session(&mut recv, &e0).unwrap_err();
        assert!(format!("{}", err).contains("epoch"));
    }

    #[test]
    fn stateful_open_caps_skipped_keys_buffer() {
        let (mut send, mut recv) = pair();
        // Run sender far ahead.
        let mut envs = Vec::new();
        for _ in 0..(MAX_SKIPPED_KEYS_PER_EPOCH + 2) {
            envs.push(seal_text_message(&mut send, "x").unwrap());
        }
        // Try to open the final envelope first — would require buffering
        // MAX_SKIPPED_KEYS_PER_EPOCH+1 skipped keys.
        let err = open_envelope_with_session(&mut recv, envs.last().unwrap()).unwrap_err();
        assert!(format!("{}", err).contains("max skipped-key buffer"));
        // Session must be untouched.
        assert_eq!(recv.counter, 0);
    }

    #[test]
    fn stateless_and_stateful_open_agree_at_seq_zero() {
        let (mut send, mut recv) = pair();
        let chain_key_at_zero = recv.chain_key;
        let env = seal_text_message(&mut send, "ping").unwrap();
        let a = open_envelope(&env, &chain_key_at_zero).unwrap();
        let b = open_envelope_with_session(&mut recv, &env).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn stateful_open_rejects_huge_sequence_without_wrap() {
        // Regression: an attacker who controls `envelope.sequence` can
        // pick `skip` near u64::MAX so the previous additive cap check
        // (`skipped_keys.len() + skip > MAX`) wraps past 2^64 to a small
        // number and bypasses the guard, then forces a multi-EB
        // `Vec::with_capacity(skip as usize)` allocation. The exploit
        // needs the buffer to be near its cap so `len + skip` actually
        // crosses 2^64 — fill it to the cap to exercise the wrap path.
        let (mut send, mut recv) = pair();
        for i in 0..MAX_SKIPPED_KEYS_PER_EPOCH {
            recv.skipped_keys
                .insert(1_000_000 + i as u64, ([1u8; 32], [2u8; 12]));
        }
        assert_eq!(recv.skipped_keys.len(), MAX_SKIPPED_KEYS_PER_EPOCH);

        let mut env = seal_text_message(&mut send, "x").unwrap();
        // len = 1024, skip = u64::MAX - 1023 → 1024 + skip == 2^64 → wraps
        // to 0 under the old check (0 > 1024 is false → bypass). New
        // subtraction-direction check rejects.
        env.sequence = u64::MAX - (MAX_SKIPPED_KEYS_PER_EPOCH as u64 - 1);

        let err = open_envelope_with_session(&mut recv, &env).unwrap_err();
        assert!(format!("{}", err).contains("max skipped-key buffer"));
        // Session must be untouched — no partial advance, no allocation.
        assert_eq!(recv.counter, 0);
        assert_eq!(recv.skipped_keys.len(), MAX_SKIPPED_KEYS_PER_EPOCH);
    }

    #[test]
    fn stateful_open_rejects_sequence_u64_max() {
        // Regression: the success path sets `session.counter = sequence + 1`,
        // which wraps to 0 when sequence == u64::MAX. Reject up front.
        let (mut send, mut recv) = pair();
        let mut env = seal_text_message(&mut send, "x").unwrap();
        env.sequence = u64::MAX;
        let err = open_envelope_with_session(&mut recv, &env).unwrap_err();
        assert!(format!("{}", err).contains("u64::MAX"));
        assert_eq!(recv.counter, 0);
    }

    #[test]
    fn bincode_roundtrip_omits_skipped_keys() {
        let (_send, mut recv) = pair();
        recv.skipped_keys.insert(7, ([1u8; 32], [2u8; 12]));
        let bytes = bincode::serialize(&recv).unwrap();
        let restored: MessagingSession = bincode::deserialize(&bytes).unwrap();
        // skipped_keys is #[serde(skip)] → not persisted across restart.
        assert!(restored.skipped_keys.is_empty());
        assert_eq!(restored.chain_key, recv.chain_key);
        assert_eq!(restored.counter, recv.counter);
    }
}
