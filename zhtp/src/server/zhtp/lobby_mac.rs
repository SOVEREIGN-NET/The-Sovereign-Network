//! Lobby auth — server-side HMAC channel binding (S6 of epic #2554).
//!
//! On every authenticated request from a Password (OPAQUE lobby) session
//! the client MUST include:
//!
//! - `X-OPAQUE-Seq`: monotonically increasing u64 (decimal ascii), unique
//!   per session_token. Server rejects `seq ≤ last_seen` as replay.
//! - `X-OPAQUE-Mac`: `HMAC-SHA-512(session_key, canonical_request)`
//!   truncated to the first 32 bytes, hex-encoded (64 lowercase chars).
//!
//! The `session_key` is the OPAQUE-derived 64-byte key from the login flow
//! (lives in `SessionManager::opaque_session_keys`).
//!
//! Canonical request layout (network wire contract — must match
//! `lib-client::opaque::canonical_request_bytes` byte-for-byte):
//!
//! ```text
//!   method_byte:    u8         (GET=0, POST=1, PUT=2, DELETE=3, PATCH=4, HEAD=5, OPTIONS=6)
//!   uri_len:        u32 big-endian
//!   uri:            uri_len bytes UTF-8
//!   body_len:       u32 big-endian
//!   body:           body_len bytes
//!   seq:            u64 big-endian
//! ```
//!
//! Key sessions are NOT subject to MAC verification — they're already
//! protected by Dilithium signatures via the UHP v2 layer.

use hmac::Mac;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest};
use subtle::ConstantTimeEq;

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// Wire-encoded byte for each method. Must match the client-side enum.
pub fn method_byte(m: &ZhtpMethod) -> Option<u8> {
    match m {
        ZhtpMethod::Get => Some(0),
        ZhtpMethod::Post => Some(1),
        ZhtpMethod::Put => Some(2),
        ZhtpMethod::Delete => Some(3),
        ZhtpMethod::Patch => Some(4),
        ZhtpMethod::Head => Some(5),
        ZhtpMethod::Options => Some(6),
        _ => None,
    }
}

/// Build the canonical bytes hashed by the MAC.
pub fn canonical_request_bytes(method: u8, uri: &[u8], body: &[u8], seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + uri.len() + 4 + body.len() + 8);
    out.push(method);
    out.extend_from_slice(&(uri.len() as u32).to_be_bytes());
    out.extend_from_slice(uri);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&seq.to_be_bytes());
    out
}

/// Compute the expected MAC (first 32 bytes of HMAC-SHA-512).
pub fn compute_mac(key: &[u8], method: u8, uri: &[u8], body: &[u8], seq: u64) -> [u8; 32] {
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
    mac.update(&canonical_request_bytes(method, uri, body, seq));
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Reason a lobby request failed channel-binding verification. Distinct
/// values so the caller can log diagnostics; the on-wire response always
/// collapses to 401 to avoid leaking which check rejected the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    MissingSeqHeader,
    MalformedSeqHeader,
    MissingMacHeader,
    MalformedMacHeader,
    UnsupportedMethod,
    NoSessionKey,
    ReplayOrOutOfOrder,
    MacMismatch,
}

/// Verify the per-request MAC + seq on a Password-session request.
///
/// The caller is responsible for having already established that the
/// request belongs to a Password (OPAQUE lobby) session and that the
/// session_key has been resolved from the SessionManager. Returns `Ok(())`
/// on success and a `VerifyError` otherwise. The seq counter is advanced
/// only on a fully successful verification.
pub async fn verify(
    request: &ZhtpRequest,
    token: &str,
    session_key: &[u8],
    session_manager: &crate::session_manager::SessionManager,
) -> Result<(), VerifyError> {
    let seq_str = request
        .headers
        .get("X-OPAQUE-Seq")
        .ok_or(VerifyError::MissingSeqHeader)?;
    let seq: u64 = seq_str
        .parse()
        .map_err(|_| VerifyError::MalformedSeqHeader)?;

    let mac_hex = request
        .headers
        .get("X-OPAQUE-Mac")
        .ok_or(VerifyError::MissingMacHeader)?;
    let mac_bytes = hex::decode(mac_hex).map_err(|_| VerifyError::MalformedMacHeader)?;
    if mac_bytes.len() != 32 {
        return Err(VerifyError::MalformedMacHeader);
    }
    let mut provided = [0u8; 32];
    provided.copy_from_slice(&mac_bytes);

    let mb = method_byte(&request.method).ok_or(VerifyError::UnsupportedMethod)?;

    let expected = compute_mac(
        session_key,
        mb,
        request.uri.as_bytes(),
        &request.body,
        seq,
    );

    if !bool::from(expected.ct_eq(&provided)) {
        return Err(VerifyError::MacMismatch);
    }

    // MAC is valid — only NOW commit the seq advance. Doing this earlier
    // would let a forged MAC burn a sequence number and DoS the session.
    if !session_manager.check_and_advance_seq(token, seq).await {
        return Err(VerifyError::ReplayOrOutOfOrder);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key32() -> Vec<u8> {
        (0..64u8).collect()
    }

    #[test]
    fn canonical_layout_stable() {
        let bytes = canonical_request_bytes(1, b"/api/v1/x", b"hi", 42);
        // method(1) + 4 + 9 + 4 + 2 + 8
        assert_eq!(bytes.len(), 1 + 4 + 9 + 4 + 2 + 8);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..5], &(9u32).to_be_bytes());
        assert_eq!(&bytes[5..14], b"/api/v1/x");
        assert_eq!(&bytes[14..18], &(2u32).to_be_bytes());
        assert_eq!(&bytes[18..20], b"hi");
        assert_eq!(&bytes[20..28], &(42u64).to_be_bytes());
    }

    #[test]
    fn mac_deterministic_for_same_inputs() {
        let k = key32();
        let a = compute_mac(&k, 0, b"/api/v1/chain/info", b"", 1);
        let b = compute_mac(&k, 0, b"/api/v1/chain/info", b"", 1);
        assert_eq!(a, b);
    }

    #[test]
    fn mac_changes_when_uri_changes() {
        let k = key32();
        let a = compute_mac(&k, 0, b"/api/v1/chain/info", b"", 1);
        let b = compute_mac(&k, 0, b"/api/v1/dao/proposals", b"", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn mac_changes_when_body_changes() {
        let k = key32();
        let a = compute_mac(&k, 1, b"/x", b"alpha", 1);
        let b = compute_mac(&k, 1, b"/x", b"beta", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn mac_changes_when_seq_changes() {
        let k = key32();
        let a = compute_mac(&k, 0, b"/x", b"", 1);
        let b = compute_mac(&k, 0, b"/x", b"", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn method_byte_round_trip() {
        assert_eq!(method_byte(&ZhtpMethod::Get), Some(0));
        assert_eq!(method_byte(&ZhtpMethod::Post), Some(1));
        assert_eq!(method_byte(&ZhtpMethod::Put), Some(2));
        assert_eq!(method_byte(&ZhtpMethod::Delete), Some(3));
        assert_eq!(method_byte(&ZhtpMethod::Patch), Some(4));
        assert_eq!(method_byte(&ZhtpMethod::Head), Some(5));
        assert_eq!(method_byte(&ZhtpMethod::Options), Some(6));
        assert_eq!(method_byte(&ZhtpMethod::Verify), None);
    }

    #[tokio::test]
    async fn seq_strict_monotonic() {
        let sm = crate::session_manager::SessionManager::new();
        assert!(sm.check_and_advance_seq("t", 1).await);
        assert!(sm.check_and_advance_seq("t", 2).await);
        // Replay (same)
        assert!(!sm.check_and_advance_seq("t", 2).await);
        // Out of order (lower)
        assert!(!sm.check_and_advance_seq("t", 1).await);
        // Forward still works
        assert!(sm.check_and_advance_seq("t", 100).await);
    }
}
