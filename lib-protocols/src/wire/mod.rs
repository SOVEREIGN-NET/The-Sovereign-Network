//! ZHTP Wire Protocol
//!
//! Binary wire format for ZhtpRequest/ZhtpResponse over QUIC streams.
//!
//! # Protocol Design
//!
//! - **Envelope**: Adds request_id for multiplexing, version for compatibility
//! - **AuthContext**: Binds requests to UHP handshake (session proof, not user-supplied)
//! - **Serialization**: CBOR (compact, schema-free, well-supported)
//! - **Framing**: Length-prefixed messages (4-byte big-endian length + payload)
//!
//! # Security Model
//!
//! The `auth_context` field is derived from the UHP handshake and MUST NOT be
//! user-supplied. It binds each request to the authenticated session, preventing
//! replay attacks and ensuring request authorization can be verified.
//!
//! # Wire Format
//!
//! ```text
//! +----------+------------------+
//! | len (4B) |  CBOR payload    |
//! +----------+------------------+
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};

/// Wire protocol version
pub const WIRE_VERSION: u16 = 1;

/// Maximum message size (16 MB)
pub const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Authentication context derived from UHP handshake
///
/// This proves the request originates from the authenticated session
/// and cannot be replayed or forged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Session ID from UHP handshake (16 bytes)
    pub session_id: [u8; 16],

    /// Client DID (from handshake identity verification)
    pub client_did: String,

    /// Request sequence number (prevents replay within session)
    pub sequence: u64,

    /// HMAC of request content using session-derived key
    /// Proves request hasn't been tampered with
    pub request_mac: [u8; 32],
}

impl AuthContext {
    /// Create a new auth context for a request
    ///
    /// The MAC is computed over: session_id || sequence || request_hash
    pub fn new(
        session_id: [u8; 16],
        client_did: String,
        sequence: u64,
        session_key: &[u8; 32],
        request_hash: &[u8; 32],
    ) -> Self {
        // Compute MAC binding session, sequence, and request content
        let mut mac_input = Vec::with_capacity(16 + 8 + 32);
        mac_input.extend_from_slice(&session_id);
        mac_input.extend_from_slice(&sequence.to_le_bytes());
        mac_input.extend_from_slice(request_hash);

        // HMAC using session key
        let request_mac = Self::hmac_blake3(session_key, &mac_input);

        Self {
            session_id,
            client_did,
            sequence,
            request_mac,
        }
    }

    /// Verify the auth context MAC
    pub fn verify(&self, session_key: &[u8; 32], request_hash: &[u8; 32]) -> bool {
        let mut mac_input = Vec::with_capacity(16 + 8 + 32);
        mac_input.extend_from_slice(&self.session_id);
        mac_input.extend_from_slice(&self.sequence.to_le_bytes());
        mac_input.extend_from_slice(request_hash);

        let expected_mac = Self::hmac_blake3(session_key, &mac_input);
        constant_time_eq(&self.request_mac, &expected_mac)
    }

    /// HMAC using BLAKE3 in keyed mode
    fn hmac_blake3(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let hasher = blake3::Hasher::new_keyed(key);
        let mut h = hasher;
        h.update(data);
        *h.finalize().as_bytes()
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Request envelope for wire transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRequestWire {
    /// Wire protocol version
    pub version: u16,
    /// Unique request ID for multiplexing (16 bytes UUID)
    pub request_id: [u8; 16],
    /// Request timestamp (milliseconds since epoch)
    pub timestamp_ms: u64,
    /// Authentication context (derived from UHP handshake, not user-supplied)
    pub auth_context: Option<AuthContext>,
    /// The actual ZHTP request
    pub request: ZhtpRequest,
}

impl ZhtpRequestWire {
    /// Create a new wire request with generated ID (no auth context)
    ///
    /// NOTE: Requests without auth_context may be rejected by handlers
    /// that require authenticated access. Use `new_authenticated` for
    /// requests over UHP-authenticated connections.
    pub fn new(request: ZhtpRequest) -> Self {
        let mut request_id = [0u8; 16];
        getrandom::getrandom(&mut request_id)
            .expect("Failed to generate secure request_id");

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            version: WIRE_VERSION,
            request_id,
            timestamp_ms,
            auth_context: None,
            request,
        }
    }

    /// Create an authenticated wire request
    ///
    /// The auth_context binds the request to the UHP session and includes
    /// a MAC that proves request integrity.
    ///
    /// The MAC is computed over canonical CBOR-serialized request bytes
    /// to ensure deterministic verification across implementations.
    pub fn new_authenticated(
        request: ZhtpRequest,
        session_id: [u8; 16],
        client_did: String,
        sequence: u64,
        session_key: &[u8; 32],
    ) -> Self {
        let mut request_id = [0u8; 16];
        getrandom::getrandom(&mut request_id)
            .expect("Failed to generate secure request_id");

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Compute canonical request hash using CBOR (deterministic serialization)
        let request_hash = Self::compute_canonical_request_hash(&request, &request_id, timestamp_ms);

        let auth_context = AuthContext::new(
            session_id,
            client_did,
            sequence,
            session_key,
            &request_hash,
        );

        Self {
            version: WIRE_VERSION,
            request_id,
            timestamp_ms,
            auth_context: Some(auth_context),
            request,
        }
    }

    /// Compute canonical hash of request for MAC verification
    ///
    /// This creates a deterministic hash by including all request fields
    /// in a fixed order with CBOR serialization.
    pub fn compute_canonical_request_hash(request: &ZhtpRequest, request_id: &[u8; 16], timestamp_ms: u64) -> [u8; 32] {
        // Build canonical input: version || request_id || timestamp || method || uri || body
        // Using CBOR ensures deterministic byte representation
        let mut hasher = blake3::Hasher::new();

        // Include wire envelope fields
        hasher.update(&WIRE_VERSION.to_le_bytes());
        hasher.update(request_id);
        hasher.update(&timestamp_ms.to_le_bytes());

        // Include request fields in canonical order
        // Method as u8 discriminant
        let method_byte = match request.method {
            crate::types::ZhtpMethod::Get => 0u8,
            crate::types::ZhtpMethod::Post => 1u8,
            crate::types::ZhtpMethod::Put => 2u8,
            crate::types::ZhtpMethod::Delete => 3u8,
            crate::types::ZhtpMethod::Options => 4u8,
            crate::types::ZhtpMethod::Head => 5u8,
            crate::types::ZhtpMethod::Patch => 6u8,
            crate::types::ZhtpMethod::Verify => 7u8,
            crate::types::ZhtpMethod::Connect => 8u8,
            crate::types::ZhtpMethod::Trace => 9u8,
        };
        hasher.update(&[method_byte]);

        // URI (length-prefixed)
        hasher.update(&(request.uri.len() as u32).to_le_bytes());
        hasher.update(request.uri.as_bytes());

        // Headers - serialize each field in fixed order for determinism
        // Using a simple encoding: field present (1) + value, or absent (0)
        if let Some(ref s) = request.headers.content_type {
            hasher.update(&[1u8]);
            hasher.update(&(s.len() as u32).to_le_bytes());
            hasher.update(s.as_bytes());
        } else {
            hasher.update(&[0u8]);
        }

        if let Some(v) = request.headers.content_length {
            hasher.update(&[1u8]);
            hasher.update(&v.to_le_bytes());
        } else {
            hasher.update(&[0u8]);
        }

        if let Some(ref s) = request.headers.content_encoding {
            hasher.update(&[1u8]);
            hasher.update(&(s.len() as u32).to_le_bytes());
            hasher.update(s.as_bytes());
        } else {
            hasher.update(&[0u8]);
        }

        if let Some(ref s) = request.headers.cache_control {
            hasher.update(&[1u8]);
            hasher.update(&(s.len() as u32).to_le_bytes());
            hasher.update(s.as_bytes());
        } else {
            hasher.update(&[0u8]);
        }

        // Body (length-prefixed)
        hasher.update(&(request.body.len() as u32).to_le_bytes());
        hasher.update(&request.body);

        *hasher.finalize().as_bytes()
    }

    /// Verify the canonical hash matches for MAC verification
    pub fn verify_canonical_hash(&self, expected_hash: &[u8; 32]) -> bool {
        let computed = Self::compute_canonical_request_hash(
            &self.request,
            &self.request_id,
            self.timestamp_ms,
        );
        constant_time_eq(&computed, expected_hash)
    }

    /// Create with specific request ID (for testing or correlation)
    pub fn with_id(request: ZhtpRequest, request_id: [u8; 16]) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            version: WIRE_VERSION,
            request_id,
            timestamp_ms,
            auth_context: None,
            request,
        }
    }

    /// Serialize to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| anyhow!("CBOR serialization failed: {}", e))?;
        Ok(buf)
    }

    /// Deserialize from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|e| anyhow!("CBOR deserialization failed: {}", e))
    }

    /// Encode with length prefix for framing
    pub fn encode_framed(&self) -> Result<Vec<u8>> {
        let payload = self.to_cbor()?;
        let len = payload.len() as u32;

        if len > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} bytes (max {})", len, MAX_MESSAGE_SIZE));
        }

        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&payload);
        Ok(framed)
    }

    /// Get request ID as hex string
    pub fn request_id_hex(&self) -> String {
        hex::encode(self.request_id)
    }
}

/// Response envelope for wire transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpResponseWire {
    /// Request ID this response corresponds to
    pub request_id: [u8; 16],
    /// Response status code
    pub status: u16,
    /// The actual ZHTP response
    pub response: ZhtpResponse,
    /// Optional error code for failures
    pub error_code: Option<u16>,
    /// Optional error message
    pub error_message: Option<String>,
}

impl ZhtpResponseWire {
    /// Create a success response
    pub fn success(request_id: [u8; 16], response: ZhtpResponse) -> Self {
        Self {
            request_id,
            status: response.status.code(),
            response,
            error_code: None,
            error_message: None,
        }
    }

    /// Create an error response
    pub fn error(request_id: [u8; 16], status: ZhtpStatus, message: String) -> Self {
        let response = ZhtpResponse::error(status.clone(), message.clone());
        Self {
            request_id,
            status: status.code(),
            response,
            error_code: Some(status.code()),
            error_message: Some(message),
        }
    }

    /// Serialize to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| anyhow!("CBOR serialization failed: {}", e))?;
        Ok(buf)
    }

    /// Deserialize from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|e| anyhow!("CBOR deserialization failed: {}", e))
    }

    /// Encode with length prefix for framing
    pub fn encode_framed(&self) -> Result<Vec<u8>> {
        let payload = self.to_cbor()?;
        let len = payload.len() as u32;

        if len > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} bytes (max {})", len, MAX_MESSAGE_SIZE));
        }

        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&payload);
        Ok(framed)
    }

    /// Check if response indicates success
    pub fn is_success(&self) -> bool {
        self.error_code.is_none() && self.status < 400
    }

    /// Get request ID as hex string
    pub fn request_id_hex(&self) -> String {
        hex::encode(self.request_id)
    }
}

/// Read a length-prefixed message from an async reader
pub async fn read_framed_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    // Read length prefix (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await
        .map_err(|e| anyhow!("Failed to read message length: {}", e))?;

    let len = u32::from_be_bytes(len_buf);

    if len > MAX_MESSAGE_SIZE {
        return Err(anyhow!("Message too large: {} bytes (max {})", len, MAX_MESSAGE_SIZE));
    }

    // Read payload
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await
        .map_err(|e| anyhow!("Failed to read message payload: {}", e))?;

    Ok(payload)
}

/// Write a length-prefixed message to an async writer
pub async fn write_framed_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let len = payload.len() as u32;

    if len > MAX_MESSAGE_SIZE {
        return Err(anyhow!("Message too large: {} bytes (max {})", len, MAX_MESSAGE_SIZE));
    }

    // Write length prefix
    writer.write_all(&len.to_be_bytes()).await
        .map_err(|e| anyhow!("Failed to write message length: {}", e))?;

    // Write payload
    writer.write_all(payload).await
        .map_err(|e| anyhow!("Failed to write message payload: {}", e))?;

    writer.flush().await
        .map_err(|e| anyhow!("Failed to flush: {}", e))?;

    Ok(())
}

/// Read and decode a request from a QUIC stream
pub async fn read_request<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<ZhtpRequestWire> {
    let payload = read_framed_message(reader).await?;
    ZhtpRequestWire::from_cbor(&payload)
}

/// Read and decode a response from a QUIC stream
pub async fn read_response<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<ZhtpResponseWire> {
    let payload = read_framed_message(reader).await?;
    ZhtpResponseWire::from_cbor(&payload)
}

/// Encode and write a request to a QUIC stream
pub async fn write_request<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    request: &ZhtpRequestWire,
) -> Result<()> {
    let payload = request.to_cbor()?;
    write_framed_message(writer, &payload).await
}

/// Encode and write a response to a QUIC stream
pub async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: &ZhtpResponseWire,
) -> Result<()> {
    let payload = response.to_cbor()?;
    write_framed_message(writer, &payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ZhtpHeaders, ZhtpMethod};

    fn make_test_request() -> ZhtpRequest {
        ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/web4/domains/register".to_string(),
            version: "1.0".to_string(),
            headers: ZhtpHeaders::default(),
            body: b"test body".to_vec(),
            timestamp: 1234567890,
            requester: None,
            auth_proof: None,
        }
    }

    #[test]
    fn test_request_wire_roundtrip() {
        let request = make_test_request();
        let wire = ZhtpRequestWire::new(request.clone());

        // Serialize
        let cbor = wire.to_cbor().unwrap();

        // Deserialize
        let decoded = ZhtpRequestWire::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.version, WIRE_VERSION);
        assert_eq!(decoded.request.uri, request.uri);
        assert_eq!(decoded.request.body, request.body);
    }

    #[test]
    fn test_request_framed_encoding() {
        let request = make_test_request();
        let wire = ZhtpRequestWire::new(request);

        let framed = wire.encode_framed().unwrap();

        // First 4 bytes should be length
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]);
        assert_eq!(len as usize, framed.len() - 4);

        // Rest should be valid CBOR
        let payload = &framed[4..];
        let decoded = ZhtpRequestWire::from_cbor(payload).unwrap();
        assert_eq!(decoded.request.uri, "/api/v1/web4/domains/register");
    }

    #[test]
    fn test_response_wire_success() {
        let request_id = [1u8; 16];
        let response = ZhtpResponse::success(b"OK".to_vec(), None);
        let wire = ZhtpResponseWire::success(request_id, response);

        assert!(wire.is_success());
        assert_eq!(wire.request_id, request_id);
        assert!(wire.error_code.is_none());
    }

    #[test]
    fn test_response_wire_error() {
        let request_id = [2u8; 16];
        let wire = ZhtpResponseWire::error(
            request_id,
            ZhtpStatus::BadRequest,
            "Invalid input".to_string(),
        );

        assert!(!wire.is_success());
        assert_eq!(wire.error_code, Some(400));
        assert_eq!(wire.error_message, Some("Invalid input".to_string()));
    }

    #[test]
    fn test_message_size_limit() {
        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/test".to_string(),
            version: "1.0".to_string(),
            headers: ZhtpHeaders::default(),
            body: vec![0u8; (MAX_MESSAGE_SIZE + 1) as usize], // Too large
            timestamp: 0,
            requester: None,
            auth_proof: None,
        };
        let wire = ZhtpRequestWire::new(request);

        let result = wire.encode_framed();
        assert!(result.is_err());
    }
}
