//! ZHTP Wire Protocol
//!
//! Binary wire format for ZhtpRequest/ZhtpResponse over QUIC streams.
//!
//! # Protocol Design
//!
//! - **Envelope**: Adds request_id for multiplexing, version for compatibility
//! - **Serialization**: CBOR (compact, schema-free, well-supported)
//! - **Framing**: Length-prefixed messages (4-byte big-endian length + payload)
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

/// Request envelope for wire transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRequestWire {
    /// Wire protocol version
    pub version: u16,
    /// Unique request ID for multiplexing (16 bytes UUID)
    pub request_id: [u8; 16],
    /// Request timestamp (milliseconds since epoch)
    pub timestamp_ms: u64,
    /// The actual ZHTP request
    pub request: ZhtpRequest,
}

impl ZhtpRequestWire {
    /// Create a new wire request with generated ID
    pub fn new(request: ZhtpRequest) -> Self {
        let mut request_id = [0u8; 16];
        getrandom::getrandom(&mut request_id).unwrap_or_else(|_| {
            // Fallback to timestamp-based ID if getrandom fails
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            request_id[..16].copy_from_slice(&ts.to_le_bytes());
        });

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            version: WIRE_VERSION,
            request_id,
            timestamp_ms,
            request,
        }
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
