//! ZHTP Request/Response serialization
//!
//! Handles serialization of ZHTP protocol messages using CBOR format
//! and the ZHTP wire protocol frame format.
//!
//! # Wire Format
//!
//! ```text
//! +------+------+--------+---------+
//! | ZHTP | Ver  | Length | Payload |
//! +------+------+--------+---------+
//! | 4B   | 1B   | 4B BE  | N bytes |
//! +------+------+--------+---------+
//! ```
//!
//! - Magic: "ZHTP" (4 bytes)
//! - Version: 1 (1 byte)
//! - Length: Payload length in big-endian (4 bytes)
//! - Payload: CBOR-encoded request or response

use crate::error::{ClientError, Result};
use crate::ZHTP_WIRE_VERSION;
use serde::{Deserialize, Serialize};

/// ZHTP request message
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ZhtpRequest {
    /// HTTP-like method: "Get", "Post", "Put", "Delete", etc.
    pub method: String,
    /// Request URI
    pub uri: String,
    /// Protocol version (e.g., "ZHTP/1.0")
    pub version: String,
    /// Request headers
    pub headers: ZhtpHeaders,
    /// Request body
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Request timestamp (Unix seconds)
    pub timestamp: u64,
    /// Optional requester identity ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
}

impl ZhtpRequest {
    /// Create a new GET request
    pub fn get(uri: &str) -> Self {
        Self {
            method: "Get".into(),
            uri: uri.into(),
            version: "ZHTP/1.0".into(),
            headers: ZhtpHeaders::default(),
            body: Vec::new(),
            timestamp: current_timestamp(),
            requester: None,
        }
    }

    /// Create a new POST request
    pub fn post(uri: &str, body: Vec<u8>, content_type: &str) -> Self {
        let mut headers = ZhtpHeaders::default();
        headers.content_type = Some(content_type.into());
        headers.content_length = body.len() as u64;

        Self {
            method: "Post".into(),
            uri: uri.into(),
            version: "ZHTP/1.0".into(),
            headers,
            body,
            timestamp: current_timestamp(),
            requester: None,
        }
    }

    /// Create a new PUT request
    pub fn put(uri: &str, body: Vec<u8>, content_type: &str) -> Self {
        let mut req = Self::post(uri, body, content_type);
        req.method = "Put".into();
        req
    }

    /// Create a new DELETE request
    pub fn delete(uri: &str) -> Self {
        Self {
            method: "Delete".into(),
            uri: uri.into(),
            version: "ZHTP/1.0".into(),
            headers: ZhtpHeaders::default(),
            body: Vec::new(),
            timestamp: current_timestamp(),
            requester: None,
        }
    }

    /// Set the requester identity
    pub fn with_requester(mut self, requester: String) -> Self {
        self.requester = Some(requester);
        self
    }

    /// Set a custom header
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.custom.insert(key.into(), value.into());
        self
    }
}

/// ZHTP response message
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ZhtpResponse {
    /// HTTP-like status code (200, 404, 500, etc.)
    pub status: u16,
    /// Status text (e.g., "OK", "Not Found")
    pub status_text: String,
    /// Protocol version
    pub version: String,
    /// Response headers
    pub headers: ZhtpHeaders,
    /// Response body
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Response timestamp
    pub timestamp: u64,
}

impl ZhtpResponse {
    /// Check if response indicates success (2xx)
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Check if response indicates client error (4xx)
    pub fn is_client_error(&self) -> bool {
        self.status >= 400 && self.status < 500
    }

    /// Check if response indicates server error (5xx)
    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }

    /// Get body as UTF-8 string
    pub fn body_string(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| ClientError::SerializationError(e.to_string()))
    }

    /// Parse body as JSON
    pub fn body_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| ClientError::SerializationError(e.to_string()))
    }
}

/// ZHTP headers
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct ZhtpHeaders {
    /// Content type (e.g., "application/json")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Content length in bytes
    #[serde(default)]
    pub content_length: u64,

    /// Privacy level (0-100)
    #[serde(default = "default_privacy_level")]
    pub privacy_level: u8,

    /// Encryption method
    #[serde(default = "default_encryption")]
    pub encryption: String,

    /// DAO fee paid
    #[serde(default)]
    pub dao_fee: u64,

    /// Network fee paid
    #[serde(default)]
    pub network_fee: u64,

    /// Cache control directive
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,

    /// Custom headers
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub custom: std::collections::HashMap<String, String>,
}

fn default_privacy_level() -> u8 {
    100
}

fn default_encryption() -> String {
    "CRYSTALS-Kyber".into()
}

// ============================================================================
// Serialization Functions
// ============================================================================

/// Serialize a ZHTP request to CBOR bytes
pub fn serialize_request(request: &ZhtpRequest) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(request, &mut buf)?;
    Ok(buf)
}

/// Deserialize a ZHTP request from CBOR bytes
pub fn deserialize_request(data: &[u8]) -> Result<ZhtpRequest> {
    ciborium::from_reader(data).map_err(|e| ClientError::SerializationError(e.to_string()))
}

/// Serialize a ZHTP response to CBOR bytes
pub fn serialize_response(response: &ZhtpResponse) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(response, &mut buf)?;
    Ok(buf)
}

/// Deserialize a ZHTP response from CBOR bytes
pub fn deserialize_response(data: &[u8]) -> Result<ZhtpResponse> {
    ciborium::from_reader(data).map_err(|e| ClientError::SerializationError(e.to_string()))
}

// ============================================================================
// Wire Format Functions
// ============================================================================

/// ZHTP wire protocol magic bytes
pub const ZHTP_MAGIC: &[u8; 4] = b"ZHTP";

/// Create a ZHTP wire frame from payload bytes
///
/// Format: [ZHTP (4)] [version (1)] [length BE (4)] [payload]
pub fn create_zhtp_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + payload.len());

    // Magic
    frame.extend_from_slice(ZHTP_MAGIC);

    // Version
    frame.push(ZHTP_WIRE_VERSION);

    // Length (big-endian)
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());

    // Payload
    frame.extend_from_slice(payload);

    frame
}

/// Parse a ZHTP wire frame and extract the payload
///
/// Returns the payload bytes
pub fn parse_zhtp_frame(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 9 {
        return Err(ClientError::InvalidFormat(
            "Frame too short (minimum 9 bytes)".into(),
        ));
    }

    // Verify magic
    if &data[0..4] != ZHTP_MAGIC {
        return Err(ClientError::InvalidFormat(format!(
            "Invalid magic: expected 'ZHTP', got {:?}",
            &data[0..4]
        )));
    }

    // Check version
    let version = data[4];
    if version != ZHTP_WIRE_VERSION {
        // Log warning but continue (forward compatibility)
        tracing::warn!(
            "ZHTP wire version mismatch: expected {}, got {}",
            ZHTP_WIRE_VERSION,
            version
        );
    }

    // Get length
    let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;

    // Validate we have enough data
    if data.len() < 9 + length {
        return Err(ClientError::InvalidFormat(format!(
            "Frame truncated: expected {} payload bytes, got {}",
            length,
            data.len() - 9
        )));
    }

    Ok(data[9..9 + length].to_vec())
}

/// Create a complete ZHTP request frame
///
/// Serializes the request to CBOR and wraps in wire format
pub fn create_request_frame(request: &ZhtpRequest) -> Result<Vec<u8>> {
    let payload = serialize_request(request)?;
    Ok(create_zhtp_frame(&payload))
}

/// Parse a ZHTP request from a wire frame
pub fn parse_request_frame(data: &[u8]) -> Result<ZhtpRequest> {
    let payload = parse_zhtp_frame(data)?;
    deserialize_request(&payload)
}

/// Create a complete ZHTP response frame
pub fn create_response_frame(response: &ZhtpResponse) -> Result<Vec<u8>> {
    let payload = serialize_response(response)?;
    Ok(create_zhtp_frame(&payload))
}

/// Parse a ZHTP response from a wire frame
pub fn parse_response_frame(data: &[u8]) -> Result<ZhtpResponse> {
    let payload = parse_zhtp_frame(data)?;
    deserialize_response(&payload)
}

// ============================================================================
// Helpers
// ============================================================================

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_request() {
        let request = ZhtpRequest::get("/api/v1/test");

        let bytes = serialize_request(&request).unwrap();
        let restored = deserialize_request(&bytes).unwrap();

        assert_eq!(restored.method, request.method);
        assert_eq!(restored.uri, request.uri);
    }

    #[test]
    fn test_create_parse_frame() {
        let payload = b"test payload";
        let frame = create_zhtp_frame(payload);

        assert_eq!(&frame[0..4], b"ZHTP");
        assert_eq!(frame[4], ZHTP_WIRE_VERSION);

        let parsed = parse_zhtp_frame(&frame).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn test_request_frame_roundtrip() {
        let request = ZhtpRequest::post("/api/v1/data", b"hello world".to_vec(), "text/plain");

        let frame = create_request_frame(&request).unwrap();
        let restored = parse_request_frame(&frame).unwrap();

        assert_eq!(restored.method, "Post");
        assert_eq!(restored.uri, "/api/v1/data");
        assert_eq!(restored.body, b"hello world");
    }

    #[test]
    fn test_response_helpers() {
        let response = ZhtpResponse {
            status: 200,
            status_text: "OK".into(),
            version: "ZHTP/1.0".into(),
            headers: ZhtpHeaders::default(),
            body: Vec::new(),
            timestamp: 0,
        };

        assert!(response.is_success());
        assert!(!response.is_client_error());
        assert!(!response.is_server_error());
    }

    #[test]
    fn test_invalid_frame_magic() {
        let bad_frame = b"HTTP1234payload";
        assert!(parse_zhtp_frame(bad_frame).is_err());
    }

    #[test]
    fn test_truncated_frame() {
        let mut frame = create_zhtp_frame(b"test payload");
        frame.truncate(10); // Truncate payload
        assert!(parse_zhtp_frame(&frame).is_err());
    }
}
