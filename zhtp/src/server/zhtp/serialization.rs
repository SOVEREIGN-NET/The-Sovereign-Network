//! ZHTP Message Serialization
//!
//! Multi-format serialization for ZHTP requests and responses over QUIC streams.
//! Supports:
//! - CBOR (Concise Binary Object Representation) - efficient binary, cross-platform
//! - JSON - human-readable, widely supported
//! - Bincode - Rust-specific binary, for internal/mesh communication
//!
//! Wire format: ZHTP magic (4 bytes) + version (1 byte) + length (4 bytes BE) + payload
//! The payload format is auto-detected from content.

use anyhow::{Result, Context};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse};
use tracing::{debug, warn};

/// ZHTP protocol magic bytes
pub const ZHTP_MAGIC: &[u8; 4] = b"ZHTP";

/// ZHTP protocol version
pub const ZHTP_VERSION: u8 = 1;

/// Maximum message size (10 MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Payload format detected from content
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// CBOR - Concise Binary Object Representation
    Cbor,
    /// JSON - JavaScript Object Notation
    Json,
    /// Bincode - Rust binary serialization (legacy/internal)
    Bincode,
}

impl PayloadFormat {
    /// Detect payload format from first bytes
    pub fn detect(data: &[u8]) -> Self {
        if data.is_empty() {
            return PayloadFormat::Bincode; // Default fallback
        }

        let first_byte = data[0];

        // JSON detection: starts with { or [ (possibly with whitespace)
        // Check first non-whitespace byte
        let first_non_ws = data.iter()
            .find(|&&b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
            .copied()
            .unwrap_or(0);

        if first_non_ws == b'{' || first_non_ws == b'[' {
            return PayloadFormat::Json;
        }

        // CBOR detection: map or array major types
        // Major type 5 (map): 0xa0-0xbf, or 0xb8-0xbb for larger
        // Major type 4 (array): 0x80-0x9f, or 0x98-0x9b for larger
        // We expect requests/responses to be maps (objects)
        let major_type = first_byte >> 5;
        if major_type == 5 || major_type == 4 {
            return PayloadFormat::Cbor;
        }

        // Bincode fallback (legacy format)
        // Bincode typically starts with small numbers for enum variants
        PayloadFormat::Bincode
    }
}

/// Serialize a ZHTP request with protocol header (default: CBOR)
pub fn serialize_request(request: &ZhtpRequest) -> Result<Vec<u8>> {
    serialize_request_with_format(request, PayloadFormat::Cbor)
}

/// Serialize a ZHTP request with specific format
pub fn serialize_request_with_format(request: &ZhtpRequest, format: PayloadFormat) -> Result<Vec<u8>> {
    let body = match format {
        PayloadFormat::Cbor => {
            let mut buf = Vec::new();
            ciborium::into_writer(request, &mut buf)
                .context("Failed to serialize ZhtpRequest as CBOR")?;
            buf
        }
        PayloadFormat::Json => {
            serde_json::to_vec(request)
                .context("Failed to serialize ZhtpRequest as JSON")?
        }
        PayloadFormat::Bincode => {
            bincode::serialize(request)
                .context("Failed to serialize ZhtpRequest as bincode")?
        }
    };

    if body.len() > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!("Request too large: {} bytes (max: {} bytes)",
            body.len(), MAX_MESSAGE_SIZE));
    }

    // Build message with header
    let mut message = Vec::with_capacity(9 + body.len());

    // Magic bytes (4 bytes)
    message.extend_from_slice(ZHTP_MAGIC);

    // Version (1 byte)
    message.push(ZHTP_VERSION);

    // Message length (4 bytes, big-endian)
    message.extend_from_slice(&(body.len() as u32).to_be_bytes());

    // Request body
    message.extend_from_slice(&body);

    Ok(message)
}

/// Deserialize a ZHTP request from bytes, auto-detecting format
/// Returns the request and the detected format (for responding in same format)
pub fn deserialize_request_with_format(data: &[u8]) -> Result<(ZhtpRequest, PayloadFormat)> {
    // Validate minimum size
    if data.len() < 9 {
        return Err(anyhow::anyhow!("Message too short: {} bytes (min: 9)", data.len()));
    }

    // Validate magic bytes
    if &data[0..4] != ZHTP_MAGIC {
        return Err(anyhow::anyhow!("Invalid ZHTP magic bytes"));
    }

    // Validate version
    let version = data[4];
    if version != ZHTP_VERSION {
        return Err(anyhow::anyhow!("Unsupported ZHTP version: {}", version));
    }

    // Parse message length
    let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;

    // Validate length
    if length > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!("Message too large: {} bytes (max: {})",
            length, MAX_MESSAGE_SIZE));
    }

    if data.len() < 9 + length {
        return Err(anyhow::anyhow!("Incomplete message: expected {} bytes, got {}",
            9 + length, data.len()));
    }

    let payload = &data[9..9 + length];

    // Detect format and deserialize
    let format = PayloadFormat::detect(payload);
    debug!("Detected payload format: {:?}", format);

    let request = match format {
        PayloadFormat::Cbor => {
            ciborium::from_reader(payload)
                .context("Failed to deserialize ZhtpRequest from CBOR")?
        }
        PayloadFormat::Json => {
            serde_json::from_slice(payload)
                .context("Failed to deserialize ZhtpRequest from JSON")?
        }
        PayloadFormat::Bincode => {
            bincode::deserialize(payload)
                .context("Failed to deserialize ZhtpRequest from bincode")?
        }
    };

    Ok((request, format))
}

/// Deserialize a ZHTP request from bytes (legacy API, returns request only)
pub fn deserialize_request(data: &[u8]) -> Result<ZhtpRequest> {
    deserialize_request_with_format(data).map(|(req, _)| req)
}

/// Serialize a ZHTP response with protocol header (default: CBOR)
pub fn serialize_response(response: &ZhtpResponse) -> Result<Vec<u8>> {
    serialize_response_with_format(response, PayloadFormat::Cbor)
}

/// Serialize a ZHTP response with specific format
pub fn serialize_response_with_format(response: &ZhtpResponse, format: PayloadFormat) -> Result<Vec<u8>> {
    let body = match format {
        PayloadFormat::Cbor => {
            let mut buf = Vec::new();
            ciborium::into_writer(response, &mut buf)
                .context("Failed to serialize ZhtpResponse as CBOR")?;
            buf
        }
        PayloadFormat::Json => {
            serde_json::to_vec(response)
                .context("Failed to serialize ZhtpResponse as JSON")?
        }
        PayloadFormat::Bincode => {
            bincode::serialize(response)
                .context("Failed to serialize ZhtpResponse as bincode")?
        }
    };

    if body.len() > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!("Response too large: {} bytes (max: {} bytes)",
            body.len(), MAX_MESSAGE_SIZE));
    }

    // Build message with header
    let mut message = Vec::with_capacity(9 + body.len());

    // Magic bytes (4 bytes)
    message.extend_from_slice(ZHTP_MAGIC);

    // Version (1 byte)
    message.push(ZHTP_VERSION);

    // Message length (4 bytes, big-endian)
    message.extend_from_slice(&(body.len() as u32).to_be_bytes());

    // Response body
    message.extend_from_slice(&body);

    Ok(message)
}

/// Deserialize a ZHTP response from bytes, auto-detecting format
pub fn deserialize_response_with_format(data: &[u8]) -> Result<(ZhtpResponse, PayloadFormat)> {
    // Validate minimum size
    if data.len() < 9 {
        return Err(anyhow::anyhow!("Message too short: {} bytes (min: 9)", data.len()));
    }

    // Validate magic bytes
    if &data[0..4] != ZHTP_MAGIC {
        return Err(anyhow::anyhow!("Invalid ZHTP magic bytes"));
    }

    // Validate version
    let version = data[4];
    if version != ZHTP_VERSION {
        return Err(anyhow::anyhow!("Unsupported ZHTP version: {}", version));
    }

    // Parse message length
    let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;

    // Validate length
    if length > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!("Message too large: {} bytes (max: {})",
            length, MAX_MESSAGE_SIZE));
    }

    if data.len() < 9 + length {
        return Err(anyhow::anyhow!("Incomplete message: expected {} bytes, got {}",
            9 + length, data.len()));
    }

    let payload = &data[9..9 + length];

    // Detect format and deserialize
    let format = PayloadFormat::detect(payload);

    let response = match format {
        PayloadFormat::Cbor => {
            ciborium::from_reader(payload)
                .context("Failed to deserialize ZhtpResponse from CBOR")?
        }
        PayloadFormat::Json => {
            serde_json::from_slice(payload)
                .context("Failed to deserialize ZhtpResponse from JSON")?
        }
        PayloadFormat::Bincode => {
            bincode::deserialize(payload)
                .context("Failed to deserialize ZhtpResponse from bincode")?
        }
    };

    Ok((response, format))
}

/// Deserialize a ZHTP response from bytes (legacy API)
pub fn deserialize_response(data: &[u8]) -> Result<ZhtpResponse> {
    deserialize_response_with_format(data).map(|(resp, _)| resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_protocols::types::{ZhtpMethod, ZhtpHeaders, ZhtpStatus};

    fn create_test_request() -> ZhtpRequest {
        ZhtpRequest {
            method: ZhtpMethod::Get,
            uri: "/api/v1/test".to_string(),
            headers: ZhtpHeaders::new(),
            body: b"test data".to_vec(),
            timestamp: 1234567890,
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        }
    }

    #[test]
    fn test_cbor_request_roundtrip() {
        let request = create_test_request();

        let serialized = serialize_request_with_format(&request, PayloadFormat::Cbor).unwrap();

        // Check header
        assert_eq!(&serialized[0..4], ZHTP_MAGIC);
        assert_eq!(serialized[4], ZHTP_VERSION);

        // Deserialize
        let (deserialized, format) = deserialize_request_with_format(&serialized).unwrap();

        assert_eq!(format, PayloadFormat::Cbor);
        assert_eq!(deserialized.method, request.method);
        assert_eq!(deserialized.uri, request.uri);
        assert_eq!(deserialized.body, request.body);
    }

    #[test]
    fn test_json_request_roundtrip() {
        let request = create_test_request();

        let serialized = serialize_request_with_format(&request, PayloadFormat::Json).unwrap();

        // Check header
        assert_eq!(&serialized[0..4], ZHTP_MAGIC);

        // Deserialize
        let (deserialized, format) = deserialize_request_with_format(&serialized).unwrap();

        assert_eq!(format, PayloadFormat::Json);
        assert_eq!(deserialized.method, request.method);
        assert_eq!(deserialized.uri, request.uri);
    }

    #[test]
    fn test_bincode_request_roundtrip() {
        let request = create_test_request();

        let serialized = serialize_request_with_format(&request, PayloadFormat::Bincode).unwrap();

        // Check header
        assert_eq!(&serialized[0..4], ZHTP_MAGIC);

        // Deserialize
        let (deserialized, format) = deserialize_request_with_format(&serialized).unwrap();

        // Note: bincode detection is a fallback, might be detected as such
        assert_eq!(deserialized.method, request.method);
        assert_eq!(deserialized.uri, request.uri);
    }

    #[test]
    fn test_cbor_response_roundtrip() {
        let response = ZhtpResponse::success(b"response data".to_vec(), None);

        let serialized = serialize_response_with_format(&response, PayloadFormat::Cbor).unwrap();

        // Check header
        assert_eq!(&serialized[0..4], ZHTP_MAGIC);

        // Deserialize
        let (deserialized, format) = deserialize_response_with_format(&serialized).unwrap();

        assert_eq!(format, PayloadFormat::Cbor);
        assert_eq!(deserialized.status, response.status);
        assert_eq!(deserialized.body, response.body);
    }

    #[test]
    fn test_json_response_roundtrip() {
        let response = ZhtpResponse::success(b"response data".to_vec(), None);

        let serialized = serialize_response_with_format(&response, PayloadFormat::Json).unwrap();

        // Deserialize
        let (deserialized, format) = deserialize_response_with_format(&serialized).unwrap();

        assert_eq!(format, PayloadFormat::Json);
        assert_eq!(deserialized.status, response.status);
    }

    #[test]
    fn test_format_detection() {
        // CBOR map (major type 5)
        assert_eq!(PayloadFormat::detect(&[0xa0]), PayloadFormat::Cbor);
        assert_eq!(PayloadFormat::detect(&[0xbf]), PayloadFormat::Cbor);

        // JSON object
        assert_eq!(PayloadFormat::detect(b"{\"key\":\"value\"}"), PayloadFormat::Json);
        assert_eq!(PayloadFormat::detect(b"  {\"key\":\"value\"}"), PayloadFormat::Json);

        // JSON array
        assert_eq!(PayloadFormat::detect(b"[1,2,3]"), PayloadFormat::Json);

        // Bincode (small numbers = enum variants)
        assert_eq!(PayloadFormat::detect(&[0x00, 0x01, 0x02]), PayloadFormat::Bincode);
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let mut data = vec![0; 100];
        data[0..4].copy_from_slice(b"FAIL");

        let result = deserialize_request(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid ZHTP magic bytes"));
    }

    #[test]
    fn test_invalid_version() {
        let mut data = vec![0; 100];
        data[0..4].copy_from_slice(ZHTP_MAGIC);
        data[4] = 99; // Invalid version

        let result = deserialize_request(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported ZHTP version"));
    }

    #[test]
    fn test_message_too_short() {
        let data = vec![0; 5]; // Less than 9 bytes
        let result = deserialize_request(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }
}
