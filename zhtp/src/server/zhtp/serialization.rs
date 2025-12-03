//! ZHTP Message Serialization
//!
//! Binary serialization for ZHTP requests and responses over QUIC streams.
//! Uses bincode for efficient serialization with magic bytes for protocol identification.

use anyhow::{Result, Context};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse};

/// ZHTP protocol magic bytes
pub const ZHTP_MAGIC: &[u8; 4] = b"ZHTP";

/// ZHTP protocol version
pub const ZHTP_VERSION: u8 = 1;

/// Maximum message size (10 MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Serialize a ZHTP request with protocol header
pub fn serialize_request(request: &ZhtpRequest) -> Result<Vec<u8>> {
    // Serialize the request body
    let body = bincode::serialize(request)
        .context("Failed to serialize ZhtpRequest")?;
    
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

/// Deserialize a ZHTP request from bytes
pub fn deserialize_request(data: &[u8]) -> Result<ZhtpRequest> {
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
    
    // Deserialize request
    let request: ZhtpRequest = bincode::deserialize(&data[9..9 + length])
        .context("Failed to deserialize ZhtpRequest")?;
    
    Ok(request)
}

/// Serialize a ZHTP response with protocol header
pub fn serialize_response(response: &ZhtpResponse) -> Result<Vec<u8>> {
    // Serialize the response body
    let body = bincode::serialize(response)
        .context("Failed to serialize ZhtpResponse")?;
    
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

/// Deserialize a ZHTP response from bytes
pub fn deserialize_response(data: &[u8]) -> Result<ZhtpResponse> {
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
    
    // Deserialize response
    let response: ZhtpResponse = bincode::deserialize(&data[9..9 + length])
        .context("Failed to deserialize ZhtpResponse")?;
    
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_protocols::types::{ZhtpMethod, ZhtpHeaders};

    #[test]
    fn test_request_serialization_roundtrip() {
        let request = ZhtpRequest {
            method: ZhtpMethod::Get,
            uri: "/api/v1/test".to_string(),
            headers: ZhtpHeaders::new(),
            body: b"test data".to_vec(),
            timestamp: 1234567890,
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        };

        let serialized = serialize_request(&request).unwrap();
        
        // Check magic bytes
        assert_eq!(&serialized[0..4], ZHTP_MAGIC);
        
        // Check version
        assert_eq!(serialized[4], ZHTP_VERSION);
        
        // Deserialize
        let deserialized = deserialize_request(&serialized).unwrap();
        
        assert_eq!(deserialized.method, request.method);
        assert_eq!(deserialized.uri, request.uri);
        assert_eq!(deserialized.body, request.body);
    }

    #[test]
    fn test_response_serialization_roundtrip() {
        let response = ZhtpResponse::success(b"response data".to_vec(), None);

        let serialized = serialize_response(&response).unwrap();

        // Check magic bytes
        assert_eq!(&serialized[0..4], ZHTP_MAGIC);

        // Check version
        assert_eq!(serialized[4], ZHTP_VERSION);

        // Deserialize
        let deserialized = deserialize_response(&serialized).unwrap();

        assert_eq!(deserialized.status, response.status);
        assert_eq!(deserialized.body, response.body);
        assert_eq!(deserialized.timestamp, response.timestamp);
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
    fn test_message_too_large() {
        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/test".to_string(),
            headers: ZhtpHeaders::new(),
            body: vec![0; MAX_MESSAGE_SIZE + 1], // Too large
            timestamp: 0,
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        };

        let result = serialize_request(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Request too large"));
    }
}
