//! Serialization format validation for cross-contract calls
//!
//! Ensures that serialized arguments match expected formats and are compatible
//! across different ABI versions and contract implementations.

use anyhow::{anyhow, Result};

/// Supported serialization formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SerializationFormat {
    /// Bincode format (Rust-native, compact)
    Bincode,
    /// JSON format (human-readable, cross-language)
    Json,
    /// MessagePack format (binary, cross-language)
    MessagePack,
    /// CBOR format (compact, cross-language)
    Cbor,
}

impl SerializationFormat {
    /// Parse format from string
    pub fn parse(format: &str) -> Result<Self> {
        match format.to_lowercase().as_str() {
            "bincode" => Ok(SerializationFormat::Bincode),
            "json" => Ok(SerializationFormat::Json),
            "msgpack" | "messagepack" => Ok(SerializationFormat::MessagePack),
            "cbor" => Ok(SerializationFormat::Cbor),
            _ => Err(anyhow!("Unknown serialization format: {}", format)),
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SerializationFormat::Bincode => "bincode",
            SerializationFormat::Json => "json",
            SerializationFormat::MessagePack => "msgpack",
            SerializationFormat::Cbor => "cbor",
        }
    }

    /// Check if format can be cross-compatible with another format
    pub fn is_compatible_with(&self, other: SerializationFormat) -> bool {
        // Bincode is not compatible with anything except itself (Rust-specific)
        if *self == SerializationFormat::Bincode || other == SerializationFormat::Bincode {
            return *self == other;
        }

        // JSON, MessagePack, and CBOR are all cross-language compatible
        match (*self, other) {
            (SerializationFormat::Json, SerializationFormat::Json) => true,
            (SerializationFormat::MessagePack, SerializationFormat::MessagePack) => true,
            (SerializationFormat::Cbor, SerializationFormat::Cbor) => true,
            // No cross-format compatibility (would require conversion layer)
            _ => false,
        }
    }
}

/// Serialization format validator
pub struct SerializationValidator;

impl SerializationValidator {
    /// Detect serialization format from byte data
    ///
    /// Uses magic bytes and structure to identify format:
    /// - JSON: starts with {, [, ", or whitespace+{/[
    /// - MessagePack: specific prefix bytes (0xdc, 0xdd, 0xc4-0xc6, etc.)
    /// - CBOR: recognized format with major types
    /// - Bincode: default fallback for unrecognized formats
    ///
    /// Note: MessagePack detection takes precedence over CBOR since they overlap
    pub fn detect_format(data: &[u8]) -> Result<SerializationFormat> {
        if data.is_empty() {
            return Err(anyhow!("Cannot detect format of empty data"));
        }

        // Try JSON detection first (most readable and specific)
        if Self::is_json(data) {
            return Ok(SerializationFormat::Json);
        }

        // Try MessagePack detection (has specific prefixes)
        if Self::is_messagepack(data) {
            return Ok(SerializationFormat::MessagePack);
        }

        // For now, if not JSON or MessagePack, default to bincode
        // CBOR detection is too similar to other formats to be reliable
        Ok(SerializationFormat::Bincode)
    }

    /// Check if data looks like JSON
    fn is_json(data: &[u8]) -> bool {
        let trimmed = Self::skip_whitespace(data);
        if trimmed.is_empty() {
            return false;
        }

        let first = trimmed[0];
        // JSON starts with {, [, ", null, true, false, or digit
        matches!(first, b'{' | b'[' | b'"' | b'n' | b't' | b'f' | b'0'..=b'9' | b'-')
    }

    /// Check if data looks like MessagePack
    fn is_messagepack(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let first = data[0];
        // MessagePack format prefixes
        match first {
            // Fixint (positive)
            0x00..=0x7f => true,
            // Fixmap
            0x80..=0x8f => true,
            // Fixarray
            0x90..=0x9f => true,
            // Fixstr
            0xa0..=0xbf => true,
            // null, false, true
            0xc0 | 0xc2 | 0xc3 => true,
            // bin8, bin16, bin32
            0xc4 | 0xc5 | 0xc6 => true,
            // uint8, uint16, uint32, uint64
            0xcc | 0xcd | 0xce | 0xcf => true,
            // int8, int16, int32, int64
            0xd0 | 0xd1 | 0xd2 | 0xd3 => true,
            // float32, float64
            0xca | 0xcb => true,
            // str8, str16, str32
            0xd9 | 0xda | 0xdb => true,
            // array16, array32
            0xdc | 0xdd => true,
            // map16, map32
            0xde | 0xdf => true,
            _ => false,
        }
    }

    /// Check if data looks like CBOR
    /// Note: Not currently used due to overlap with other format detection
    #[allow(dead_code)]
    fn is_cbor(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let first = data[0];
        // CBOR major types (top 3 bits)
        let major_type = (first >> 5) & 0x07;

        // All CBOR major types are valid
        // 0: unsigned integer
        // 1: negative integer
        // 2: byte string
        // 3: text string
        // 4: array
        // 5: map
        // 6: semantic tag
        // 7: simple/float
        major_type <= 7
    }

    /// Skip leading whitespace in byte array
    fn skip_whitespace(data: &[u8]) -> &[u8] {
        let start = data
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .unwrap_or(data.len());
        &data[start..]
    }

    /// Validate that serialized data matches expected format
    pub fn validate_format(data: &[u8], expected_format: SerializationFormat) -> Result<()> {
        let detected = Self::detect_format(data)?;

        if detected == expected_format {
            Ok(())
        } else {
            Err(anyhow!(
                "Format mismatch: expected {}, but data appears to be {}",
                expected_format.as_str(),
                detected.as_str()
            ))
        }
    }

    /// Validate compatibility between two format versions
    pub fn validate_format_compatibility(
        caller_format: SerializationFormat,
        callee_format: SerializationFormat,
    ) -> Result<()> {
        if caller_format.is_compatible_with(callee_format) {
            Ok(())
        } else {
            Err(anyhow!(
                "Serialization format incompatibility: {} cannot interop with {}",
                caller_format.as_str(),
                callee_format.as_str()
            ))
        }
    }

    /// Check endianness consistency in data
    /// (Bincode data should be consistent in endianness)
    pub fn validate_endianness_consistency(data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(anyhow!("Data too short for endianness check"));
        }

        // For now, this is a placeholder - actual endianness validation
        // would depend on the specific data format
        // JSON/MessagePack/CBOR handle endianness automatically
        // Bincode is little-endian on all platforms

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_format_valid() {
        assert_eq!(
            SerializationFormat::parse("bincode").unwrap(),
            SerializationFormat::Bincode
        );
        assert_eq!(
            SerializationFormat::parse("json").unwrap(),
            SerializationFormat::Json
        );
        assert_eq!(
            SerializationFormat::parse("msgpack").unwrap(),
            SerializationFormat::MessagePack
        );
        assert_eq!(
            SerializationFormat::parse("cbor").unwrap(),
            SerializationFormat::Cbor
        );
    }

    #[test]
    fn test_parse_format_case_insensitive() {
        assert_eq!(
            SerializationFormat::parse("BINCODE").unwrap(),
            SerializationFormat::Bincode
        );
        assert_eq!(
            SerializationFormat::parse("JSON").unwrap(),
            SerializationFormat::Json
        );
    }

    #[test]
    fn test_parse_format_invalid() {
        assert!(SerializationFormat::parse("invalid").is_err());
        assert!(SerializationFormat::parse("protobuf").is_err());
    }

    #[test]
    fn test_format_as_str() {
        assert_eq!(SerializationFormat::Bincode.as_str(), "bincode");
        assert_eq!(SerializationFormat::Json.as_str(), "json");
        assert_eq!(SerializationFormat::MessagePack.as_str(), "msgpack");
        assert_eq!(SerializationFormat::Cbor.as_str(), "cbor");
    }

    #[test]
    fn test_format_compatibility_same() {
        assert!(SerializationFormat::Json.is_compatible_with(SerializationFormat::Json));
        assert!(SerializationFormat::Bincode
            .is_compatible_with(SerializationFormat::Bincode));
    }

    #[test]
    fn test_format_compatibility_bincode_exclusive() {
        assert!(!SerializationFormat::Bincode
            .is_compatible_with(SerializationFormat::Json));
        assert!(!SerializationFormat::Json
            .is_compatible_with(SerializationFormat::Bincode));
    }

    #[test]
    fn test_format_compatibility_cross_language() {
        assert!(!SerializationFormat::Json
            .is_compatible_with(SerializationFormat::MessagePack));
        assert!(!SerializationFormat::MessagePack
            .is_compatible_with(SerializationFormat::Cbor));
    }

    #[test]
    fn test_detect_json_object() {
        let json = br#"{"key": "value"}"#;
        let detected = SerializationValidator::detect_format(json).unwrap();
        assert_eq!(detected, SerializationFormat::Json);
    }

    #[test]
    fn test_detect_json_array() {
        let json = b"[1, 2, 3]";
        let detected = SerializationValidator::detect_format(json).unwrap();
        assert_eq!(detected, SerializationFormat::Json);
    }

    #[test]
    fn test_detect_json_string() {
        let json = b"\"hello\"";
        let detected = SerializationValidator::detect_format(json).unwrap();
        assert_eq!(detected, SerializationFormat::Json);
    }

    #[test]
    fn test_detect_json_with_whitespace() {
        let json = b"  \n  {\"key\": \"value\"}";
        let detected = SerializationValidator::detect_format(json).unwrap();
        assert_eq!(detected, SerializationFormat::Json);
    }

    #[test]
    fn test_detect_json_null() {
        let json = b"null";
        let detected = SerializationValidator::detect_format(json).unwrap();
        assert_eq!(detected, SerializationFormat::Json);
    }

    #[test]
    fn test_detect_json_boolean() {
        let json = b"true";
        let detected = SerializationValidator::detect_format(json).unwrap();
        assert_eq!(detected, SerializationFormat::Json);
    }

    #[test]
    fn test_detect_json_number() {
        let json = b"12345";
        let detected = SerializationValidator::detect_format(json).unwrap();
        assert_eq!(detected, SerializationFormat::Json);
    }

    #[test]
    fn test_detect_messagepack_uint8() {
        let msgpack = vec![0xcc, 0x42]; // uint8(66)
        let detected = SerializationValidator::detect_format(&msgpack).unwrap();
        assert_eq!(detected, SerializationFormat::MessagePack);
    }

    #[test]
    fn test_detect_messagepack_fixint() {
        let msgpack = vec![0x42]; // fixint(66)
        let detected = SerializationValidator::detect_format(&msgpack).unwrap();
        assert_eq!(detected, SerializationFormat::MessagePack);
    }

    #[test]
    fn test_detect_messagepack_array() {
        let msgpack = vec![0xdc, 0x00, 0x03]; // array16 with 3 elements
        let detected = SerializationValidator::detect_format(&msgpack).unwrap();
        assert_eq!(detected, SerializationFormat::MessagePack);
    }

    #[test]
    fn test_detect_unknown_binary_defaults_to_bincode() {
        // Unknown binary data that doesn't match JSON/MessagePack patterns
        // should default to bincode. Use a byte sequence that's not valid
        // in MessagePack (reserved bytes in 0xc1, 0xc7-0xcb range with data)
        let unknown = vec![0xc1]; // Reserved/undefined in MessagePack
        let detected = SerializationValidator::detect_format(&unknown).unwrap();
        assert_eq!(detected, SerializationFormat::Bincode);
    }

    #[test]
    fn test_detect_messagepack_fixstr() {
        // MessagePack fixstr format (0xa0-0xbf prefix)
        let msgpack = vec![0xa5, 0x68, 0x65, 0x6c, 0x6c, 0x6f]; // fixstr "hello"
        let detected = SerializationValidator::detect_format(&msgpack).unwrap();
        assert_eq!(detected, SerializationFormat::MessagePack);
    }

    #[test]
    fn test_detect_messagepack_boolean() {
        // MessagePack false
        let msgpack = vec![0xc2];
        let detected = SerializationValidator::detect_format(&msgpack).unwrap();
        assert_eq!(detected, SerializationFormat::MessagePack);
    }

    #[test]
    fn test_detect_empty_data() {
        let result = SerializationValidator::detect_format(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_format_match() {
        let json = b"{\"a\": 1}";
        let result =
            SerializationValidator::validate_format(json, SerializationFormat::Json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_format_mismatch() {
        let json = b"{\"a\": 1}";
        let result = SerializationValidator::validate_format(json, SerializationFormat::Bincode);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_format_compatibility_same() {
        let result = SerializationValidator::validate_format_compatibility(
            SerializationFormat::Json,
            SerializationFormat::Json,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_format_compatibility_different() {
        let result = SerializationValidator::validate_format_compatibility(
            SerializationFormat::Json,
            SerializationFormat::Bincode,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_endianness_sufficient_data() {
        let data = vec![0u8; 16];
        let result = SerializationValidator::validate_endianness_consistency(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_endianness_insufficient_data() {
        let data = vec![0u8; 4];
        let result = SerializationValidator::validate_endianness_consistency(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_equality() {
        assert_eq!(SerializationFormat::Json, SerializationFormat::Json);
        assert_ne!(SerializationFormat::Json, SerializationFormat::Bincode);
    }

    #[test]
    fn test_format_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(SerializationFormat::Json);
        set.insert(SerializationFormat::Bincode);
        set.insert(SerializationFormat::Json); // Duplicate

        assert_eq!(set.len(), 2); // Only 2 unique formats
    }
}
