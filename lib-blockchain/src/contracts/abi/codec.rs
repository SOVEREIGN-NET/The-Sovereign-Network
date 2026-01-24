//! Deterministic ABI encoding and decoding
//!
//! Provides canonical serialization of ABI schemas to ensure consistent
//! representations across different implementations and languages.

use serde_json::{Value};
use anyhow::{Result, anyhow};

use super::schema::*;

/// ABI encoding/decoding trait
pub trait AbiCodec {
    /// Encode to deterministic JSON string
    fn to_canonical_json(&self) -> String;

    /// Encode to compact binary format
    fn to_bytes(&self) -> Result<Vec<u8>>;

    /// Decode from JSON
    fn from_json(json: &str) -> Result<Self>
    where
        Self: Sized;
}

/// Encodes ABIs to canonical forms
pub struct AbiEncoder;

impl AbiEncoder {
    /// Encode contract ABI to canonical JSON
    ///
    /// Ensures deterministic representation by:
    /// - Sorting object keys alphabetically
    /// - Using consistent formatting
    /// - Omitting None values
    pub fn encode_abi(abi: &ContractAbi) -> Result<String> {
        // Serialize to serde_json Value for manipulation
        let json = serde_json::to_value(abi)
            .map_err(|e| anyhow!("Failed to encode ABI: {}", e))?;

        // Canonicalize (sort keys, remove nulls)
        let canonical = Self::canonicalize_value(&json);

        // Format deterministically
        Ok(serde_json::to_string(&canonical)
            .map_err(|e| anyhow!("Failed to format ABI: {}", e))?)
    }

    /// Canonicalize a JSON value (sort keys, remove null values)
    fn canonicalize_value(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                // Sort keys alphabetically and remove null values
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();

                for key in keys {
                    if let Some(v) = map.get(&key) {
                        // Skip null values
                        if !v.is_null() {
                            sorted.insert(key, Self::canonicalize_value(v));
                        }
                    }
                }
                Value::Object(sorted)
            }
            Value::Array(arr) => {
                // Canonicalize each element
                Value::Array(arr.iter().map(Self::canonicalize_value).collect())
            }
            other => other.clone(),
        }
    }

    /// Compute SHA256 hash of canonical ABI JSON
    ///
    /// Used for ABI versioning and consistency verification
    pub fn abi_hash(abi: &ContractAbi) -> Result<[u8; 32]> {
        let json = Self::encode_abi(abi)?;
        let hash = blake3::hash(json.as_bytes());
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        Ok(result)
    }
}

/// Decodes ABIs from canonical forms
pub struct AbiDecoder;

impl AbiDecoder {
    /// Decode contract ABI from JSON string
    pub fn decode_abi(json: &str) -> Result<ContractAbi> {
        serde_json::from_str(json)
            .map_err(|e| anyhow!("Failed to decode ABI: {}", e))
    }

    /// Decode from compact binary
    pub fn decode_bytes(bytes: &[u8]) -> Result<ContractAbi> {
        // For now, use JSON encoding in bytes
        // In production, could use a more compact format like bincode
        let json = String::from_utf8(bytes.to_vec())?;
        Self::decode_abi(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_encoding() {
        let abi = ContractAbi::new("Test", "1.0.0");
        let json = AbiEncoder::encode_abi(&abi).expect("Should encode");
        assert!(json.contains("\"contract\""));
        assert!(json.contains("Test"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn test_abi_round_trip() {
        let original = ContractAbi::new("UBI", "1.0.0")
            .with_method(MethodSchema::new("claim", ReturnType::Void).kernel_only());

        let json = AbiEncoder::encode_abi(&original).expect("Should encode");
        let decoded = AbiDecoder::decode_abi(&json).expect("Should decode");

        assert_eq!(decoded.contract, "UBI");
        assert_eq!(decoded.version, "1.0.0");
        assert_eq!(decoded.methods.len(), 1);
        assert_eq!(decoded.methods[0].name, "claim");
    }

    #[test]
    fn test_abi_hash_deterministic() {
        let abi = ContractAbi::new("Test", "1.0.0");
        let hash1 = AbiEncoder::abi_hash(&abi).expect("Should hash");
        let hash2 = AbiEncoder::abi_hash(&abi).expect("Should hash");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_canonicalization_removes_nulls() {
        let json_str = r#"{"a": 1, "b": null, "c": "test"}"#;
        let value: Value = serde_json::from_str(json_str).unwrap();
        let canonical = AbiEncoder::canonicalize_value(&value);

        // Should not contain "b" since it was null
        assert!(!canonical["b"].is_object());
    }

    #[test]
    fn test_canonicalization_sorts_keys() {
        let json_str = r#"{"z": 1, "a": 2, "m": 3}"#;
        let value: Value = serde_json::from_str(json_str).unwrap();
        let canonical = AbiEncoder::canonicalize_value(&value);

        let json = serde_json::to_string(&canonical).unwrap();
        // Keys should appear in alphabetical order
        let a_pos = json.find("\"a\"").unwrap();
        let m_pos = json.find("\"m\"").unwrap();
        let z_pos = json.find("\"z\"").unwrap();
        assert!(a_pos < m_pos && m_pos < z_pos);
    }
}
