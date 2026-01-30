use blake3;

/// General purpose data hashing function
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Generate ZHTP native token ID
pub fn generate_lib_token_id() -> [u8; 32] {
    blake3::hash(b"ZHTP_NATIVE_TOKEN").into()
}

/// Generate custom token ID based on name and symbol
///
/// SECURITY: Uses length-prefixing to prevent collisions.
/// Without length-prefixing, "AB" + "CD" would hash the same as "ABC" + "D".
/// With length-prefixing: "TOKEN:2:AB:2:CD" != "TOKEN:3:ABC:1:D"
pub fn generate_custom_token_id(name: &str, symbol: &str) -> [u8; 32] {
    // Length-prefix to prevent collisions: "AB"+"CD" != "ABC"+"D"
    let token_data = format!(
        "TOKEN:{}:{}:{}:{}",
        name.len(),
        name.to_uppercase(),
        symbol.len(),
        symbol.to_uppercase()
    );
    blake3::hash(token_data.as_bytes()).into()
}

/// Generate contract ID from multiple components
pub fn generate_contract_id(components: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for component in components {
        hasher.update(component);
    }
    hasher.finalize().into()
}

/// Generate message ID for Whisper messages
pub fn generate_message_id(sender_key: &[u8], timestamp_nanos: u128) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(sender_key);
    data.extend_from_slice(&timestamp_nanos.to_le_bytes());
    blake3::hash(&data).into()
}

/// Generate contact ID from owner and contact public key
pub fn generate_contact_id(owner_key: &[u8], contact_key: &[u8]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(owner_key);
    data.extend_from_slice(contact_key);
    blake3::hash(&data).into()
}

/// Generate group ID from creator, name and timestamp
pub fn generate_group_id(creator_key: &[u8], group_name: &str, timestamp_nanos: u128) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(creator_key);
    data.extend_from_slice(group_name.as_bytes());
    data.extend_from_slice(&timestamp_nanos.to_le_bytes());
    blake3::hash(&data).into()
}

/// Generate file ID for shared files
pub fn generate_file_id(owner_key: &[u8], content_hash: &[u8; 32], timestamp_nanos: u128) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(owner_key);
    data.extend_from_slice(content_hash);
    data.extend_from_slice(&timestamp_nanos.to_le_bytes());
    blake3::hash(&data).into()
}

/// Generate storage key for contract state
pub fn generate_storage_key(prefix: &str, identifier: &[u8]) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(prefix.as_bytes());
    key.push(b':');
    key.extend_from_slice(&hex::encode(identifier).as_bytes());
    key
}

/// Generate indexed storage key with multiple components
pub fn generate_indexed_storage_key(prefix: &str, components: &[&[u8]]) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(prefix.as_bytes());
    
    for component in components {
        key.push(b':');
        key.extend_from_slice(&hex::encode(component).as_bytes());
    }
    
    key
}

/// Validate ID format (32 bytes)
pub fn validate_id(id: &[u8]) -> bool {
    id.len() == 32
}

/// Convert ID to hex string for display
pub fn id_to_hex(id: &[u8; 32]) -> String {
    hex::encode(id)
}

/// Convert hex string back to ID
pub fn hex_to_id(hex_str: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Generate deterministic ID from seed
pub fn generate_deterministic_id(seed: &str) -> [u8; 32] {
    blake3::hash(seed.as_bytes()).into()
}

/// Generate random-like ID from current time and additional entropy
pub fn generate_time_based_id(additional_entropy: &[u8]) -> [u8; 32] {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_le_bytes());
    data.extend_from_slice(additional_entropy);
    
    blake3::hash(&data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lib_token_id_generation() {
        let id1 = generate_lib_token_id();
        let id2 = generate_lib_token_id();
        
        // Should be deterministic
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_custom_token_id_generation() {
        let id1 = generate_custom_token_id("Whisper", "WHISPER");
        let id2 = generate_custom_token_id("Whisper", "WHISPER");
        let id3 = generate_custom_token_id("Test", "TEST");

        // Same inputs should produce same ID
        assert_eq!(id1, id2);
        // Different inputs should produce different IDs
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_custom_token_id_collision_resistance() {
        // Test that length-prefixing prevents collisions
        // Without length-prefixing, these would produce the same hash:
        // "AB_CD_TOKEN" == "ABC_D_TOKEN" (if name/symbol were just concatenated)

        let id1 = generate_custom_token_id("AB", "CD");
        let id2 = generate_custom_token_id("ABC", "D");
        let id3 = generate_custom_token_id("A", "BCD");
        let id4 = generate_custom_token_id("ABCD", "");

        // All should be different due to length-prefixing
        assert_ne!(id1, id2, "AB+CD should differ from ABC+D");
        assert_ne!(id1, id3, "AB+CD should differ from A+BCD");
        assert_ne!(id1, id4, "AB+CD should differ from ABCD+empty");
        assert_ne!(id2, id3, "ABC+D should differ from A+BCD");
        assert_ne!(id2, id4, "ABC+D should differ from ABCD+empty");
        assert_ne!(id3, id4, "A+BCD should differ from ABCD+empty");
    }

    #[test]
    fn test_contract_id_generation() {
        let component1 = b"component1";
        let component2 = b"component2";
        
        let id1 = generate_contract_id(&[component1, component2]);
        let id2 = generate_contract_id(&[component1, component2]);
        let id3 = generate_contract_id(&[component2, component1]); // Different order
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3); // Order matters
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_message_id_generation() {
        let sender_key = b"sender_public_key_data_here_32bytes";
        let timestamp1 = 123456789u128;
        let timestamp2 = 123456790u128;
        
        let id1 = generate_message_id(sender_key, timestamp1);
        let id2 = generate_message_id(sender_key, timestamp1);
        let id3 = generate_message_id(sender_key, timestamp2);
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_contact_id_generation() {
        let owner_key = b"owner_key_32_bytes_of_data_here_";
        let contact_key1 = b"contact1_key_24_bytes_here___";
        let contact_key2 = b"contact2_key_24_bytes_here___";
        
        let id1 = generate_contact_id(owner_key, contact_key1);
        let id2 = generate_contact_id(owner_key, contact_key1);
        let id3 = generate_contact_id(owner_key, contact_key2);
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_group_id_generation() {
        let creator_key = b"creator_key_32_bytes_of_data_here";
        let group_name = "Test Group";
        let timestamp = 123456789u128;
        
        let id1 = generate_group_id(creator_key, group_name, timestamp);
        let id2 = generate_group_id(creator_key, group_name, timestamp);
        let id3 = generate_group_id(creator_key, "Different Group", timestamp);
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_file_id_generation() {
        let owner_key = b"owner_key_32_bytes_of_data_here_";
        let content_hash = [1u8; 32];
        let timestamp = 123456789u128;
        
        let id1 = generate_file_id(owner_key, &content_hash, timestamp);
        let id2 = generate_file_id(owner_key, &content_hash, timestamp);
        let id3 = generate_file_id(owner_key, &[2u8; 32], timestamp);
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_storage_key_generation() {
        let key1 = generate_storage_key("message", &[1, 2, 3, 4]);
        let key2 = generate_storage_key("message", &[1, 2, 3, 4]);
        let key3 = generate_storage_key("contact", &[1, 2, 3, 4]);
        
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        
        let key_str = String::from_utf8(key1).unwrap();
        assert!(key_str.starts_with("message:"));
    }

    #[test]
    fn test_indexed_storage_key_generation() {
        let component1 = b"comp1";
        let component2 = b"comp2";
        
        let key1 = generate_indexed_storage_key("prefix", &[component1, component2]);
        let key2 = generate_indexed_storage_key("prefix", &[component1, component2]);
        let key3 = generate_indexed_storage_key("prefix", &[component2, component1]);
        
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        
        let key_str = String::from_utf8(key1).unwrap();
        assert!(key_str.starts_with("prefix:"));
    }

    #[test]
    fn test_id_validation() {
        let valid_id = [0u8; 32];
        let invalid_id = [0u8; 31];
        
        assert!(validate_id(&valid_id));
        assert!(!validate_id(&invalid_id));
    }

    #[test]
    fn test_hex_conversion() {
        let id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        
        let hex_str = id_to_hex(&id);
        let recovered_id = hex_to_id(&hex_str).unwrap();
        
        assert_eq!(id, recovered_id);
        assert_eq!(hex_str.len(), 64); // 32 bytes * 2 hex chars per byte
    }

    #[test]
    fn test_deterministic_id() {
        let id1 = generate_deterministic_id("test_seed");
        let id2 = generate_deterministic_id("test_seed");
        let id3 = generate_deterministic_id("different_seed");
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_time_based_id() {
        let entropy1 = b"entropy1";
        let entropy2 = b"entropy2";
        
        let id1 = generate_time_based_id(entropy1);
        let id2 = generate_time_based_id(entropy2);
        
        // Should be different (unless generated at exact same nanosecond, which is extremely unlikely)
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 32);
        
        // Test with same entropy but different times
        std::thread::sleep(std::time::Duration::from_nanos(1));
        let id3 = generate_time_based_id(entropy1);
        assert_ne!(id1, id3); // Different due to time component
    }
}
