//! Identity integration for ZHTP blockchain
//! Provides DID creation, validation, and identity management functionality

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::integration::crypto_integration::PublicKey;
use crate::transaction::IdentityTransactionData;
use lib_identity::{IdentityType, AccessLevel};

/// DID (Decentralized Identifier) structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Did {
    pub method: String,
    pub identifier: String,
}

impl Did {
    /// Parse a DID from string format
    pub fn parse(did_string: &str) -> Result<Self> {
        if !did_string.starts_with("did:") {
            return Err(anyhow::anyhow!("DID must start with 'did:'"));
        }

        let parts: Vec<&str> = did_string.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid DID format"));
        }

        Ok(Self {
            method: parts[1].to_string(),
            identifier: parts[2].to_string(),
        })
    }

    /// Convert DID to string format
    pub fn to_string(&self) -> String {
        format!("did:{}:{}", self.method, self.identifier)
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Convert string identity type to proper IdentityType enum
pub fn parse_identity_type(identity_type_str: &str) -> Result<IdentityType> {
    match identity_type_str.to_lowercase().as_str() {
        "human" | "individual" | "person" => Ok(IdentityType::Human),
        "agent" | "ai" | "bot" => Ok(IdentityType::Agent),
        "contract" | "smart_contract" => Ok(IdentityType::Contract),
        "organization" | "org" | "company" => Ok(IdentityType::Organization),
        "device" | "iot" | "sensor" => Ok(IdentityType::Device),
        _ => Err(anyhow::anyhow!("Unknown identity type: {}", identity_type_str)),
    }
}

/// Convert IdentityType enum to string representation
pub fn identity_type_to_string(identity_type: &IdentityType) -> String {
    match identity_type {
        IdentityType::Human => "human".to_string(),
        IdentityType::Agent => "agent".to_string(),
        IdentityType::Contract => "contract".to_string(),
        IdentityType::Organization => "organization".to_string(),
        IdentityType::Device => "device".to_string(),
    }
}

/// Determine access level based on identity type and reputation
pub fn determine_access_level(identity_type: &IdentityType, reputation_score: u32) -> AccessLevel {
    match identity_type {
        IdentityType::Human => {
            if reputation_score >= 80 {
                AccessLevel::FullCitizen
            } else {
                AccessLevel::Visitor // Assuming Visitor exists in AccessLevel
            }
        },
        IdentityType::Organization => AccessLevel::FullCitizen, // Organizations get full access
        IdentityType::Agent | IdentityType::Contract | IdentityType::Device => {
            AccessLevel::Visitor // AI/devices get limited access initially
        },
    }
}

/// Create a blockchain DID from public key and method-specific ID
pub fn create_blockchain_did(public_key: &PublicKey, method_specific_id: &str) -> Result<Did> {
    // Create identifier from public key hash and method-specific ID
    let pk_hash = blake3::hash(&public_key.key_id);
    let identifier = format!("{}:{}", method_specific_id, hex::encode(&pk_hash.as_bytes()[..16]));
    
    Ok(Did {
        method: "zhtp".to_string(),
        identifier,
    })
}

/// Validate identity transaction data
pub fn validate_identity_data(identity_data: &IdentityTransactionData) -> Result<bool> {
    // Basic validation
    if identity_data.did.is_empty() {
        return Ok(false);
    }

    // Validate DID format
    if !identity_data.did.starts_with("did:zhtp:") {
        return Ok(false);
    }

    // Validate identity type
    if identity_data.identity_type.is_empty() {
        return Ok(false);
    }

    // Validate public key
    if identity_data.public_key.is_empty() {
        return Ok(false);
    }

    // Additional validation can be added here
    Ok(true)
}

/// Process identity registration
pub fn process_identity_registration(identity_data: &IdentityTransactionData) -> Result<String> {
    // Validate the identity data first
    if !validate_identity_data(identity_data)? {
        return Err(anyhow::anyhow!("Invalid identity data"));
    }

    // Generate registration ID
    let registration_data = [
        identity_data.did.as_bytes(),
        &identity_data.public_key,
        identity_data.identity_type.as_bytes(),
    ].concat();
    
    let registration_hash = blake3::hash(&registration_data);
    let registration_id = hex::encode(registration_hash.as_bytes());
    
    Ok(registration_id)
}

/// Process identity update
pub fn process_identity_update(did: Did, identity_data: &IdentityTransactionData) -> Result<String> {
    // Validate that DID matches
    if did.to_string() != identity_data.did {
        return Err(anyhow::anyhow!("DID mismatch in identity update"));
    }

    // Validate the updated identity data
    if !validate_identity_data(identity_data)? {
        return Err(anyhow::anyhow!("Invalid updated identity data"));
    }

    // Generate update ID
    let update_data = [
        identity_data.did.as_bytes(),
        &identity_data.public_key,
        identity_data.identity_type.as_bytes(),
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes(),
    ].concat();
    
    let update_hash = blake3::hash(&update_data);
    let update_id = hex::encode(update_hash.as_bytes());
    
    Ok(update_id)
}

/// Process identity revocation
pub fn process_identity_revocation(
    did: &str,
    public_key: &PublicKey,
    revocation_reason: &str,
) -> Result<String> {
    // Validate DID format
    let parsed_did = Did::parse(did)?;
    if parsed_did.method != "zhtp" {
        return Err(anyhow::anyhow!("Invalid DID method for revocation"));
    }

    // Generate revocation ID
    let revocation_data = [
        did.as_bytes(),
        &public_key.key_id,
        revocation_reason.as_bytes(),
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes(),
    ].concat();
    
    let revocation_hash = blake3::hash(&revocation_data);
    let revocation_id = hex::encode(revocation_hash.as_bytes());
    
    Ok(revocation_id)
}

/// Verify identity for blockchain operations
pub fn verify_identity_for_operation(
    did: &str,
    public_key: &PublicKey,
    operation_type: &str,
) -> Result<bool> {
    // Parse and validate DID
    let parsed_did = Did::parse(did)?;
    if parsed_did.method != "zhtp" {
        return Ok(false);
    }

    // Basic verification (in a system, this would check against the identity registry)
    if did.is_empty() || public_key.key_id.is_empty() || operation_type.is_empty() {
        return Ok(false);
    }

    // All basic checks pass
    Ok(true)
}

/// Create identity commitment for zero-knowledge proofs
pub fn create_identity_commitment(
    did: &Did,
    secret: [u8; 32],
    attributes: &[&str],
) -> Result<[u8; 32]> {
    // Create commitment data
    let mut commitment_data = Vec::new();
    commitment_data.extend_from_slice(did.to_string().as_bytes());
    commitment_data.extend_from_slice(&secret);
    
    for attr in attributes {
        commitment_data.extend_from_slice(attr.as_bytes());
    }
    
    // Generate commitment hash
    let commitment_hash = blake3::hash(&commitment_data);
    Ok(*commitment_hash.as_bytes())
}

/// Identity attributes for commitments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAttributes {
    pub citizenship: Option<String>,
    pub age_range: Option<String>,
    pub verification_level: Option<String>,
    pub custom_attributes: Vec<(String, String)>,
}

impl IdentityAttributes {
    /// Create new empty attributes
    pub fn new() -> Self {
        Self {
            citizenship: None,
            age_range: None,
            verification_level: None,
            custom_attributes: Vec::new(),
        }
    }

    /// Add citizenship attribute
    pub fn with_citizenship(mut self, citizenship: String) -> Self {
        self.citizenship = Some(citizenship);
        self
    }

    /// Add age range attribute
    pub fn with_age_range(mut self, age_range: String) -> Self {
        self.age_range = Some(age_range);
        self
    }

    /// Add verification level attribute
    pub fn with_verification_level(mut self, level: String) -> Self {
        self.verification_level = Some(level);
        self
    }

    /// Add custom attribute
    pub fn with_custom_attribute(mut self, key: String, value: String) -> Self {
        self.custom_attributes.push((key, value));
        self
    }

    /// Convert to string array for commitment generation
    pub fn to_string_array(&self) -> Vec<String> {
        let mut attrs = Vec::new();
        
        if let Some(ref citizenship) = self.citizenship {
            attrs.push(format!("citizenship:{}", citizenship));
        }
        
        if let Some(ref age_range) = self.age_range {
            attrs.push(format!("age_range:{}", age_range));
        }
        
        if let Some(ref verification_level) = self.verification_level {
            attrs.push(format!("verification_level:{}", verification_level));
        }
        
        for (key, value) in &self.custom_attributes {
            attrs.push(format!("{}:{}", key, value));
        }
        
        attrs
    }
}

impl Default for IdentityAttributes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    #[test]
    fn test_did_parsing() -> Result<()> {
        let did_string = "did:zhtp:user123";
        let did = Did::parse(did_string)?;
        
        assert_eq!(did.method, "zhtp");
        assert_eq!(did.identifier, "user123");
        assert_eq!(did.to_string(), did_string);
        
        Ok(())
    }

    #[test]
    fn test_blockchain_did_creation() -> Result<()> {
        let keypair = KeyPair::generate()?;
        let did = create_blockchain_did(&keypair.public_key, "user123")?;
        
        assert_eq!(did.method, "zhtp");
        assert!(did.identifier.starts_with("user123:"));
        assert!(did.to_string().starts_with("did:zhtp:user123:"));
        
        Ok(())
    }

    #[test]
    fn test_identity_validation() -> Result<()> {
        let keypair = KeyPair::generate()?;
        let identity_data = IdentityTransactionData {
            did: "did:zhtp:test123".to_string(),
            display_name: "Test User".to_string(),
            public_key: keypair.public_key.key_id.to_vec(),
            ownership_proof: Vec::new(),
            identity_type: identity_type_to_string(&IdentityType::Human),
            did_document_hash: Hash::default(),
            created_at: 0,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };
        
        assert!(validate_identity_data(&identity_data)?);
        
        Ok(())
    }

    #[test]
    fn test_identity_registration() -> Result<()> {
        let keypair = KeyPair::generate()?;
        let identity_data = IdentityTransactionData {
            did: "did:zhtp:test123".to_string(),
            display_name: "Test User 2".to_string(),
            public_key: keypair.public_key.key_id.to_vec(),
            ownership_proof: Vec::new(),
            identity_type: identity_type_to_string(&IdentityType::Human),
            did_document_hash: Hash::default(),
            created_at: 0,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };
        
        let registration_id = process_identity_registration(&identity_data)?;
        assert!(!registration_id.is_empty());
        assert_eq!(registration_id.len(), 64); // hex encoded 32 bytes
        
        Ok(())
    }

    #[test]
    fn test_identity_commitment() -> Result<()> {
        let did = Did::parse("did:zhtp:commitment_test")?;
        let secret = [42u8; 32];
        let attributes = vec!["citizenship:US", "age_range:25-35"];
        
        let commitment = create_identity_commitment(&did, secret, &attributes)?;
        assert_ne!(commitment, [0u8; 32]);
        
        // Same inputs should produce same commitment
        let commitment2 = create_identity_commitment(&did, secret, &attributes)?;
        assert_eq!(commitment, commitment2);
        
        // Different secret should produce different commitment
        let different_secret = [24u8; 32];
        let commitment3 = create_identity_commitment(&did, different_secret, &attributes)?;
        assert_ne!(commitment, commitment3);
        
        Ok(())
    }

    #[test]
    fn test_identity_attributes() {
        let attributes = IdentityAttributes::new()
            .with_citizenship("US".to_string())
            .with_age_range("25-35".to_string())
            .with_verification_level("verified".to_string())
            .with_custom_attribute("employer".to_string(), "TechCorp".to_string());
        
        let attr_strings = attributes.to_string_array();
        assert!(attr_strings.contains(&"citizenship:US".to_string()));
        assert!(attr_strings.contains(&"age_range:25-35".to_string()));
        assert!(attr_strings.contains(&"verification_level:verified".to_string()));
        assert!(attr_strings.contains(&"employer:TechCorp".to_string()));
    }
}
