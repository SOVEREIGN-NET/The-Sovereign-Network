// packages/lib-identity/src/did/document_generation.rs
// W3C DID Document generation for ZHTP identities.
//
// Current invariant (ADR-0004): DID is anchored to a root signing public key; seed/recovery
// material must never be embedded directly into the DID.
// IMPLEMENTATIONS from original identity.rs

use crate::identity::ZhtpIdentity;
use lib_crypto::keypair::KeyPair;
use lib_crypto::types::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use crate::did::storage;

// Note: base64 encoding removed after cleanup - no longer needed

/// W3C DID Document structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(rename = "authentication")]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation: Vec<String>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation: Vec<String>,
    pub service: Vec<ServiceEndpoint>,
    pub created: String,
    pub updated: String,
    #[serde(rename = "versionId")]
    pub version_id: u32,
    /// Registry of authorized device keys (Phase 1)
    #[serde(default, rename = "deviceRegistry")]
    pub device_registry: Vec<DeviceEntry>,
}

/// Device status for registry entries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Removed,
}

/// Device entry in DID document registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: String,
    /// Multibase-encoded signing public key
    pub signing_key_multibase: String,
    /// Multibase-encoded encryption public key
    pub encryption_key_multibase: String,
    pub status: DeviceStatus,
    pub added_at: u64,
    pub removed_at: Option<u64>,
}

/// DID document device registry diff for updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistryDiff {
    pub adds: Vec<DeviceEntry>,
    pub removes: Vec<String>,
}

/// DID document update (signed by DID root key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocumentUpdate {
    pub did: String,
    pub prev_hash: [u8; 32],
    pub new_hash: [u8; 32],
    pub version: u64,
    pub timestamp: u64,
    pub diff: DeviceRegistryDiff,
    pub signature: Signature,
}

impl DidDocument {
    /// Create a DID document from a ZHTP identity (one-way relationship)
    /// This is the canonical way to generate DID documents
    pub fn from_identity(identity: &ZhtpIdentity, base_url: Option<&str>) -> Result<Self, String> {
        generate_did_document(identity, base_url)
    }
    
    /// Get the DID document as a hash for storage/reference
    pub fn to_hash(&self) -> Result<lib_crypto::Hash, String> {
        let serialized = serde_json::to_vec(self)
            .map_err(|e| format!("Failed to serialize DID document: {}", e))?;
        Ok(lib_crypto::Hash::from_bytes(&lib_crypto::hash_blake3(&serialized)))
    }
}

/// DID Verification Method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub verification_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// DID Service Endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}





/// Generate W3C DID Document for ZHTP identity
/// Implementation from original identity.rs lines 1500-1600
pub fn generate_did_document(
    identity: &ZhtpIdentity,
    base_url: Option<&str>,
) -> Result<DidDocument, String> {
    let base_url = base_url.unwrap_or("https://did.zhtp.network");
    let did = format!("did:zhtp:{}", hex::encode(&identity.id.0));
    
    // Generate timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp = format_timestamp(now);
    
    // Create verification methods
    let verification_methods = create_verification_methods(&identity, &did)?;
    
    // Create service endpoints
    let services = create_service_endpoints(&identity, &did, base_url)?;
    
    // Create authentication and assertion method references
    let auth_methods = verification_methods.iter()
        .filter(|vm| vm.verification_type.contains("Authentication"))
        .map(|vm| vm.id.clone())
        .collect();
    
    let assertion_methods = verification_methods.iter()
        .filter(|vm| vm.verification_type.contains("Assertion"))
        .map(|vm| vm.id.clone())
        .collect();
    
    let key_agreement_methods = verification_methods.iter()
        .filter(|vm| vm.verification_type.contains("KeyAgreement"))
        .map(|vm| vm.id.clone())
        .collect();
    
    let capability_invocation = vec![format!("{}#primary", did)];
    let capability_delegation = vec![format!("{}#delegate", did)];
    
    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
            "https://zhtp.network/contexts/identity/v1".to_string(),
        ],
        id: did,
        verification_method: verification_methods,
        authentication: auth_methods,
        assertion_method: assertion_methods,
        key_agreement: key_agreement_methods,
        capability_invocation,
        capability_delegation,
        service: services,
        created: timestamp.clone(),
        updated: timestamp,
        version_id: 1,
        device_registry: Vec::new(),
    })
}

/// Create verification methods for the DID document
fn create_verification_methods(
    identity: &ZhtpIdentity,
    did: &str,
) -> Result<Vec<VerificationMethod>, String> {
    let mut methods = Vec::new();
    
    // Primary quantum-resistant authentication key
    let primary_key_multibase = encode_public_key_multibase(&identity.public_key.as_bytes())?;
    methods.push(VerificationMethod {
        id: format!("{}#primary", did),
        verification_type: "PostQuantumSignature2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: primary_key_multibase,
    });

    // Authentication method
    methods.push(VerificationMethod {
        id: format!("{}#authentication", did),
        verification_type: "PostQuantumAuthentication2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: encode_public_key_multibase(&identity.public_key.as_bytes())?,
    });

    // Assertion method for credentials
    methods.push(VerificationMethod {
        id: format!("{}#assertion", did),
        verification_type: "PostQuantumAssertion2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: encode_public_key_multibase(&identity.public_key.as_bytes())?,
    });

    // Key agreement for encryption
    methods.push(VerificationMethod {
        id: format!("{}#keyAgreement", did),
        verification_type: "PostQuantumKeyAgreement2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: encode_public_key_multibase(&identity.public_key.as_bytes())?,
    });
    
    Ok(methods)
}

/// Create service endpoints for the DID document
fn create_service_endpoints(
    identity: &ZhtpIdentity,
    did: &str,
    base_url: &str,
) -> Result<Vec<ServiceEndpoint>, String> {
    let mut services = Vec::new();
    
    // ZHTP Quantum Wallet service
    services.push(ServiceEndpoint {
        id: format!("{}#quantumWallet", did),
        service_type: "ZhtpQuantumWallet".to_string(),
        service_endpoint: format!("{}/wallet/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    // Identity verification service
    services.push(ServiceEndpoint {
        id: format!("{}#verification", did),
        service_type: "ZhtpIdentityVerification".to_string(),
        service_endpoint: format!("{}/verify/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    // Credential issuance service
    services.push(ServiceEndpoint {
        id: format!("{}#credentials", did),
        service_type: "ZhtpCredentialIssuance".to_string(),
        service_endpoint: format!("{}/credentials/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    // UBI service endpoint (if citizen)
    if identity.access_level.to_string().contains("Citizen") {
        services.push(ServiceEndpoint {
            id: format!("{}#ubi", did),
            service_type: "ZhtpUBIService".to_string(),
            service_endpoint: format!("{}/ubi/{}", base_url, hex::encode(&identity.id.0)),
        });
    }
    
    // DAO governance service (if citizen)
    if identity.access_level.to_string().contains("Citizen") {
        services.push(ServiceEndpoint {
            id: format!("{}#dao", did),
            service_type: "ZhtpDAOGovernance".to_string(),
            service_endpoint: format!("{}/dao/{}", base_url, hex::encode(&identity.id.0)),
        });
    }
    
    // Web4 access service (if citizen)
    if identity.access_level.to_string().contains("Citizen") {
        services.push(ServiceEndpoint {
            id: format!("{}#web4", did),
            service_type: "ZhtpWeb4Access".to_string(),
            service_endpoint: format!("{}/web4/{}", base_url, hex::encode(&identity.id.0)),
        });
    }
    
    // Zero-knowledge proof service
    services.push(ServiceEndpoint {
        id: format!("{}#zkProofs", did),
        service_type: "ZhtpZKProofService".to_string(),
        service_endpoint: format!("{}/zk/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    Ok(services)
}

/// Encode public key in multibase format
fn encode_public_key_multibase(public_key: &[u8]) -> Result<String, String> {
    // Use base58btc encoding (multibase identifier 'z')
    let encoded = encode_base58(public_key);
    Ok(format!("z{}", encoded))
}

/// Encode bytes in base58 format
fn encode_base58(input: &[u8]) -> String {
    // Simplified base58-like encoding to avoid overflow
    // In implementation, use proper base58 crate
    if input.is_empty() {
        return String::new();
    }
    
    // Use hex encoding with base58 prefix for demo
    format!("base58_{}", hex::encode(input))
}

/// Format timestamp in ISO 8601 format
fn format_timestamp(timestamp: u64) -> String {
    // Simple ISO 8601 format for demo (avoid overflow)
    // In implementation, use chrono or similar
    let seconds_per_day = 86400u64;
    let days_since_epoch = timestamp / seconds_per_day;
    let seconds_in_day = timestamp % seconds_per_day;
    
    let hours = seconds_in_day / 3600;
    let minutes = (seconds_in_day % 3600) / 60;
    let seconds = seconds_in_day % 60;
    
    // Simplified date calculation to avoid overflow
    let year = 2024; // Fixed year for demo
    let month = ((days_since_epoch % 365) / 30).min(11) + 1;
    let day = ((days_since_epoch % 365) % 30).min(28) + 1;
    
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", 
            year, month, day, hours, minutes, seconds)
}

/// Update DID document with new information
pub fn update_did_document(
    mut document: DidDocument,
    identity: &ZhtpIdentity,
) -> Result<DidDocument, String> {
    // Update timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    document.updated = format_timestamp(now);
    
    // Increment version
    document.version_id += 1;
    
    // Update verification methods if keys changed
    document.verification_method = create_verification_methods(identity, &document.id)?;
    
    // Update service endpoints
    document.service = create_service_endpoints(identity, &document.id, "https://did.zhtp.network")?;
    
    Ok(document)
}

/// Resolve DID to DID Document (in-memory registry)
pub fn resolve_did(did: &str) -> Result<DidDocument, String> {
    storage::resolve_did_document(did)
}















/// Validate DID Document structure
pub fn validate_did_document(document: &DidDocument) -> Result<bool, String> {
    // Check required fields
    if document.id.is_empty() {
        return Err("DID document missing id".to_string());
    }
    
    if !document.id.starts_with("did:") {
        return Err("Invalid DID format".to_string());
    }
    
    if document.verification_method.is_empty() {
        return Err("DID document must have at least one verification method".to_string());
    }
    
    // Validate verification methods
    for vm in &document.verification_method {
        if vm.id.is_empty() || vm.verification_type.is_empty() || vm.controller.is_empty() {
            return Err("Invalid verification method".to_string());
        }
    }
    
    // Validate service endpoints
    for service in &document.service {
        if service.id.is_empty() || service.service_type.is_empty() || service.service_endpoint.is_empty() {
            return Err("Invalid service endpoint".to_string());
        }
    }

    // Validate device registry entries
    let mut seen_device_ids = std::collections::HashSet::new();
    for device in &document.device_registry {
        if device.device_id.is_empty() {
            return Err("Device entry missing device_id".to_string());
        }
        if device.signing_key_multibase.is_empty() || device.encryption_key_multibase.is_empty() {
            return Err("Device entry missing keys".to_string());
        }
        if !seen_device_ids.insert(device.device_id.clone()) {
            return Err(format!("Duplicate device_id in registry: {}", device.device_id));
        }
    }
    
    Ok(true)
}

/// Store DID document in in-memory registry (Phase 1 baseline)
pub fn store_did_document(document: DidDocument) -> Result<(), String> {
    validate_did_document(&document)?;
    storage::store_did_document(document)
}

/// Create a DID-signed update to add a device to the registry
pub fn create_device_add_update(
    identity: &ZhtpIdentity,
    document: &DidDocument,
    device_id: &str,
    signing_pk: &[u8],
    encryption_pk: &[u8],
) -> Result<DidDocumentUpdate, String> {
    if device_id.is_empty() {
        return Err("Device id cannot be empty".to_string());
    }
    let now = current_unix_timestamp()?;
    let entry = DeviceEntry {
        device_id: device_id.to_string(),
        signing_key_multibase: encode_public_key_multibase(signing_pk)?,
        encryption_key_multibase: encode_public_key_multibase(encryption_pk)?,
        status: DeviceStatus::Active,
        added_at: now,
        removed_at: None,
    };
    let diff = DeviceRegistryDiff {
        adds: vec![entry],
        removes: Vec::new(),
    };
    create_signed_update(identity, document, diff)
}

/// Create a DID-signed update to remove a device from the registry
pub fn create_device_remove_update(
    identity: &ZhtpIdentity,
    document: &DidDocument,
    device_id: &str,
) -> Result<DidDocumentUpdate, String> {
    if device_id.is_empty() {
        return Err("Device id cannot be empty".to_string());
    }
    let diff = DeviceRegistryDiff {
        adds: Vec::new(),
        removes: vec![device_id.to_string()],
    };
    create_signed_update(identity, document, diff)
}

/// List active devices from DID document
pub fn list_active_devices(document: &DidDocument) -> Vec<DeviceEntry> {
    document
        .device_registry
        .iter()
        .filter(|d| d.status == DeviceStatus::Active)
        .cloned()
        .collect()
}

/// Get device entry by device_id
pub fn get_device_entry(document: &DidDocument, device_id: &str) -> Option<DeviceEntry> {
    document
        .device_registry
        .iter()
        .find(|d| d.device_id == device_id)
        .cloned()
}

/// Get decoded device keys (signing, encryption) by device_id
pub fn get_device_keys(document: &DidDocument, device_id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let entry = get_device_entry(document, device_id)
        .ok_or_else(|| format!("Device not found: {}", device_id))?;
    let signing = decode_public_key_multibase(&entry.signing_key_multibase)?;
    let encryption = decode_public_key_multibase(&entry.encryption_key_multibase)?;
    Ok((signing, encryption))
}

/// Validate and apply DID document update
pub fn apply_did_update(
    document: DidDocument,
    update: &DidDocumentUpdate,
) -> Result<DidDocument, String> {
    if !validate_did_update(&document, update)? {
        return Err("Invalid DID update".to_string());
    }

    apply_did_update_unchecked(document, update)
}

/// Apply DID update and persist document in configured store
pub fn apply_did_update_and_store(
    document: DidDocument,
    update: &DidDocumentUpdate,
) -> Result<DidDocument, String> {
    let updated = apply_did_update(document, update)?;
    store_did_document(updated.clone())?;
    Ok(updated)
}

/// Validate DID document update
pub fn validate_did_update(
    document: &DidDocument,
    update: &DidDocumentUpdate,
) -> Result<bool, String> {
    if update.did != document.id {
        return Err("Update DID mismatch".to_string());
    }

    // Verify prev hash
    let current_hash = document.to_hash()?.0;
    if update.prev_hash != current_hash {
        return Err("Update prev_hash mismatch".to_string());
    }

    // Verify version monotonicity
    let expected_version = document.version_id as u64 + 1;
    if update.version != expected_version {
        return Err("Update version not monotonic".to_string());
    }

    // Verify signature against DID root key
    let root_pk_bytes = did_root_public_key_bytes(document)?;
    let root_pk = PublicKey::new(root_pk_bytes);
    if update.signature.public_key.dilithium_pk != root_pk.dilithium_pk {
        return Err("Update signature public key does not match DID root".to_string());
    }

    let signing_bytes = did_update_signing_bytes(update)?;
    let is_valid = root_pk
        .verify(&signing_bytes, &update.signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    if !is_valid {
        return Err("Invalid update signature".to_string());
    }

    // Verify new_hash matches expected document state
    let expected_doc = apply_did_update_unchecked(document.clone(), update)?;
    let expected_hash = expected_doc.to_hash()?.0;
    if update.new_hash != expected_hash {
        return Err("Update new_hash mismatch".to_string());
    }

    Ok(true)
}

fn create_signed_update(
    identity: &ZhtpIdentity,
    document: &DidDocument,
    diff: DeviceRegistryDiff,
) -> Result<DidDocumentUpdate, String> {
    let now = current_unix_timestamp()?;
    let prev_hash = document.to_hash()?.0;
    let version = document.version_id as u64 + 1;

    let mut update = DidDocumentUpdate {
        did: document.id.clone(),
        prev_hash,
        new_hash: [0u8; 32],
        version,
        timestamp: now,
        diff,
        signature: Signature::default(),
    };

    // Compute new hash by applying update
    let updated_doc = apply_did_update_unchecked(document.clone(), &update)?;
    update.new_hash = updated_doc.to_hash()?.0;

    // Sign update
    let signing_bytes = did_update_signing_bytes(&update)?;
    let private_key = identity
        .private_key
        .clone()
        .ok_or_else(|| "Identity missing private key for signing".to_string())?;
    let keypair = KeyPair {
        public_key: identity.public_key.clone(),
        private_key,
    };
    update.signature = keypair
        .sign(&signing_bytes)
        .map_err(|e| format!("Failed to sign DID update: {}", e))?;

    Ok(update)
}

fn apply_did_update_unchecked(
    mut document: DidDocument,
    update: &DidDocumentUpdate,
) -> Result<DidDocument, String> {
    // Apply additions
    for entry in &update.diff.adds {
        if document.device_registry.iter().any(|d| d.device_id == entry.device_id && d.status == DeviceStatus::Active) {
            return Err(format!("Device already active: {}", entry.device_id));
        }
        document.device_registry.push(entry.clone());
    }

    // Apply removals
    for device_id in &update.diff.removes {
        if let Some(existing) = document.device_registry.iter_mut().find(|d| d.device_id == *device_id && d.status == DeviceStatus::Active) {
            existing.status = DeviceStatus::Removed;
            existing.removed_at = Some(update.timestamp);
        } else {
            return Err(format!("Active device not found: {}", device_id));
        }
    }

    // Update metadata
    document.updated = format_timestamp(update.timestamp);
    if update.version > u32::MAX as u64 {
        return Err("Update version exceeds document version capacity".to_string());
    }
    document.version_id = update.version as u32;

    Ok(document)
}

fn did_update_signing_bytes(update: &DidDocumentUpdate) -> Result<Vec<u8>, String> {
    #[derive(Serialize)]
    struct UpdateForSigning<'a> {
        did: &'a String,
        prev_hash: &'a [u8; 32],
        new_hash: &'a [u8; 32],
        version: u64,
        timestamp: u64,
        diff: &'a DeviceRegistryDiff,
    }

    let payload = UpdateForSigning {
        did: &update.did,
        prev_hash: &update.prev_hash,
        new_hash: &update.new_hash,
        version: update.version,
        timestamp: update.timestamp,
        diff: &update.diff,
    };

    bincode::serialize(&payload).map_err(|e| format!("Failed to serialize update: {}", e))
}

fn current_unix_timestamp() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "System time before Unix epoch".to_string())
}

fn did_root_public_key_bytes(document: &DidDocument) -> Result<Vec<u8>, String> {
    let root_method = document
        .verification_method
        .iter()
        .find(|vm| vm.id.ends_with("#primary"))
        .ok_or_else(|| "DID document missing primary verification method".to_string())?;

    decode_public_key_multibase(&root_method.public_key_multibase)
}

pub fn decode_public_key_multibase(encoded: &str) -> Result<Vec<u8>, String> {
    let encoded = encoded
        .strip_prefix('z')
        .ok_or_else(|| "Unsupported multibase prefix".to_string())?;

    let hex_part = encoded
        .strip_prefix("base58_")
        .ok_or_else(|| "Unsupported multibase encoding".to_string())?;

    hex::decode(hex_part).map_err(|e| format!("Invalid multibase hex: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityType;

    #[test]
    fn test_device_add_update_flow() -> Result<(), String> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = generate_did_document(&identity, None)?;
        let update = create_device_add_update(
            &identity,
            &doc,
            "phone-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;

        let updated = apply_did_update(doc, &update)?;
        let entry = updated.device_registry.iter().find(|d| d.device_id == "phone-1");
        assert!(entry.is_some(), "Device should be added");
        assert_eq!(entry.unwrap().status, DeviceStatus::Active);
        Ok(())
    }

    #[test]
    fn test_device_remove_update_flow() -> Result<(), String> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = generate_did_document(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "tablet-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let doc_with_device = apply_did_update(doc, &add_update)?;

        let remove_update = create_device_remove_update(&identity, &doc_with_device, "tablet-1")?;
        let updated = apply_did_update(doc_with_device, &remove_update)?;
        let entry = updated.device_registry.iter().find(|d| d.device_id == "tablet-1");
        assert!(entry.is_some(), "Device should exist");
        assert_eq!(entry.unwrap().status, DeviceStatus::Removed);
        Ok(())
    }

    #[test]
    fn test_list_active_devices() -> Result<(), String> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = generate_did_document(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "device-a",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let updated = apply_did_update(doc, &add_update)?;
        let active = list_active_devices(&updated);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].device_id, "device-a");
        Ok(())
    }

    #[test]
    fn test_get_device_keys() -> Result<(), String> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = generate_did_document(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "device-b",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let updated = apply_did_update(doc, &add_update)?;

        let (signing, encryption) = get_device_keys(&updated, "device-b")?;
        assert_eq!(signing, identity.public_key.dilithium_pk);
        assert_eq!(encryption, identity.public_key.kyber_pk);
        Ok(())
    }

    #[test]
    fn test_update_invalid_signature_rejected() -> Result<(), String> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = generate_did_document(&identity, None)?;
        let mut update = create_device_add_update(
            &identity,
            &doc,
            "device-c",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        // Corrupt signature bytes
        if !update.signature.signature.is_empty() {
            update.signature.signature[0] ^= 0xFF;
        }
        let result = validate_did_update(&doc, &update);
        assert!(result.is_err(), "Invalid signature should be rejected");
        Ok(())
    }

    #[test]
    fn test_store_and_resolve_did_document() -> Result<(), String> {
        crate::set_did_store_memory().map_err(|e| e)?;
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = generate_did_document(&identity, None)?;
        store_did_document(doc.clone())?;
        let resolved = resolve_did(&doc.id)?;
        assert_eq!(resolved.id, doc.id);
        Ok(())
    }
}
