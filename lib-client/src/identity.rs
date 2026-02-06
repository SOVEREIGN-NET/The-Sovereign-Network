//! Client-side identity generation
//!
//! Generates ZHTP identities with post-quantum cryptographic keys.
//! All keys are generated locally on the client device and private
//! keys NEVER leave the device.
//!
//! # Security Model
//!
//! ```text
//! Client Device                    Server
//!     |                               |
//!     |-- Generate master_seed        |
//!     |-- Derive Dilithium5 keypair   |
//!     |-- Derive Kyber1024 keypair    |
//!     |-- Compute DID from public key |
//!     |                               |
//!     |-- Send ONLY public keys ----->|  (Registration)
//!     |                               |
//!     |   Private keys stay here!     |
//! ```
//!
//! # Key Derivation
//!
//! ```text
//! master_seed (32 bytes random)
//!     |
//!     +-- Dilithium5 keypair (signing)
//!     |
//!     +-- Kyber1024 keypair (key exchange)
//!     |
//!     +-- DID = "did:zhtp:" + hex(Blake3(dilithium_pk))
//!     |
//!     +-- node_id = Blake3(did || device_id)
//! ```

use crate::bip39_wordlist::BIP39_WORDLIST;
use crate::crypto::{Blake3, Dilithium5, Kyber1024, random_bytes};
use crate::error::{ClientError, Result};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// Complete ZHTP identity with both public and private keys
///
/// This struct contains sensitive cryptographic material and should
/// be stored securely (e.g., iOS Keychain, Android Keystore).
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Decentralized Identifier: "did:zhtp:{hash}"
    pub did: String,

    /// Dilithium5 public key for signature verification (~2592 bytes)
    pub public_key: Vec<u8>,

    /// Dilithium5 private key for signing (~4896 bytes)
    /// SECURITY: Never transmit this!
    pub private_key: Vec<u8>,

    /// Kyber1024 public key for key encapsulation (~1568 bytes)
    pub kyber_public_key: Vec<u8>,

    /// Kyber1024 secret key for decapsulation (~3168 bytes)
    /// SECURITY: Never transmit this!
    pub kyber_secret_key: Vec<u8>,

    /// Node identifier: Blake3(did || device_id)
    pub node_id: Vec<u8>,

    /// Device identifier (e.g., UUID)
    pub device_id: String,

    /// Master seed for key derivation (32 bytes)
    /// SECURITY: Never transmit this!
    pub master_seed: Vec<u8>,

    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
}

/// Public portion of identity (safe to send to server)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicIdentity {
    /// Decentralized Identifier
    pub did: String,

    /// Dilithium5 public key
    pub public_key: Vec<u8>,

    /// Kyber1024 public key
    pub kyber_public_key: Vec<u8>,

    /// Node identifier
    pub node_id: Vec<u8>,

    /// Device identifier
    pub device_id: String,

    /// Creation timestamp
    pub created_at: u64,
}

/// Generate a new ZHTP identity with post-quantum keys
///
/// All cryptographic keys are generated locally. Private keys
/// never leave the device.
///
/// # Arguments
///
/// * `device_id` - Unique device identifier (e.g., UUID)
///
/// # Returns
///
/// Complete `Identity` with public and private keys
///
/// # Example
///
/// ```ignore
/// let identity = generate_identity("iphone-abc123".into())?;
/// // Store identity.private_key in Keychain
/// // Send get_public_identity(&identity) to server
/// ```
pub fn generate_identity(device_id: String) -> Result<Identity> {
    // 1. Generate master seed (32 random bytes)
    let master_seed = random_bytes(32);

    // 2. Generate Dilithium5 keypair from seed (deterministic - enables recovery)
    let (dilithium_pk, dilithium_sk) = Dilithium5::generate_keypair_from_seed(&master_seed)?;

    // 3. Generate Kyber1024 keypair from seed (deterministic - enables recovery)
    let (kyber_pk, kyber_sk) = Kyber1024::generate_keypair_from_seed(&master_seed)?;

    // 4. Derive DID from public key
    let pk_hash = Blake3::hash(&dilithium_pk);
    let did = format!("did:zhtp:{}", hex::encode(pk_hash));

    // 5. Derive node ID: Blake3(did || device_id)
    let node_id_input = format!("{}{}", did, device_id);
    let node_id = Blake3::hash_vec(node_id_input.as_bytes());

    // 6. Get creation timestamp
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(Identity {
        did,
        public_key: dilithium_pk,
        private_key: dilithium_sk,
        kyber_public_key: kyber_pk,
        kyber_secret_key: kyber_sk,
        node_id,
        device_id,
        master_seed,
        created_at,
    })
}

/// Restore an identity from a master seed
///
/// Used for recovery when user enters their seed phrase on a new device.
/// The same seed will produce the same keys (deterministic derivation).
///
/// # Note
///
/// Currently generates new random keys because pqcrypto doesn't support
/// seeded generation. TODO: Implement proper deterministic derivation.
pub fn restore_identity_from_seed(master_seed: Vec<u8>, device_id: String) -> Result<Identity> {
    if master_seed.len() != 32 {
        return Err(ClientError::CryptoError(
            "Master seed must be 32 bytes".into(),
        ));
    }

    // TODO: Use seed for deterministic key derivation
    // For now, generate new keys (not truly deterministic)
    let (dilithium_pk, dilithium_sk) = Dilithium5::generate_keypair_from_seed(&master_seed)?;
    let (kyber_pk, kyber_sk) = Kyber1024::generate_keypair_from_seed(&master_seed)?;

    let pk_hash = Blake3::hash(&dilithium_pk);
    let did = format!("did:zhtp:{}", hex::encode(pk_hash));

    let node_id_input = format!("{}{}", did, device_id);
    let node_id = Blake3::hash_vec(node_id_input.as_bytes());

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(Identity {
        did,
        public_key: dilithium_pk,
        private_key: dilithium_sk,
        kyber_public_key: kyber_pk,
        kyber_secret_key: kyber_sk,
        node_id,
        device_id,
        master_seed,
        created_at,
    })
}

/// Restore an identity from a 24-word BIP39 seed phrase
///
/// This derives the 32-byte master seed from the phrase and restores the identity.
pub fn restore_identity_from_phrase(phrase: &str, device_id: String) -> Result<Identity> {
    let entropy = entropy_from_mnemonic(phrase)?;
    restore_identity_from_seed(entropy, device_id)
}

/// Extract public portion of identity (safe to send to server)
///
/// This function returns only the public parts of the identity
/// that can be safely transmitted to the server for registration.
pub fn get_public_identity(identity: &Identity) -> PublicIdentity {
    PublicIdentity {
        did: identity.did.clone(),
        public_key: identity.public_key.clone(),
        kyber_public_key: identity.kyber_public_key.clone(),
        node_id: identity.node_id.clone(),
        device_id: identity.device_id.clone(),
        created_at: identity.created_at,
    }
}

/// Convert the master seed into a 24-word BIP39 mnemonic (English)
pub fn get_seed_phrase(identity: &Identity) -> Result<String> {
    mnemonic_from_entropy(&identity.master_seed).map(|words| words.join(" "))
}

fn entropy_from_mnemonic(phrase: &str) -> Result<Vec<u8>> {
    let words: Vec<String> = phrase
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect();

    if words.len() != 24 {
        return Err(ClientError::CryptoError(
            "Seed phrase must be exactly 24 words".into(),
        ));
    }

    let mut bits = Vec::with_capacity(words.len() * 11);
    for word in words {
        let index = BIP39_WORDLIST
            .iter()
            .position(|w| *w == word)
            .ok_or_else(|| ClientError::CryptoError("Invalid BIP39 word".into()))? as u16;

        for i in (0..11).rev() {
            bits.push(((index >> i) & 1) as u8);
        }
    }

    if bits.len() != 264 {
        return Err(ClientError::CryptoError(
            "Invalid mnemonic length".into(),
        ));
    }

    let mut entropy = vec![0u8; 32];
    for i in 0..32 {
        let mut byte = 0u8;
        for j in 0..8 {
            byte = (byte << 1) | bits[i * 8 + j];
        }
        entropy[i] = byte;
    }

    let mut checksum_byte = 0u8;
    for j in 0..8 {
        checksum_byte = (checksum_byte << 1) | bits[256 + j];
    }

    let expected_checksum = Sha256::digest(&entropy)[0];
    if checksum_byte != expected_checksum {
        return Err(ClientError::CryptoError(
            "Invalid seed phrase checksum".into(),
        ));
    }

    Ok(entropy)
}

fn mnemonic_from_entropy(entropy: &[u8]) -> Result<Vec<&'static str>> {
    if entropy.len() != 32 {
        return Err(ClientError::CryptoError(
            "Master seed must be 32 bytes".into(),
        ));
    }

    let entropy_bits = entropy.len() * 8;
    let checksum_bits = entropy_bits / 32;
    let hash = Sha256::digest(entropy);

    let total_bits = entropy_bits + checksum_bits;
    let word_count = total_bits / 11;

    let mut words = Vec::with_capacity(word_count);
    let mut bit_index = 0usize;

    for _ in 0..word_count {
        let mut index = 0u16;
        for _ in 0..11 {
            index <<= 1;
            let bit = if bit_index < entropy_bits {
                let byte = entropy[bit_index / 8];
                (byte >> (7 - (bit_index % 8))) & 1
            } else {
                let checksum_bit_index = bit_index - entropy_bits;
                if checksum_bit_index >= 8 {
                    0
                } else {
                    (hash[0] >> (7 - checksum_bit_index)) & 1
                }
            };
            index |= bit as u16;
            bit_index += 1;
        }
        let word = BIP39_WORDLIST
            .get(index as usize)
            .ok_or_else(|| ClientError::CryptoError("Invalid BIP39 index".into()))?;
        words.push(*word);
    }

    Ok(words)
}

/// Sign a registration proof for server registration
///
/// Creates a signature over "ZHTP_REGISTER:{did}:{timestamp}" that
/// proves ownership of the private key without revealing it.
///
/// # Arguments
///
/// * `identity` - The identity to sign with
/// * `timestamp` - Current Unix timestamp (server validates freshness)
///
/// # Returns
///
/// Dilithium5 signature as bytes
pub fn sign_registration_proof(identity: &Identity, timestamp: u64) -> Result<Vec<u8>> {
    let message = format!("ZHTP_REGISTER:{}:{}", identity.did, timestamp);
    Dilithium5::sign(message.as_bytes(), &identity.private_key)
}

/// Sign an arbitrary message with the identity's private key
pub fn sign_message(identity: &Identity, message: &[u8]) -> Result<Vec<u8>> {
    Dilithium5::sign(message, &identity.private_key)
}

/// Verify a signature against an identity's public key
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    Dilithium5::verify(message, signature, public_key)
}

/// Serialize identity to JSON for storage
pub fn serialize_identity(identity: &Identity) -> Result<String> {
    serde_json::to_string(identity).map_err(|e| ClientError::SerializationError(e.to_string()))
}

/// Deserialize identity from JSON
pub fn deserialize_identity(json: &str) -> Result<Identity> {
    serde_json::from_str(json).map_err(|e| ClientError::SerializationError(e.to_string()))
}

/// Serialize only public identity to JSON
pub fn serialize_public_identity(identity: &PublicIdentity) -> Result<String> {
    serde_json::to_string(identity).map_err(|e| ClientError::SerializationError(e.to_string()))
}

/// Export identity as base64-encoded keystore tarball for CI/CD deployment
///
/// Creates a tar.gz archive containing:
/// - keystore/user_identity.json (ZhtpIdentity format for CLI)
/// - keystore/user_private_key.json (private keys)
///
/// The output can be stored as a GitHub secret (ZHTP_KEYSTORE_B64) and used
/// with the deploy-site GitHub Action.
///
/// # Security
/// The output contains private keys! Treat it as a secret.
///
/// # Example
/// ```ignore
/// let identity = generate_identity("device-123".into())?;
/// let keystore_b64 = export_keystore_base64(&identity)?;
/// // User copies this to GitHub secrets as ZHTP_KEYSTORE_B64
/// ```
pub fn export_keystore_base64(identity: &Identity) -> Result<String> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, Header};

    // 1. Create user_identity.json (ZhtpIdentity format)
    let user_identity_json = create_zhtp_identity_json(identity)?;

    // 2. Create user_private_key.json (KeystorePrivateKey format)
    let user_private_key_json = create_keystore_private_key_json(identity)?;

    // 3. Create tar.gz archive in memory
    let mut archive_data = Vec::new();
    {
        let encoder = GzEncoder::new(&mut archive_data, Compression::default());
        let mut archive = Builder::new(encoder);

        // Add keystore/user_identity.json
        let identity_bytes = user_identity_json.as_bytes();
        let mut header = Header::new_gnu();
        header.set_path("keystore/user_identity.json")
            .map_err(|e| ClientError::SerializationError(format!("Failed to set path: {}", e)))?;
        header.set_size(identity_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, identity_bytes)
            .map_err(|e| ClientError::SerializationError(format!("Failed to add identity: {}", e)))?;

        // Add keystore/user_private_key.json
        let private_key_bytes = user_private_key_json.as_bytes();
        let mut header = Header::new_gnu();
        header.set_path("keystore/user_private_key.json")
            .map_err(|e| ClientError::SerializationError(format!("Failed to set path: {}", e)))?;
        header.set_size(private_key_bytes.len() as u64);
        header.set_mode(0o600); // Restrictive permissions for private key
        header.set_cksum();
        archive.append(&header, private_key_bytes)
            .map_err(|e| ClientError::SerializationError(format!("Failed to add private key: {}", e)))?;

        // Finalize archive
        let encoder = archive.into_inner()
            .map_err(|e| ClientError::SerializationError(format!("Failed to finalize archive: {}", e)))?;
        encoder.finish()
            .map_err(|e| ClientError::SerializationError(format!("Failed to finish compression: {}", e)))?;
    }

    // 4. Base64 encode
    use base64::{Engine, engine::general_purpose::STANDARD};
    Ok(STANDARD.encode(&archive_data))
}

/// Create ZhtpIdentity JSON format expected by the CLI
fn create_zhtp_identity_json(identity: &Identity) -> Result<String> {
    use crate::crypto::Blake3;

    // Compute key_id = Blake3(dilithium_public_key)
    let key_id = Blake3::hash(&identity.public_key);

    // Extract identity ID from DID (format: "did:zhtp:{id_hex}")
    let id_hex = identity.did.strip_prefix("did:zhtp:").unwrap_or(&identity.did);
    let id_bytes: Vec<u8> = hex::decode(id_hex).unwrap_or_else(|_| key_id.to_vec());

    // Generate dao_member_id from DID (deterministic)
    let dao_member_id = format!("dao:{}", id_hex);

    // NodeId struct format
    let node_id_bytes: [u8; 32] = if identity.node_id.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&identity.node_id[..32]);
        arr
    } else {
        let mut arr = [0u8; 32];
        arr[..identity.node_id.len()].copy_from_slice(&identity.node_id);
        arr
    };

    let zero_bytes: [u8; 32] = [0u8; 32];
    let node_id_struct = serde_json::json!({
        "bytes": node_id_bytes,
        "creation_nonce": zero_bytes,
        "network_genesis": zero_bytes
    });

    // Convert key_id to [u8; 32] array format
    let key_id_arr: [u8; 32] = {
        let mut arr = [0u8; 32];
        let len = std::cmp::min(key_id.len(), 32);
        arr[..len].copy_from_slice(&key_id[..len]);
        arr
    };

    // Build ZhtpIdentity format (matches lib-identity expectations)
    let zhtp_identity = serde_json::json!({
        "id": id_bytes,
        "did": identity.did,
        "identity_type": "Device",
        "public_key": {
            "dilithium_pk": identity.public_key,
            "kyber_pk": identity.kyber_public_key,
            "key_id": key_id_arr
        },
        "node_id": node_id_struct,
        "device_node_ids": {
            identity.device_id.clone(): node_id_struct
        },
        "primary_device": identity.device_id,
        "dao_member_id": dao_member_id,
        "ownership_proof": {
            "proof_system": "dilithium-pop-placeholder-v0",
            "proof_data": [],
            "public_inputs": id_bytes.clone(),
            "verification_key": identity.public_key.clone(),
            "plonky2_proof": null,
            "proof": []
        },
        "credentials": {},
        "metadata": {},
        "attestations": [],
        "reputation": 100,
        "access_level": "Standard",
        "age": null,
        "jurisdiction": null,
        "citizenship_verified": false,
        "dao_voting_power": 0,
        "private_data_id": null,
        "created_at": identity.created_at,
        "last_active": identity.created_at,
        "recovery_keys": [],
        "did_document_hash": null,
        "owner_identity_id": null,
        "reward_wallet_id": null
    });

    serde_json::to_string_pretty(&zhtp_identity)
        .map_err(|e| ClientError::SerializationError(e.to_string()))
}

/// Create KeystorePrivateKey JSON format expected by the CLI
fn create_keystore_private_key_json(identity: &Identity) -> Result<String> {
    let keystore_key = serde_json::json!({
        "dilithium_sk": identity.private_key,
        "dilithium_pk": identity.public_key,
        "kyber_sk": identity.kyber_secret_key,
        "master_seed": identity.master_seed
    });

    serde_json::to_string_pretty(&keystore_key)
        .map_err(|e| ClientError::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = generate_identity("test-device".into()).unwrap();

        assert!(identity.did.starts_with("did:zhtp:"));
        assert_eq!(identity.public_key.len(), Dilithium5::PUBLIC_KEY_SIZE);
        // Seeded keys use crystals-dilithium (4864 bytes)
        assert_eq!(identity.private_key.len(), Dilithium5::SECRET_KEY_SIZE_SEEDED);
        assert_eq!(identity.kyber_public_key.len(), Kyber1024::PUBLIC_KEY_SIZE);
        assert_eq!(identity.kyber_secret_key.len(), Kyber1024::SECRET_KEY_SIZE);
        assert_eq!(identity.node_id.len(), 32);
        assert_eq!(identity.device_id, "test-device");
        assert_eq!(identity.master_seed.len(), 32);
    }

    #[test]
    fn test_get_public_identity() {
        let identity = generate_identity("test-device".into()).unwrap();
        let public = get_public_identity(&identity);

        assert_eq!(public.did, identity.did);
        assert_eq!(public.public_key, identity.public_key);
        assert_eq!(public.kyber_public_key, identity.kyber_public_key);
        assert_eq!(public.node_id, identity.node_id);
        assert_eq!(public.device_id, identity.device_id);
    }

    #[test]
    fn test_sign_registration_proof() {
        let identity = generate_identity("test-device".into()).unwrap();
        let timestamp = 1234567890u64;

        let signature = sign_registration_proof(&identity, timestamp).unwrap();

        // Verify the signature
        let message = format!("ZHTP_REGISTER:{}:{}", identity.did, timestamp);
        assert!(Dilithium5::verify(message.as_bytes(), &signature, &identity.public_key).unwrap());
    }

    #[test]
    fn test_serialize_deserialize_identity() {
        let identity = generate_identity("test-device".into()).unwrap();

        let json = serialize_identity(&identity).unwrap();
        let restored = deserialize_identity(&json).unwrap();

        assert_eq!(restored.did, identity.did);
        assert_eq!(restored.public_key, identity.public_key);
        assert_eq!(restored.private_key, identity.private_key);
    }

    #[test]
    fn test_get_seed_phrase_word_count() {
        let mut identity = generate_identity("test-device".into()).unwrap();
        identity.master_seed = vec![0u8; 32];

        let phrase = get_seed_phrase(&identity).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn test_seed_recovery_produces_same_did() {
        // Generate a new identity
        let identity = generate_identity("test-device".into()).unwrap();
        let original_did = identity.did.clone();
        let original_public_key = identity.public_key.clone();

        // Get the seed phrase
        let phrase = get_seed_phrase(&identity).unwrap();

        // Restore from seed phrase
        let restored = restore_identity_from_phrase(&phrase, "new-device".into()).unwrap();

        // DIDs MUST match (this is the critical test)
        assert_eq!(restored.did, original_did, "Restored DID must match original");
        assert_eq!(restored.public_key, original_public_key, "Restored public key must match");
    }

    #[test]
    fn test_seed_recovery_deterministic() {
        // Same seed should always produce same keys
        let seed = vec![42u8; 32];

        let id1 = restore_identity_from_seed(seed.clone(), "device1".into()).unwrap();
        let id2 = restore_identity_from_seed(seed.clone(), "device2".into()).unwrap();

        // Same keys regardless of device_id
        assert_eq!(id1.did, id2.did);
        assert_eq!(id1.public_key, id2.public_key);
        assert_eq!(id1.private_key, id2.private_key);
    }

    #[test]
    fn test_export_keystore_base64() {
        let identity = generate_identity("test-device".into()).unwrap();

        // Export should succeed
        let keystore_b64 = export_keystore_base64(&identity).unwrap();

        // Should be valid base64
        use base64::{Engine, engine::general_purpose::STANDARD};
        let decoded = STANDARD.decode(&keystore_b64).expect("Should be valid base64");

        // Should be a valid gzip (starts with 0x1f 0x8b)
        assert!(decoded.len() > 2, "Archive should have content");
        assert_eq!(decoded[0], 0x1f, "Should start with gzip magic byte 1");
        assert_eq!(decoded[1], 0x8b, "Should start with gzip magic byte 2");

        // Decompress and verify tar structure
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(&decoded[..]);
        let mut tar_data = Vec::new();
        decoder.read_to_end(&mut tar_data).expect("Should decompress");

        // Check that tar contains expected files
        use tar::Archive;
        let mut archive = Archive::new(&tar_data[..]);
        let entries: Vec<_> = archive.entries().unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(entries.contains(&"keystore/user_identity.json".to_string()),
            "Should contain user_identity.json, got: {:?}", entries);
        assert!(entries.contains(&"keystore/user_private_key.json".to_string()),
            "Should contain user_private_key.json, got: {:?}", entries);
    }
}
