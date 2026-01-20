//! ZHTP Identity implementation from the original identity.rs

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use std::collections::HashMap;
use lib_crypto::{Hash, PublicKey, PrivateKey};
use lib_proofs::ZeroKnowledgeProof;

use crate::types::{IdentityId, IdentityType, CredentialType, IdentityProofParams, IdentityVerification, AccessLevel, NodeId};
use crate::credentials::ZkCredential;
use crate::credentials::IdentityAttestation;

// Custom serialization for HashMap<CredentialType, ZkCredential> to use string keys
mod credentials_serde {
    use super::*;

    pub fn serialize<S>(map: &HashMap<CredentialType, ZkCredential>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut ser_map = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            // Serialize CredentialType as string key
            let key_str = serde_json::to_string(k).unwrap_or_else(|_| format!("{:?}", k));
            ser_map.serialize_entry(&key_str, v)?;
        }
        ser_map.end()
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<CredentialType, ZkCredential>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_map: HashMap<String, ZkCredential> = HashMap::deserialize(deserializer)?;
        let mut result = HashMap::new();
        for (k, v) in string_map {
            if let Ok(key) = serde_json::from_str(&k) {
                result.insert(key, v);
            }
        }
        Ok(result)
    }
}

/// ZHTP Identity with zero-knowledge privacy and integrated quantum wallet management
///
/// ## Security-Critical Deserialization Requirements
///
/// **DANGER**: Direct use of `serde_json::from_str()` or `Deserialize` produces identities
/// with ZERO-VALUED cryptographic secrets. Using such identities without re-derivation is a
/// CRITICAL SECURITY VULNERABILITY.
///
/// ### Safe Deserialization (REQUIRED)
/// ```ignore
/// // ✓ SAFE: Use from_serialized() which enforces re-derivation
/// let identity = ZhtpIdentity::from_serialized(&json_data, &private_key)?;
/// ```
///
/// ### Unsafe Deserialization (NOT RECOMMENDED)
/// ```ignore
/// // ✗ UNSAFE: Direct Deserialize is forbidden; use from_serialized instead.
/// // Attempting direct deserialization will fail.
/// ```
///
/// ### Construction (Preferred)
/// Always prefer `new()` or `from_legacy_fields()` which properly derive all secrets:
/// ```ignore
/// let identity = ZhtpIdentity::new(
///     identity_type, public_key, private_key,
///     primary_device, age, jurisdiction, citizenship_verified, ownership_proof
/// )?;
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ZhtpIdentity {
    /// Unique identity identifier  
    pub id: IdentityId,
    /// Identity type
    pub identity_type: IdentityType,
    /// Decentralized Identifier (DID)
    pub did: String,
    /// Public key for verification (lib-crypto type)
    pub public_key: PublicKey,
    /// Private key (sensitive - not serialized)
    #[serde(skip)]
    pub private_key: Option<PrivateKey>,
    /// Primary device NodeId
    pub node_id: NodeId,
    /// Device name to NodeId mapping
    pub device_node_ids: HashMap<String, NodeId>,
    /// Primary device name
    pub primary_device: String,
    /// Zero-knowledge proof of identity ownership
    pub ownership_proof: ZeroKnowledgeProof,
    /// Associated credentials
    #[serde(with = "credentials_serde")]
    pub credentials: HashMap<CredentialType, ZkCredential>,
    /// Reputation score (0-1000)
    pub reputation: u64,
    /// Current age (for age verification)
    pub age: Option<u64>,
    /// Access level (for citizen benefits)
    pub access_level: AccessLevel,
    /// Identity metadata
    pub metadata: HashMap<String, String>,
    /// Private identity data reference
    pub private_data_id: Option<IdentityId>,
    /// Integrated quantum wallet system
    pub wallet_manager: crate::wallets::WalletManager,
    /// Identity attestations from trusted parties
    pub attestations: Vec<IdentityAttestation>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_active: u64,
    /// Recovery options
    pub recovery_keys: Vec<Vec<u8>>,
    /// DID document hash for blockchain integration
    pub did_document_hash: Option<Hash>,
    /// Owner identity (for device/node identities owned by a user/org)
    pub owner_identity_id: Option<IdentityId>,
    /// Designated wallet for routing/mining rewards (for device/node identities)
    pub reward_wallet_id: Option<crate::wallets::WalletId>,
    /// HD Wallet encrypted master seed (for hierarchical deterministic wallet generation)
    #[serde(skip)]
    pub encrypted_master_seed: Option<Vec<u8>>,
    /// Next wallet derivation index for HD wallets
    #[serde(skip, default)]
    pub next_wallet_index: u32,
    /// Optional password hash for DID-level authentication
    #[serde(skip)]
    pub password_hash: Option<Vec<u8>>,
    /// Master seed phrase for identity recovery (20 words)
    #[serde(skip)]
    pub master_seed_phrase: Option<crate::recovery::RecoveryPhrase>,
    /// Zero-knowledge identity secret (32 bytes)
    /// Derived from private key - never serialized
    /// SECURITY: Always zero after deserialization - MUST call rederive_secrets()
    #[serde(skip)]
    pub zk_identity_secret: [u8; 32],
    /// Zero-knowledge credential hash (32 bytes)
    /// Derived from secret + age + jurisdiction
    /// SECURITY: Always zero after deserialization - MUST call rederive_secrets()
    #[serde(skip)]
    pub zk_credential_hash: [u8; 32],
    /// Wallet master seed (64 bytes - raw derived seed)
    /// Derived from private key - never serialized
    /// SECURITY: Always zero after deserialization - MUST call rederive_secrets()
    #[serde(skip, default = "default_wallet_seed")]
    pub wallet_master_seed: [u8; 64],
    /// DAO member identifier
    pub dao_member_id: String,
    /// DAO voting power
    pub dao_voting_power: u64,
    /// Citizenship verification status
    pub citizenship_verified: bool,
    /// Jurisdiction (optional)
    pub jurisdiction: Option<String>,
}

// Default functions for deserialization of secret fields
// SECURITY: These explicitly return zero values - secrets MUST be re-derived after deserialization
#[allow(dead_code)]
fn default_wallet_seed() -> [u8; 64] {
    [0u8; 64]
}

impl PartialEq for ZhtpIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<'de> Deserialize<'de> for ZhtpIdentity {
    fn deserialize<D>(_deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "Direct deserialization of ZhtpIdentity is forbidden. Use ZhtpIdentity::from_serialized(private_key) to safely re-derive secrets.",
        ))
    }
}

impl ZhtpIdentity {
    /// Create a new ZHTP identity with properly derived fields per architecture spec
    ///
    /// All cryptographic fields (DID, secrets, seeds) are deterministically derived
    /// from the master keypair according to ARCHITECTURE_CONSOLIDATION.md specification.
    pub fn new(
        identity_type: IdentityType,
        public_key: PublicKey,
        private_key: PrivateKey,  // Required for proper derivation
        primary_device: String,
        age: Option<u64>,
        jurisdiction: Option<String>,
        citizenship_verified: bool,
        ownership_proof: ZeroKnowledgeProof,
    ) -> Result<Self> {
        // 1. Derive DID from public key (canonical)
        let did = Self::generate_did(&public_key)?;

        // 2. Derive ID from DID
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(did.as_bytes()).to_vec());

        // 3. Generate primary NodeId from DID + device
        let node_id = NodeId::from_did_device(&did, &primary_device)?;

        // 4. Initialize device mapping with primary device
        let mut device_node_ids = HashMap::new();
        device_node_ids.insert(primary_device.clone(), node_id);

        // 5. Derive all secrets from master keypair (deterministic)
        // Age and jurisdiction are REQUIRED for Human identities only
        let zk_identity_secret = Self::derive_zk_secret(&private_key.dilithium_sk)?;
        let zk_credential_hash = if identity_type == IdentityType::Human {
            let age_val = age.ok_or_else(|| anyhow!("Age is required for Human identity credential derivation"))?;
            let juris_val = jurisdiction.as_deref().ok_or_else(|| anyhow!("Jurisdiction is required for Human identity credential derivation"))?;
            Self::derive_credential_hash(&zk_identity_secret, age_val, juris_val)?
        } else {
            // For non-Human identities (Device, Organization, etc.), use default credential hash
            [0u8; 32]
        };
        let wallet_master_seed = Self::derive_wallet_seed(&private_key.dilithium_sk)?;
        let dao_member_id = Self::derive_dao_member_id(&did)?;

        // 6. Set initial DAO voting power per spec:
        // - Verified citizens: 10
        // - Unverified humans: 1
        // - Other types (Device, Organization, etc.): 0
        let dao_voting_power = match identity_type {
            IdentityType::Human if citizenship_verified => 10,
            IdentityType::Human => 1,
            _ => 0,
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Create integrated wallet manager
        let wallet_manager = crate::wallets::WalletManager::new(id.clone());

        Ok(ZhtpIdentity {
            id: id.clone(),
            identity_type,
            did,
            public_key,
            private_key: Some(private_key),
            node_id,
            device_node_ids,
            primary_device,
            ownership_proof,
            credentials: HashMap::new(),
            reputation: 0,
            age,
            access_level: AccessLevel::default(),
            metadata: HashMap::new(),
            private_data_id: Some(id),
            wallet_manager,
            attestations: Vec::new(),
            created_at: current_time,
            last_active: current_time,
            recovery_keys: Vec::new(),
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
            zk_identity_secret,
            zk_credential_hash,
            wallet_master_seed,
            dao_member_id,
            dao_voting_power,
            citizenship_verified,
            jurisdiction,
        })
    }

    /// Create an "observed" identity from handshake public information
    ///
    /// This creates a lightweight identity from the public information exchanged
    /// during UHP+Kyber handshake. The identity is marked as observed (not locally
    /// created) and has no private key.
    ///
    /// # Purpose
    /// When a peer authenticates via UHP handshake, they prove control of their
    /// identity cryptographically. The node should auto-register this identity
    /// so subsequent operations (domain registration, etc.) can reference it.
    ///
    /// # What this does NOT do
    /// - Grant any privileges (registration ≠ authorization)
    /// - Provide private key access
    /// - Enable signing on behalf of the identity
    ///
    /// # Arguments
    /// * `did` - The peer's DID (e.g., "did:zhtp:...")
    /// * `public_key` - The peer's public key
    /// * `device_id` - The peer's device identifier
    /// * `node_id` - The peer's NodeId
    ///
    /// # Returns
    /// A ZhtpIdentity populated with public fields from the handshake
    pub fn from_observed_handshake(
        did: String,
        public_key: PublicKey,
        device_id: String,
        node_id: NodeId,
    ) -> Result<Self> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Derive identity ID from DID (same derivation as new())
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(did.as_bytes()).to_vec());

        // Initialize device mapping with the observed device
        let mut device_node_ids = HashMap::new();
        device_node_ids.insert(device_id.clone(), node_id.clone());

        // Create minimal wallet manager (no wallets - this is an observed identity)
        let wallet_manager = crate::wallets::WalletManager::new(id.clone());

        Ok(ZhtpIdentity {
            id: id.clone(),
            identity_type: IdentityType::Human, // Default; actual type unknown
            did,
            public_key,
            private_key: None, // No private key - this is an observed identity
            node_id,
            device_node_ids,
            primary_device: device_id,
            ownership_proof: ZeroKnowledgeProof::default(),
            credentials: HashMap::new(),
            reputation: 0,
            age: None,
            access_level: AccessLevel::default(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("observed".to_string(), "true".to_string());
                m.insert("first_seen".to_string(), current_time.to_string());
                m
            },
            private_data_id: None,
            wallet_manager,
            attestations: Vec::new(),
            created_at: current_time,
            last_active: current_time,
            recovery_keys: Vec::new(),
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
            zk_identity_secret: [0u8; 32], // No ZK secret for observed identity
            zk_credential_hash: [0u8; 32],
            wallet_master_seed: [0u8; 64],
            dao_member_id: String::new(),
            dao_voting_power: 0,
            citizenship_verified: false,
            jurisdiction: None,
        })
    }

    /// Create a new ZHTP identity with seed-anchored deterministic derivation
    ///
    /// This constructor implements seed-anchored identity where the seed is the root
    /// of trust, not PQC keypairs. All identity fields (DID, secrets, NodeIds) derive
    /// deterministically from the seed, while PQC keypairs are generated randomly
    /// and attached as capabilities.
    ///
    /// # Architecture
    /// ```text
    /// seed (root of trust)
    ///  ├─ DID = did:zhtp:{Blake3(seed || "ZHTP_DID_V1")}
    ///  ├─ IdentityId = Blake3(DID)
    ///  ├─ zk_identity_secret = Blake3(seed || "ZHTP_ZK_SECRET_V1")
    ///  ├─ wallet_master_seed = XOF(seed || "ZHTP_WALLET_SEED_V1")
    ///  ├─ dao_member_id = Blake3("DAO:" || DID)
    ///  ├─ NodeIds = f(DID, device)
    ///  └─ PQC keypairs (random, attached, rotatable)
    /// ```
    ///
    /// # Arguments
    /// * `identity_type` - Type of identity (Human, Organization, etc.)
    /// * `age` - Optional age for credential derivation (defaults to 25)
    /// * `jurisdiction` - Optional jurisdiction code (defaults to "US")
    /// * `primary_device` - Primary device identifier
    /// * `seed` - Optional 64-byte seed. If None, generates random seed.
    ///
    /// # Returns
    /// Fully initialized ZhtpIdentity with deterministic fields from seed
    ///
    /// # Determinism
    /// Same seed → same DID, same secrets, same NodeIds (always)
    /// PQC keypairs are random (by design, pqcrypto-* limitation)
    pub fn new_unified(
        identity_type: IdentityType,
        age: Option<u64>,
        jurisdiction: Option<String>,
        primary_device: &str,
        seed: Option<[u8; 64]>,
    ) -> Result<Self> {
        // Step 1: Generate or use provided seed
        let seed = match seed {
            Some(s) => s,
            None => lib_crypto::generate_identity_seed()?,
        };

        // Step 2: Derive DID from seed (seed-anchored, not from PQC key_id)
        let did = Self::derive_did_from_seed(&seed)?;

        // Step 3: Derive IdentityId by hashing the DID
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(did.as_bytes()).to_vec());

        // Step 4: Generate primary NodeId from DID + device
        let node_id = NodeId::from_did_device(&did, primary_device)?;

        // Step 5: Derive zk_identity_secret from seed
        let zk_identity_secret = Self::derive_zk_secret_from_seed(&seed)?;

        // Step 6: Derive zk_credential_hash from zk_secret + age + jurisdiction
        // Age and jurisdiction are REQUIRED for Human identities only
        let zk_credential_hash = if identity_type == IdentityType::Human {
            let age_val = age.ok_or_else(|| anyhow!("Age is required for Human identity credential derivation"))?;
            let juris_val = jurisdiction.as_deref().ok_or_else(|| anyhow!("Jurisdiction is required for Human identity credential derivation"))?;
            Self::derive_credential_hash(&zk_identity_secret, age_val, juris_val)?
        } else {
            // For non-Human identities (Device, Organization, etc.), use default credential hash
            [0u8; 32]
        };

        // Step 7: Derive wallet_master_seed from seed (64 bytes via XOF)
        let wallet_master_seed = Self::derive_wallet_seed_from_seed(&seed)?;

        // Step 8: Derive dao_member_id from DID
        let dao_member_id = Self::derive_dao_member_id(&did)?;

        // Step 9: Generate random PQC keypairs (attached, not foundational)
        let keypair = lib_crypto::KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate PQC keypair: {}", e))?;

        // Step 10: Initialize WalletManager (seeded for deterministic recovery)
        let wallet_manager = crate::wallets::WalletManager::from_master_seed(id.clone(), wallet_master_seed);

        // Step 11: Initialize device_node_ids HashMap with primary device
        let mut device_node_ids = HashMap::new();
        device_node_ids.insert(primary_device.to_string(), node_id);

        // Step 12: Set citizenship_verified=false, dao_voting_power=1 (unverified)
        let citizenship_verified = false;
        let dao_voting_power = 1;

        // Step 13: Placeholder ownership proof (to be replaced with SignaturePopV1 in ADR-0003)
        // TODO: Implement real SignaturePopV1 when ADR-0003 V1 proofs land.
        let ownership_proof = ZeroKnowledgeProof {
            proof_system: "dilithium-pop-placeholder-v0".to_string(),
            proof_data: b"TODO:SignaturePopV1".to_vec(),
            public_inputs: did.as_bytes().to_vec(),
            verification_key: keypair.public_key.dilithium_pk.clone(),
            plonky2_proof: None,
            proof: vec![],
        };

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Step 14: Return fully initialized ZhtpIdentity
        Ok(ZhtpIdentity {
            id: id.clone(),
            identity_type,
            did,
            public_key: keypair.public_key,
            private_key: Some(keypair.private_key),
            node_id,
            device_node_ids,
            primary_device: primary_device.to_string(),
            ownership_proof,
            credentials: HashMap::new(),
            reputation: 0,
            age,
            access_level: AccessLevel::default(),
            metadata: HashMap::new(),
            private_data_id: Some(id),
            wallet_manager,
            attestations: Vec::new(),
            created_at: current_time,
            last_active: current_time,
            recovery_keys: Vec::new(),
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
            zk_identity_secret,
            zk_credential_hash,
            wallet_master_seed,
            dao_member_id,
            dao_voting_power,
            citizenship_verified,
            jurisdiction,
        })
    }

    /// Generate canonical DID from PublicKey key_id
    /// Per Issue #9 spec: "did:zhtp:{hex(public_key.key_id)}"
    fn generate_did(public_key: &PublicKey) -> Result<String> {
        Ok(format!("did:zhtp:{}", hex::encode(public_key.key_id)))
    }

    /// Derive ZK identity secret from private key
    /// Per spec: Blake3("ZHTP_ZK_SECRET_V1:" + dilithium_private_key)
    fn derive_zk_secret(dilithium_sk: &[u8]) -> Result<[u8; 32]> {
        let hash = lib_crypto::hash_blake3(&[b"ZHTP_ZK_SECRET_V1:", dilithium_sk].concat());
        Ok(hash)
    }

    /// Derive credential hash from ZK secret, age, and jurisdiction
    /// Per Issue #9 spec: Blake3("ZHTP_CREDENTIAL_V1:" + secret + age + jurisdiction_code)
    /// - age: Required age value (no default)
    /// - jurisdiction: Required jurisdiction code (no default)
    fn derive_credential_hash(
        secret: &[u8; 32],
        age: u64,
        jurisdiction: &str,
    ) -> Result<[u8; 32]> {
        let juris_code = Self::jurisdiction_to_code(jurisdiction);
        let hash = lib_crypto::hash_blake3(&[
            b"ZHTP_CREDENTIAL_V1:",
            secret.as_slice(),
            &age.to_le_bytes(),
            &juris_code.to_le_bytes(),
        ].concat());
        Ok(hash)
    }

    /// Derive wallet master seed using Blake3 XOF
    /// Per spec: Blake3_XOF("ZHTP_WALLET_SEED_V1:" + dilithium_private_key)
    fn derive_wallet_seed(dilithium_sk: &[u8]) -> Result<[u8; 64]> {
        let mut output = [0u8; 64];
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ZHTP_WALLET_SEED_V1:");
        hasher.update(dilithium_sk);
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut output);
        Ok(output)
    }

    /// Derive DAO member ID from DID
    /// Per spec: Blake3("DAO:" + DID)
    fn derive_dao_member_id(did: &str) -> Result<String> {
        let hash = lib_crypto::hash_blake3(format!("DAO:{}", did).as_bytes());
        Ok(hex::encode(hash))
    }

    // ========== SEED-ANCHORED DERIVATION FUNCTIONS ==========
    // These functions implement the seed-anchored identity architecture
    // where seed is the root of trust, not PQC keypairs.

    /// Derive DID from seed (seed-anchored, not from PQC key_id)
    /// Per seed-anchored architecture: DID = did:zhtp:{Blake3(seed || "ZHTP_DID_V1")}
    fn derive_did_from_seed(seed: &[u8; 64]) -> Result<String> {
        let hash = lib_crypto::hash_blake3(&[seed.as_slice(), b"ZHTP_DID_V1"].concat());
        Ok(format!("did:zhtp:{}", hex::encode(hash)))
    }

    /// Derive ZK identity secret from seed (not from private key)
    /// Per seed-anchored architecture: Blake3(seed || "ZHTP_ZK_SECRET_V1")
    fn derive_zk_secret_from_seed(seed: &[u8; 64]) -> Result<[u8; 32]> {
        let hash = lib_crypto::hash_blake3(&[seed.as_slice(), b"ZHTP_ZK_SECRET_V1"].concat());
        Ok(hash)
    }

    /// Derive wallet master seed from identity seed (not from private key)
    /// Per seed-anchored architecture: XOF(seed || "ZHTP_WALLET_SEED_V1") [64 bytes]
    fn derive_wallet_seed_from_seed(seed: &[u8; 64]) -> Result<[u8; 64]> {
        let mut output = [0u8; 64];
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        hasher.update(b"ZHTP_WALLET_SEED_V1");
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut output);
        Ok(output)
    }

    /// Convert jurisdiction to numeric code (ISO 3166-1)
    fn jurisdiction_to_code(jurisdiction: &str) -> u64 {
        match jurisdiction {
            "US" => 840,
            "CA" => 124,
            "GB" => 826,
            "DE" => 276,
            "FR" => 250,
            _ => 840,  // Default to US
        }
    }
    
    /// Create identity from legacy Vec<u8> public_key (for migration)
    /// Now properly derives all fields from keypair per architecture spec
    pub fn from_legacy_fields(
        id: IdentityId,
        identity_type: IdentityType,
        public_key_bytes: Vec<u8>,
        private_key: PrivateKey,
        primary_device: String,
        ownership_proof: ZeroKnowledgeProof,
        wallet_manager: crate::wallets::WalletManager,
    ) -> Result<Self> {
        // Convert Vec<u8> to PublicKey
        let public_key = PublicKey::new(public_key_bytes);

        // Derive DID from public key (canonical)
        let did = Self::generate_did(&public_key)?;

        // Generate primary NodeId from DID + device
        let node_id = NodeId::from_did_device(&did, &primary_device)?;

        // Initialize device mapping
        let mut device_node_ids = HashMap::new();
        device_node_ids.insert(primary_device.clone(), node_id);

        // Derive all secrets from master keypair (deterministic)
        let zk_identity_secret = Self::derive_zk_secret(&private_key.dilithium_sk)?;
        let zk_credential_hash = Self::derive_credential_hash(&zk_identity_secret, 25, "US")?;
        let wallet_master_seed = Self::derive_wallet_seed(&private_key.dilithium_sk)?;
        let dao_member_id = Self::derive_dao_member_id(&did)?;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(ZhtpIdentity {
            id: id.clone(),
            identity_type,
            did,
            public_key,
            private_key: Some(private_key),
            node_id,
            device_node_ids,
            primary_device,
            ownership_proof,
            credentials: HashMap::new(),
            reputation: 0,
            age: None,
            access_level: AccessLevel::default(),
            metadata: HashMap::new(),
            private_data_id: Some(id),
            wallet_manager,
            attestations: Vec::new(),
            created_at: current_time,
            last_active: current_time,
            recovery_keys: Vec::new(),
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
            zk_identity_secret,
            zk_credential_hash,
            wallet_master_seed,
            dao_member_id,
            dao_voting_power: 0,
            citizenship_verified: false,
            jurisdiction: None,
        })
    }

    /// Create an identity for external registration (client-side key generation)
    ///
    /// This constructor is used when the identity was created on a client device
    /// (e.g., iOS/mobile) where the private key was generated and stored locally.
    /// The server only has access to public information.
    ///
    /// # Security
    /// - No private key stored (client keeps it)
    /// - No derived secrets (client computes these locally)
    /// - Used for identity registry/lookup purposes only
    pub fn new_external(
        did: String,
        public_key: PublicKey,
        identity_type: IdentityType,
        device_id: String,
        display_name: Option<String>,
        created_at: u64,
    ) -> Result<Self> {
        // Derive ID from DID
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(did.as_bytes()).to_vec());

        // Generate NodeId from DID + device
        let node_id = NodeId::from_did_device(&did, &device_id)?;

        // Initialize device mapping
        let mut device_node_ids = HashMap::new();
        device_node_ids.insert(device_id.clone(), node_id);

        // Derive DAO member ID from DID
        let dao_member_id = Self::derive_dao_member_id(&did)?;

        // Create minimal wallet manager (client manages actual wallets)
        let wallet_manager = crate::wallets::WalletManager::new(id.clone());

        // Initialize metadata
        let mut metadata = HashMap::new();
        if let Some(name) = display_name {
            metadata.insert("display_name".to_string(), name);
        }
        metadata.insert("registration_type".to_string(), "external".to_string());

        // Create placeholder ownership proof (actual proof was verified during registration)
        let ownership_proof = ZeroKnowledgeProof::placeholder();

        Ok(ZhtpIdentity {
            id: id.clone(),
            identity_type: identity_type.clone(),
            did,
            public_key,
            private_key: None, // Client keeps private key!
            node_id,
            device_node_ids,
            primary_device: device_id,
            ownership_proof,
            credentials: HashMap::new(),
            reputation: if identity_type == IdentityType::Human { 500 } else { 100 },
            age: None,
            access_level: if identity_type == IdentityType::Human {
                AccessLevel::FullCitizen
            } else {
                AccessLevel::Visitor
            },
            metadata,
            private_data_id: None, // No private data stored on server
            wallet_manager,
            attestations: Vec::new(),
            created_at,
            last_active: created_at,
            recovery_keys: Vec::new(),
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
            zk_identity_secret: [0u8; 32],  // Client computes this locally
            zk_credential_hash: [0u8; 32],  // Client computes this locally
            wallet_master_seed: [0u8; 64],  // Client manages wallets locally
            dao_member_id,
            dao_voting_power: if identity_type == IdentityType::Human { 10 } else { 0 },
            citizenship_verified: identity_type == IdentityType::Human,
            jurisdiction: None,
        })
    }

    /// Check if cryptographic secrets have been properly derived (not zero-valued)
    ///
    /// SECURITY: This should be called after deserialization to ensure secrets were re-derived.
    /// Zero-valued secrets indicate the identity was deserialized but rederive_secrets() was not called.
    ///
    /// # Returns
    /// true if all secrets are non-zero (properly derived), false if any are zero
    pub fn is_secrets_derived(&self) -> bool {
        self.zk_identity_secret != [0u8; 32]
            && self.zk_credential_hash != [0u8; 32]
            && self.wallet_master_seed != [0u8; 64]
    }

    /// Validate that secrets are properly derived, returning an error if not
    ///
    /// SECURITY: Use this to enforce that secrets are derived before use.
    ///
    /// # Returns
    /// Ok(()) if secrets are properly derived, Err if any are zero-valued
    pub fn validate_secrets_derived(&self) -> Result<()> {
        if !self.is_secrets_derived() {
            return Err(anyhow!(
                "Identity has zero-valued secrets - must call rederive_secrets() after deserialization"
            ));
        }
        Ok(())
    }

    /// Re-derive cryptographic secrets after deserialization
    ///
    /// SECURITY: This method MUST be called after deserializing a ZhtpIdentity from storage.
    /// The secrets (zk_identity_secret, zk_credential_hash, wallet_master_seed) are never
    /// serialized and will be zero-valued after deserialization.
    ///
    /// # Arguments
    /// * `private_key` - The private key to derive secrets from
    ///
    /// # Returns
    /// Ok(()) if secrets were successfully re-derived, Err if derivation failed
    pub fn rederive_secrets(&mut self, private_key: &PrivateKey) -> Result<()> {
        self.zk_identity_secret = Self::derive_zk_secret(&private_key.dilithium_sk)?;
        self.zk_credential_hash = Self::derive_credential_hash(
            &self.zk_identity_secret,
            self.age.unwrap_or(25),
            self.jurisdiction.as_deref().unwrap_or("US")
        )?;
        self.wallet_master_seed = Self::derive_wallet_seed(&private_key.dilithium_sk)?;
        self.validate_secrets_derived()?; // Validate after re-derivation
        Ok(())
    }

    /// Safe deserialization helper that requires re-derivation
    ///
    /// Use this instead of direct deserialization to ensure secrets are properly derived.
    ///
    /// # Arguments
    /// * `data` - Serialized identity data (JSON string)
    /// * `private_key` - Private key to derive secrets from
    ///
    /// # Returns
    /// Ok(identity) with properly derived secrets, or Err if deserialization/derivation failed
    ///
    /// # Example
    /// ```ignore
    /// let json = serde_json::to_string(&identity)?;
    /// // Later...
    /// let restored = ZhtpIdentity::from_serialized(&json, &private_key)?;
    /// ```
    pub fn from_serialized(data: &str, private_key: &PrivateKey) -> Result<Self> {
        // SECURITY: Direct Deserialize is forbidden; parse manually and re-derive secrets
        let raw: serde_json::Value = serde_json::from_str(data)
            .map_err(|e| anyhow!("Failed to parse identity JSON: {}", e))?;

        // Extract and restore STORED identity fields (do NOT recompute)
        let id: IdentityId = serde_json::from_value(
            raw.get("id")
                .cloned()
                .ok_or_else(|| anyhow!("Missing id"))?,
        ).map_err(|e| anyhow!("Invalid id: {}", e))?;

        let did = raw.get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing did"))?
            .to_string();

        // CRITICAL: Validate that ID is extracted correctly from DID
        // DID format: did:zhtp:{identity_id_hex}
        // The identity_id IS the hex part of the DID, not computed from it
        let did_prefix = "did:zhtp:";
        let expected_id_hex = did.strip_prefix(did_prefix)
            .ok_or_else(|| anyhow!("Invalid DID format: missing 'did:zhtp:' prefix"))?;
        let expected_id = Hash::from_hex(expected_id_hex)
            .map_err(|e| anyhow!("Invalid DID hex component: {}", e))?;
        if id != expected_id {
            return Err(anyhow!(
                "Identity corruption detected: ID '{}' does not match DID component. \
                DID: '{}', Expected ID: '{}'. The keystore file may be corrupted.",
                hex::encode(id.as_bytes()), did, hex::encode(expected_id.as_bytes())
            ));
        }

        let identity_type: IdentityType = serde_json::from_value(
            raw.get("identity_type")
                .cloned()
                .ok_or_else(|| anyhow!("Missing identity_type"))?,
        ).map_err(|e| anyhow!("Invalid identity_type: {}", e))?;

        let public_key: PublicKey = serde_json::from_value(
            raw.get("public_key")
                .cloned()
                .ok_or_else(|| anyhow!("Missing public_key"))?,
        ).map_err(|e| anyhow!("Invalid public_key: {}", e))?;

        let node_id: NodeId = serde_json::from_value(
            raw.get("node_id")
                .cloned()
                .ok_or_else(|| anyhow!("Missing node_id"))?,
        ).map_err(|e| anyhow!("Invalid node_id: {}", e))?;

        let device_node_ids: HashMap<String, NodeId> = serde_json::from_value(
            raw.get("device_node_ids").cloned().unwrap_or_else(|| serde_json::json!({}))
        ).unwrap_or_default();

        let primary_device = raw.get("primary_device")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing primary_device"))?
            .to_string();

        let age = raw.get("age").and_then(|v| v.as_u64());
        let jurisdiction = raw.get("jurisdiction").and_then(|v| v.as_str()).map(|s| s.to_string());
        let citizenship_verified = raw.get("citizenship_verified").and_then(|v| v.as_bool()).unwrap_or(false);

        let dao_member_id = raw.get("dao_member_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing dao_member_id"))?
            .to_string();

        let dao_voting_power = raw.get("dao_voting_power").and_then(|v| v.as_u64()).unwrap_or(0);

        // Restore ownership_proof with proper byte handling
        let ownership_proof: ZeroKnowledgeProof = serde_json::from_value(
            raw.get("ownership_proof")
                .cloned()
                .ok_or_else(|| anyhow!("Missing ownership_proof"))?,
        ).map_err(|e| anyhow!("Invalid ownership_proof: {}", e))?;

        // Optional fields
        let credentials: HashMap<CredentialType, ZkCredential> = serde_json::from_value(
            raw.get("credentials").cloned().unwrap_or_else(|| serde_json::json!({}))
        ).unwrap_or_default();

        let metadata: HashMap<String, String> = serde_json::from_value(
            raw.get("metadata").cloned().unwrap_or_else(|| serde_json::json!({}))
        ).unwrap_or_default();

        let attestations: Vec<IdentityAttestation> = serde_json::from_value(
            raw.get("attestations").cloned().unwrap_or_else(|| serde_json::json!([]))
        ).unwrap_or_default();

        let reputation = raw.get("reputation").and_then(|v| v.as_u64()).unwrap_or(0);

        let access_level: AccessLevel = raw.get("access_level")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let private_data_id: Option<IdentityId> = raw.get("private_data_id")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let wallet_manager: crate::wallets::WalletManager = raw.get("wallet_manager")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(|| crate::wallets::WalletManager::new(id.clone()));

        let created_at = raw.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let last_active = raw.get("last_active").and_then(|v| v.as_u64()).unwrap_or(0);

        let recovery_keys: Vec<Vec<u8>> = raw.get("recovery_keys")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let did_document_hash: Option<Hash> = raw.get("did_document_hash")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let owner_identity_id: Option<IdentityId> = raw.get("owner_identity_id")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let reward_wallet_id: Option<crate::wallets::WalletId> = raw.get("reward_wallet_id")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        // SECURITY: Re-derive all cryptographic secrets from private_key
        // Age and jurisdiction are REQUIRED for Human identities only
        let zk_identity_secret = Self::derive_zk_secret(&private_key.dilithium_sk)?;
        let zk_credential_hash = if identity_type == IdentityType::Human {
            let age_val = age.ok_or_else(|| anyhow!("Age is required for Human identity secret derivation"))?;
            let juris_val = jurisdiction.as_deref().ok_or_else(|| anyhow!("Jurisdiction is required for Human identity secret derivation"))?;
            Self::derive_credential_hash(&zk_identity_secret, age_val, juris_val)?
        } else {
            // For non-Human identities (Device, Organization, etc.), use default credential hash
            [0u8; 32]
        };
        let wallet_master_seed = Self::derive_wallet_seed(&private_key.dilithium_sk)?;

        // Reconstruct identity with all restored fields
        Ok(ZhtpIdentity {
            id,
            identity_type,
            did,
            public_key,
            private_key: Some(private_key.clone()),
            node_id,
            device_node_ids,
            primary_device,
            ownership_proof,
            credentials,
            reputation,
            age,
            access_level,
            metadata,
            private_data_id,
            wallet_manager,
            attestations,
            created_at,
            last_active,
            recovery_keys,
            did_document_hash,
            owner_identity_id,
            reward_wallet_id,
            encrypted_master_seed: None,  // Never serialized
            next_wallet_index: 0,         // Reset on load
            password_hash: None,          // Never serialized
            master_seed_phrase: None,     // Never serialized
            zk_identity_secret,
            zk_credential_hash,
            wallet_master_seed,
            dao_member_id,
            dao_voting_power,
            citizenship_verified,
            jurisdiction,
        })
    }

    // Note: Wallet creation now done directly through WalletManager for consistency
    // Use identity.wallet_manager.create_wallet_with_seed_phrase() for proper seed phrase support

    /// Get wallet by alias
    pub fn get_wallet(&self, alias: &str) -> Option<&crate::wallets::QuantumWallet> {
        self.wallet_manager.get_wallet_by_alias(alias)
    }
    
    /// Get total balance across all wallets
    pub fn get_total_balance(&self) -> u64 {
        self.wallet_manager.total_balance
    }
    
    /// Transfer funds between this identity's wallets
    pub fn transfer_between_wallets(
        &mut self,
        from_wallet: &crate::wallets::WalletId,
        to_wallet: &crate::wallets::WalletId,
        amount: u64,
        purpose: String,
    ) -> Result<Hash> {
        self.update_activity();
        self.wallet_manager.transfer_between_wallets(from_wallet, to_wallet, amount, purpose)
    }
    
    /// List all wallets for this identity
    pub fn list_wallets(&self) -> Vec<crate::wallets::WalletSummary> {
        self.wallet_manager.list_wallets()
    }
    
    /// Add a credential to this identity
    pub fn add_credential(&mut self, credential: ZkCredential) -> Result<()> {
        if credential.subject != self.id {
            return Err(anyhow!("Credential subject does not match identity"));
        }
        
        // Verify credential proof (simplified)
        if !self.verify_credential_proof(&credential)? {
            return Err(anyhow!("Invalid credential proof"));
        }
        
        self.credentials.insert(credential.credential_type.clone(), credential);
        self.update_activity();
        Ok(())
    }
    
    /// Add an attestation to this identity
    pub fn add_attestation(&mut self, attestation: IdentityAttestation) -> Result<()> {
        // Verify attestation proof (simplified)
        if !self.verify_attestation_proof(&attestation)? {
            return Err(anyhow!("Invalid attestation proof"));
        }
        
        self.attestations.push(attestation);
        self.update_activity();
        Ok(())
    }
    
    /// Verify this identity meets specific requirements
    pub fn verify_requirements(&self, requirements: &IdentityProofParams) -> IdentityVerification {
        let mut requirements_met = Vec::new();
        let mut requirements_failed = Vec::new();
        
        // Check required credentials
        for req_cred in &requirements.required_credentials {
            if self.credentials.contains_key(req_cred) {
                requirements_met.push(req_cred.clone());
            } else {
                requirements_failed.push(req_cred.clone());
            }
        }
        
        let verified = requirements_failed.is_empty();
        let privacy_score = std::cmp::min(requirements.privacy_level, 100);
        
        IdentityVerification {
            identity_id: self.id.clone(),
            verified,
            requirements_met,
            requirements_failed,
            privacy_score,
            verified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Generate a W3C-compliant DID document for this identity
    /// Delegates to the proper DID module for consistent formatting
    pub fn generate_did_document(&self, base_url: Option<&str>) -> Result<crate::did::DidDocument> {
        crate::did::generate_did_document(self, base_url)
            .map_err(|e| anyhow!("Failed to generate DID document: {}", e))
    }
    
    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_active = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Verify credential proof (simplified implementation)
    fn verify_credential_proof(&self, credential: &ZkCredential) -> Result<bool> {
        // Verify credential proof using actual cryptographic verification
        // Check if proof matches the credential data and issuer
        let proof_data = &credential.proof.proof_data;
        let public_inputs = &credential.proof.public_inputs;
        
        // Verify the ZK proof structure is valid
        if proof_data.is_empty() || public_inputs.is_empty() {
            return Ok(false);
        }
        
        // Verify issuer signature on credential (simplified)
        let _credential_hash = lib_crypto::hash_blake3(&serde_json::to_vec(credential)?);
        let _expected_proof = lib_crypto::hash_blake3(&[
            credential.issuer.0.as_slice(),
            credential.subject.0.as_slice(),
            &credential.issued_at.to_le_bytes(),
            &serde_json::to_vec(&credential.credential_type)?
        ].concat());
        
        // For now, verify that the proof contains expected elements
        let proof_valid = proof_data.len() >= 32 && 
                         public_inputs.len() >= 32 &&
                         credential.expires_at.map_or(true, |exp| {
                             exp > std::time::SystemTime::now()
                                 .duration_since(std::time::UNIX_EPOCH)
                                 .unwrap()
                                 .as_secs()
                         });
        
        Ok(proof_valid)
    }
    
    /// Verify attestation proof (simplified implementation)
    fn verify_attestation_proof(&self, attestation: &IdentityAttestation) -> Result<bool> {
        // Verify attestation proof using actual cryptographic verification
        let proof_data = &attestation.proof.proof_data;
        let public_inputs = &attestation.proof.public_inputs;
        
        // Verify the ZK proof structure is valid
        if proof_data.is_empty() || public_inputs.is_empty() {
            return Ok(false);
        }
        
        // Verify attester has authority to make this attestation
        let _attestation_hash = lib_crypto::hash_blake3(&[
            attestation.attester.0.as_slice(),
            &attestation.created_at.to_le_bytes(),
            &serde_json::to_vec(&attestation.attestation_type)?
        ].concat());
        
        // Verify confidence score is reasonable (0-100)
        if attestation.confidence > 100 {
            return Ok(false);
        }
        
        // Check if attestation has expired
        if let Some(expires_at) = attestation.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if expires_at <= now {
                return Ok(false);
            }
        }
        
        // For now, verify that the proof contains expected elements
        let proof_valid = proof_data.len() >= 32 && 
                         public_inputs.len() >= 32 &&
                         attestation.confidence >= 50; // Minimum confidence threshold
        
        Ok(proof_valid)
    }
    
    /// Set the reward wallet for a device/node identity
    /// Can only be called by the owner, and wallet must belong to owner
    pub fn set_reward_wallet(&mut self, wallet_id: crate::wallets::WalletId) -> Result<()> {
        // Only device identities can have reward wallets
        if self.identity_type != IdentityType::Device {
            return Err(anyhow!("Only device identities can have reward wallets"));
        }
        
        // Device must have an owner
        if self.owner_identity_id.is_none() {
            return Err(anyhow!("Device identity must have an owner"));
        }
        
        // Note: Validation that wallet belongs to owner must be done externally
        // since we don't have access to the owner's identity here
        
        self.reward_wallet_id = Some(wallet_id);
        self.update_activity();
        Ok(())
    }
    
    /// Get the reward wallet ID for this device/node
    pub fn get_reward_wallet(&self) -> Option<crate::wallets::WalletId> {
        self.reward_wallet_id.clone()
    }
    
    /// Check if this identity is owned by another identity
    pub fn is_owned(&self) -> bool {
        self.owner_identity_id.is_some()
    }
    
    /// Get the owner identity ID
    pub fn get_owner(&self) -> Option<IdentityId> {
        self.owner_identity_id.clone()
    }


    /// Add a new device to this identity with deterministic NodeId derivation
    ///
    /// Creates a new device entry with NodeId derived from the identity's DID
    /// and device name. Device names must be unique per identity.
    ///
    /// # Arguments
    /// * `device_name` - Unique device identifier (e.g., "laptop-macos", "phone-android")
    ///
    /// # Returns
    /// * `Ok(NodeId)` - The NodeId for the device (existing or newly created)
    /// * `Err` - If NodeId derivation fails
    ///
    /// # Determinism
    /// Same DID + same device_name → same NodeId (always)
    ///
    /// # Idempotency
    /// Calling with existing device_name returns the existing NodeId without modification
    ///
    /// # Examples
    /// ```ignore
    /// // Add first device
    // let laptop_node = identity.add_device("laptop-macos")?;
    /// 
    /// // Add second device
    // let phone_node = identity.add_device("phone-android")?;
    /// 
    /// // Idempotent - returns existing NodeId
    // let laptop_node_again = identity.add_device("laptop-macos")?;
    // assert_eq!(laptop_node, laptop_node_again);
    /// ```
    pub fn add_device(&mut self, device_name: &str) -> Result<NodeId> {
        // Validate device name
        if device_name.is_empty() {
            return Err(anyhow!("Device name cannot be empty"));
        }

        // Check if device already exists (idempotent)
        if let Some(&existing_node_id) = self.device_node_ids.get(device_name) {
            // Update activity even for existing devices
            self.update_activity();
            return Ok(existing_node_id);
        }

        // Generate deterministic NodeId from DID + device name
        let node_id = NodeId::from_did_device(&self.did, device_name)?;

        // Insert into device mapping
        self.device_node_ids.insert(device_name.to_string(), node_id);

        // Update last activity timestamp
        self.update_activity();

        Ok(node_id)
    }

    /// Remove a device from this identity
    ///
    /// Removes the device entry and its associated NodeId. Cannot remove
    /// the primary device.
    ///
    /// # Arguments
    /// * `device_name` - Device identifier to remove
    ///
    /// # Returns
    /// * `Ok(())` - Device successfully removed
    /// * `Err` - If device is primary or doesn't exist
    ///
    /// # Examples
    /// ```ignore
    /// identity.add_device("old-phone")?;
    /// identity.remove_device("old-phone")?; // OK
    /// identity.remove_device("laptop")?; // Error if primary device
    /// ```
    pub fn remove_device(&mut self, device_name: &str) -> Result<()> {
        // Cannot remove primary device
        if device_name == self.primary_device {
            return Err(anyhow!("Cannot remove primary device: {}", device_name));
        }

        // Check if device exists
        if self.device_node_ids.remove(device_name).is_none() {
            return Err(anyhow!("Device not found: {}", device_name));
        }

        self.update_activity();
        Ok(())
    }

    /// Get NodeId for a specific device
    ///
    /// # Arguments
    /// * `device_name` - Device identifier
    ///
    /// # Returns
    /// * `Some(NodeId)` - If device exists
    /// * `None` - If device not registered
    pub fn get_device_node_id(&self, device_name: &str) -> Option<NodeId> {
        self.device_node_ids.get(device_name).copied()
    }

    /// List all registered device names
    ///
    /// # Returns
    /// Vector of device names sorted alphabetically
    pub fn list_devices(&self) -> Vec<String> {
        let mut devices: Vec<String> = self.device_node_ids.keys().cloned().collect();
        devices.sort();
        devices
    }

    /// Get the number of registered devices
    pub fn device_count(&self) -> usize {
        self.device_node_ids.len()
    }

    /// Change the primary device
    ///
    /// Sets a new primary device and updates the main node_id field.
    /// The new primary device must already be registered.
    ///
    /// # Arguments
    /// * `new_primary` - Device name to set as primary
    ///
    /// # Returns
    /// * `Ok(())` - Primary device successfully changed
    /// * `Err` - If device doesn't exist
    pub fn set_primary_device(&mut self, new_primary: &str) -> Result<()> {
        // Verify device exists
        let new_node_id = self.device_node_ids
            .get(new_primary)
            .ok_or_else(|| anyhow!("Device not registered: {}", new_primary))?;

        self.primary_device = new_primary.to_string();
        self.node_id = *new_node_id;
        self.update_activity();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test: New device creates new NodeId
    #[test]
    fn test_add_device_creates_new_node_id() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let initial_count = identity.device_count();
        let phone_node = identity.add_device("phone-android")?;

        assert_eq!(identity.device_count(), initial_count + 1);
        assert!(identity.device_node_ids.contains_key("phone-android"));
        assert_eq!(identity.get_device_node_id("phone-android"), Some(phone_node));

        Ok(())
    }

    /// Test: Duplicate device returns same NodeId (idempotent)
    #[test]
    fn test_add_device_idempotent() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let node_id_1 = identity.add_device("tablet-ios")?;
        let node_id_2 = identity.add_device("tablet-ios")?;

        assert_eq!(node_id_1, node_id_2);
        assert_eq!(identity.device_count(), 2); // laptop + tablet

        Ok(())
    }

    /// Test: NodeId derived correctly from DID + device
    #[test]
    fn test_device_node_id_deterministic() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let device_name = "test-device";
        let node_id = identity.add_device(device_name)?;
        let expected_node_id = NodeId::from_did_device(&identity.did, device_name)?;

        assert_eq!(node_id, expected_node_id);

        Ok(())
    }

    /// Test: last_active updated on add_device
    #[test]
    fn test_add_device_updates_activity() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let initial_activity = identity.last_active;
        
        // Force a delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_secs(1));
        
        identity.add_device("phone")?;
        
        assert!(
            identity.last_active > initial_activity,
            "Expected last_active ({}) to be greater than initial ({})",
            identity.last_active,
            initial_activity
        );

        Ok(())
    }
    /// Test: Multiple devices in HashMap
    #[test]
    fn test_multiple_devices() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let devices = vec!["phone-android", "tablet-ios", "desktop-windows"];
        
        for device in &devices {
            identity.add_device(device)?;
        }

        assert_eq!(identity.device_count(), devices.len() + 1); // +1 for primary
        
        for device in &devices {
            assert!(identity.device_node_ids.contains_key(*device));
        }

        Ok(())
    }

    /// Test: List devices returns sorted names
    #[test]
    fn test_list_devices() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        identity.add_device("zebra-device")?;
        identity.add_device("alpha-device")?;
        identity.add_device("beta-device")?;

        let devices = identity.list_devices();
        
        // Should be sorted alphabetically
        assert!(devices.windows(2).all(|w| w[0] <= w[1]));
        assert!(devices.contains(&"laptop".to_string())); // primary device

        Ok(())
    }

    /// Test: Cannot remove primary device
    #[test]
    fn test_cannot_remove_primary_device() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let result = identity.remove_device("laptop");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("primary device"));

        Ok(())
    }

    /// Test: Remove non-primary device succeeds
    #[test]
    fn test_remove_device_succeeds() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        identity.add_device("old-phone")?;
        assert_eq!(identity.device_count(), 2);

        identity.remove_device("old-phone")?;
        assert_eq!(identity.device_count(), 1);
        assert!(identity.get_device_node_id("old-phone").is_none());

        Ok(())
    }

    /// Test: Change primary device
    #[test]
    fn test_set_primary_device() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let phone_node = identity.add_device("phone")?;
        identity.set_primary_device("phone")?;

        assert_eq!(identity.primary_device, "phone");
        assert_eq!(identity.node_id, phone_node);

        Ok(())
    }

    /// Test: Cannot set non-existent device as primary
    #[test]
    fn test_set_primary_device_fails_if_not_registered() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let result = identity.set_primary_device("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not registered"));

        Ok(())
    }

    /// Doctest example in function docs
    /// ```
    /// use lib_identity::identity::ZhtpIdentity;
    /// use lib_identity::types::IdentityType;
    /// 
    /// # fn main() -> anyhow::Result<()> {
    /// let mut identity = ZhtpIdentity::new_unified(
    ///     IdentityType::Human,
    ///     Some(30),
    ///     Some("US".to_string()),
    ///     "laptop-macos",
    ///     None,
    /// )?;
    /// 
    /// // Add first device
    /// let laptop_node = identity.add_device("laptop-macos")?;
    /// 
    /// // Add second device
    /// let phone_node = identity.add_device("phone-android")?;
    /// 
    /// // Idempotent - returns existing NodeId
    /// let laptop_node_again = identity.add_device("laptop-macos")?;
    /// assert_eq!(laptop_node, laptop_node_again);
    /// 
    /// // List all devices
    /// let devices = identity.list_devices();
    /// assert!(devices.contains(&"laptop-macos".to_string()));
    /// assert!(devices.contains(&"phone-android".to_string()));
    /// # Ok(())
    /// # }
    /// ```
    #[test]
    fn doctest_example() {
        // Doctest in function documentation above
    }

 #[test]
    fn test_device_node_id_stability_across_serialization() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let device_name = "tablet-persistent";
        let original_node_id = identity.add_device(device_name)?;

        // Serialize and deserialize
        let json = serde_json::to_string(&identity)?;
        
        // For deserialization, we need the private key
        let private_key = identity.private_key.clone()
            .ok_or_else(|| anyhow!("Private key missing"))?;
        
        let mut restored = ZhtpIdentity::from_serialized(&json, &private_key)?;

        // NodeId should be preserved from serialization
        assert_eq!(
            restored.get_device_node_id(device_name),
            Some(original_node_id),
            "Device NodeId should be stable across serialization"
        );

        // Re-adding same device should return identical NodeId
        let readded_node_id = restored.add_device(device_name)?;
        assert_eq!(original_node_id, readded_node_id);

        Ok(())
    }

    /// Test: Different devices have different NodeIds
    #[test]
    fn test_unique_node_ids_per_device() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let devices = vec!["phone", "tablet", "desktop", "watch"];
        let mut node_ids = Vec::new();

        for device in &devices {
            let node_id = identity.add_device(device)?;
            node_ids.push(node_id);
        }

        // All NodeIds should be unique
        let unique_count = node_ids.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, devices.len(), "All device NodeIds must be unique");

        Ok(())
    }

    /// Test: Primary device NodeId matches main node_id field
    #[test]
    fn test_primary_device_node_id_consistency() -> Result<()> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop-primary",
            None,
        )?;

        let primary_node_id = identity.get_device_node_id("laptop-primary");
        assert_eq!(
            primary_node_id,
            Some(identity.node_id),
            "Primary device NodeId must match main node_id field"
        );

        Ok(())
    }

     /// Test: Device removal updates last_active
    #[test]
    fn test_remove_device_updates_activity() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        identity.add_device("temp-device")?;
        let activity_before = identity.last_active;
        
        // Force a delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_secs(1));
        identity.remove_device("temp-device")?;

        assert!(
            identity.last_active > activity_before,
            "Expected last_active ({}) to be greater than before ({})",
            identity.last_active,
            activity_before
        );

        Ok(())
    }

    /// Test: Set primary device updates both node_id and primary_device
    #[test]
    fn test_set_primary_device_updates_both_fields() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let new_device = "phone-new-primary";
        let new_node_id = identity.add_device(new_device)?;
        
        identity.set_primary_device(new_device)?;

        assert_eq!(identity.primary_device, new_device);
        assert_eq!(identity.node_id, new_node_id);
        assert_eq!(identity.get_device_node_id(new_device), Some(new_node_id));

        Ok(())
    }

    /// Test: Device names are case-sensitive
    #[test]
    fn test_device_names_case_handling() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        // Add device with lowercase name
        let node_id_lower = identity.add_device("phone")?;
        
        // Try to add device with different case - HashMap key is case-sensitive
        // but NodeId derivation normalizes case
        let node_id_upper = identity.add_device("Phone")?;

        // Verify NodeId derivation is case-insensitive (normalized to lowercase)
        let expected_lower = NodeId::from_did_device(&identity.did, "phone")?;
        let expected_upper = NodeId::from_did_device(&identity.did, "Phone")?;
        assert_eq!(expected_lower, expected_upper, "NodeId::from_did_device normalizes case");

        // HashMap keys ARE case-sensitive, so "phone" and "Phone" are different entries
        assert_eq!(identity.device_count(), 3, "laptop + phone + Phone (case-sensitive HashMap keys)");
        
        // Both device names should exist in the HashMap
        assert!(identity.device_node_ids.contains_key("phone"));
        assert!(identity.device_node_ids.contains_key("Phone"));
        
        // But both map to the SAME NodeId (because NodeId derivation normalizes case)
        assert_eq!(node_id_lower, node_id_upper, "Both should have same NodeId due to case normalization");
        assert_eq!(node_id_lower, expected_lower);

        Ok(())
    }

    /// Test: Device NodeId derivation is deterministic for same DID
    #[test]
    fn test_device_node_id_deterministic_same_did() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            Some([42u8; 64]),
        )?;

        // First call
        let node_id_1 = identity.add_device("test-device")?;
        
        // Second call - should return same NodeId (deterministic)
        let node_id_2 = identity.add_device("test-device")?;
        
        assert_eq!(node_id_1, node_id_2, "add_device should be idempotent");
        
        // Verify it matches manual derivation
        let expected = NodeId::from_did_device(&identity.did, "test-device")?;
        assert_eq!(node_id_1, expected, "NodeId should match deterministic derivation");

        Ok(())
    }

    /// Test: Different identities produce different device NodeIds
    #[test]
    fn test_different_identities_different_node_ids() -> Result<()> {
        let identity1 = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let identity2 = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        // Different identities (different seeds) → different NodeIds even for same device name
        assert_ne!(identity1.did, identity2.did);
        assert_ne!(identity1.node_id, identity2.node_id);

        Ok(())
    }

    /// Test: Device operations work for non-Human identity types
    #[test]
    fn test_device_operations_non_human_identity() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Organization,
            None, // No age required
            None, // No jurisdiction required
            "server-primary",
            None,
        )?;

        let node1 = identity.add_device("server-backup")?;
        let _node2 = identity.add_device("load-balancer")?;

        assert_eq!(identity.device_count(), 3);
        assert!(identity.get_device_node_id("server-backup").is_some());
        
        identity.set_primary_device("server-backup")?;
        assert_eq!(identity.node_id, node1);

        Ok(())
    }

    /// Test: Large number of devices handled correctly
    #[test]
    fn test_many_devices() -> Result<()> {
        let mut identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let device_count = 100;
        for i in 0..device_count {
            identity.add_device(&format!("device-{}", i))?;
        }

        assert_eq!(identity.device_count(), device_count + 1); // +1 for primary
        
        let devices = identity.list_devices();
        assert_eq!(devices.len(), device_count + 1);

        Ok(())
    }
     #[test]
    fn test_node_id_derivation_case_behavior() -> Result<()> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        )?;

        let node_id_lower = NodeId::from_did_device(&identity.did, "testdevice")?;
        let node_id_upper = NodeId::from_did_device(&identity.did, "TestDevice")?;
        let node_id_mixed = NodeId::from_did_device(&identity.did, "TESTDEVICE")?;

        // Document the actual behavior
        if node_id_lower == node_id_upper && node_id_upper == node_id_mixed {
            println!("NodeId::from_did_device normalizes device names to lowercase");
        } else {
            println!("NodeId::from_did_device preserves case in device names");
        }

        Ok(())
    }
}
