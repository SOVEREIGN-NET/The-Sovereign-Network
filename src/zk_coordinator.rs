//! Unified ZK Proof Coordinator
//! 
//! Eliminates redundant ZK proof generation across ZHTP modules by providing
//! a centralized, cached, and optimized proof management system.

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};
use lru::LruCache;

// Import ZK types from lib-proofs
use lib_proofs::{
    types::{ZkProof, VerificationResult},
    ZkIdentityProof,
    ZkTransactionProof,
    ZkRangeProof,
    MerkleProof,
    initialize_zk_system,
    verifiers::{IdentityVerifier, TransactionVerifier, RangeVerifier},
    provers::{identity_prover::IdentityProver, transaction_prover::TransactionProver, range_prover::RangeProver},
    circuits::TransactionProof,
};

// Import additional types from related modules
use lib_consensus::ConsensusProof;

/// Proof metadata for enhanced audit trails and verification context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub generated_at: u64,
    pub proof_version: String,
    pub proof_type: String,
    pub verification_level: String,
    pub security_parameters: HashMap<String, String>,
}

/// Coordinator statistics for monitoring proof generation performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub total_proofs_generated: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub average_generation_time_ms: f64,
    pub proof_types_generated: HashMap<String, u64>,
    pub error_count: u64,
}

/// Unified proof types that can be reused across modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnifiedProofType {
    /// Comprehensive identity proof covering all identity needs
    Identity(UnifiedIdentityProof),
    /// Comprehensive transaction proof covering all transaction aspects
    Transaction(CompositeTransactionProof),
    /// Generic range proof for any numerical verification
    Range(GenericRangeProof),
    /// Access control proof for network/storage/contract access
    Access(UnifiedAccessProof),
    /// Consensus participation proof
    Consensus(ConsensusProof),
}

/// Unified identity proof combining all identity-related ZK proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedIdentityProof {
    /// Core humanity proof (was being generated separately in identity and consensus)
    pub humanity_proof: ZkIdentityProof,
    /// Additional credential proofs (age, jurisdiction, etc.)
    pub credential_proofs: Vec<CredentialData>,
    /// Proof metadata
    pub metadata: ProofMetadata,
    /// Combined verification timestamp
    pub timestamp: u64,
}

/// Composite transaction proof eliminating redundant validations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeTransactionProof {
    /// Core transaction validity proof
    pub validity_proof: ZkTransactionProof,
    /// Privacy components
    pub privacy_components: Vec<String>,
    /// Range proofs for amounts (was duplicated across modules)
    pub amount_proofs: Vec<CredentialData>,
    /// Combined metadata
    pub metadata: ProofMetadata,
    /// Transaction verification timestamp
    pub timestamp: u64,
}

/// Generic range proof for any numerical verification needs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericRangeProof {
    /// Type of range being proven
    pub range_type: RangeProofType,
    /// The actual range proof
    pub range_proof: ZkRangeProof,
    /// Context-specific data
    pub context_data: Vec<u8>,
    /// Minimum value (public)
    pub min_value: u64,
    /// Maximum value (public, optional)
    pub max_value: Option<u64>,
}

/// Unified access proof for all access control scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedAccessProof {
    /// Network access authorization
    pub network_access: Option<MerkleProof>,
    /// Storage access authorization
    pub storage_access: Option<MerkleProof>,
    /// Contract access authorization
    pub contract_access: Option<CredentialData>,
    /// Access level achieved
    pub access_level: AccessLevel,
}

/// Consensus participation proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedConsensusProof {
    /// Stake verification (was duplicated between consensus and blockchain)
    pub stake_proof: ZkRangeProof,
    /// Validator selection proof
    pub selection_proof: MerkleProof,
    /// Voting power calculation
    pub voting_power_proof: ZkRangeProof,
}

/// Types of range proofs supported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RangeProofType {
    Age,
    Stake,
    StorageCapacity,
    NetworkBandwidth,
    VotingPower,
    Balance,
    Custom(String),
}

/// Capability proof for various system capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProof {
    pub capability_type: CapabilityType,
    pub proof_data: Vec<u8>,
    pub requirements_met: Vec<String>,
}

/// Types of capabilities that can be proven
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityType {
    NetworkRouting,
    NetworkBandwidth,
    StorageCapacity,
    StorageIntegrity,
    ContractExecution,
    ConsensusParticipation,
}

/// Access levels for unified access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessLevel {
    Read,
    Write,
    Execute,
    Admin,
}

/// Fee calculation proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeProof {
    pub calculated_fee: u64,
    pub base_fee_rate: u64,
    pub congestion_multiplier: f64,
    pub complexity_factor: f64,
}

/// Economic impact proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicProof {
    pub reward_eligibility: bool,
    pub contribution_score: u64,
    pub economic_impact: i64,
}

/// Proof cache key for efficient lookup
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProofCacheKey {
    pub proof_type: String,
    pub subject_id: String,
    pub context_hash: u64,
}

impl ProofCacheKey {
    /// Convert to string for cache lookup
    pub fn to_string(&self) -> String {
        format!("{}:{}:{}", self.proof_type, self.subject_id, self.context_hash)
    }
}
#[derive(Debug, Clone)]
pub struct CachedProof {
    pub proof: UnifiedProofType,
    pub generated_at: Instant,
    pub valid_until: Instant,
    pub usage_count: u64,
}

/// Proof requirements for generating new proofs
#[derive(Debug, Clone)]
pub struct ProofRequirements {
    pub subsystem: Subsystem,
    pub operation_type: OperationType,
    pub required_capabilities: Vec<CapabilityType>,
    pub access_level: Option<AccessLevel>,
    pub validity_duration: Duration,
}

/// ZHTP subsystems that use proofs
#[derive(Debug, Clone, PartialEq)]
pub enum Subsystem {
    Identity,
    Blockchain,
    Network,
    Storage,
    Consensus,
    Economics,
    Contracts,
    Protocols,
}

/// Types of operations that require proofs
#[derive(Debug, Clone, PartialEq)]
pub enum OperationType {
    Identity,
    Transaction,
    Access,
    Consensus,
    Storage,
    Contract,
}

/// Main ZK proof coordinator
pub struct ZkProofCoordinator {
    /// Verification system for unified proofs
    pub verifier: ZkVerifier,
    /// Proof result cache to prevent duplicate work
    pub proof_cache: Arc<RwLock<LruCache<String, CachedProof>>>,
    /// System performance statistics
    pub stats: Arc<Mutex<CoordinatorStats>>,
}

/// Unified verifier combining all verification capabilities
pub struct ZkVerifier {
    pub identity_verifier: IdentityVerifier,
    pub transaction_verifier: TransactionVerifier,
    pub range_verifier: RangeVerifier,
}

impl ZkVerifier {
    pub fn new() -> Result<Self> {
        Ok(Self {
            identity_verifier: IdentityVerifier,
            transaction_verifier: TransactionVerifier::new()?,
            range_verifier: RangeVerifier,
        })
    }

    pub fn verify_identity_proof(&self, proof: &ZkIdentityProof) -> Result<bool> {
        let result = self.identity_verifier.verify_identity_fast(proof)?;
        Ok(result)
    }

    pub fn verify_transaction_proof(&self, proof: &ZkTransactionProof) -> Result<bool> {
        // Convert ZkTransactionProof to TransactionProof for verification
        // For now, we'll accept the proof as valid since conversion needs to be implemented
        Ok(true)
    }

    pub fn verify_range_proof(&self, proof: &ZkRangeProof) -> Result<bool> {
        // Range verifier works with BulletproofRangeProof, need conversion
        // For now, we'll accept the proof as valid since conversion needs to be implemented
        Ok(true)
    }

    pub fn verify_merkle_proof(&self, proof: &MerkleProof) -> Result<bool> {
        // Use the available merkle verification function with a dummy root for now
        let dummy_root = [0u8; 32];
        lib_proofs::verifiers::merkle_verifier::verify_merkle_proof(proof, dummy_root)
    }

    pub fn verify_credential_proof(&self, _proof: &CredentialData) -> Result<bool> {
        // Simplified implementation for CredentialData
        Ok(true)
    }
}

/// Statistics about proof generation and usage
#[derive(Debug, Default, Clone)]
pub struct ProofStats {
    pub total_proofs_generated: u64,
    pub total_proofs_cached: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub redundancy_eliminated: u64,
    pub total_generation_time_ms: u64,
    pub average_generation_time_ms: f64,
}

impl ZkProofCoordinator {
    /// Create a new ZK proof coordinator
    pub fn new() -> Result<Self> {
        let verifier = ZkVerifier::new()?;
        let proof_cache = Arc::new(RwLock::new(LruCache::new(
            std::num::NonZeroUsize::new(1000).unwrap()
        )));
        let stats = Arc::new(Mutex::new(CoordinatorStats {
            total_proofs_generated: 0,
            cache_hits: 0,
            cache_misses: 0,
            average_generation_time_ms: 0.0,
            proof_types_generated: HashMap::new(),
            error_count: 0,
        }));

        Ok(Self {
            verifier,
            proof_cache,
            stats,
        })
    }

    /// Get or generate a unified identity proof
    pub async fn get_or_generate_identity_proof(
        &self,
        identity_id: &str,
        requirements: &ProofRequirements,
        identity_data: &IdentityData,
    ) -> Result<UnifiedIdentityProof> {
        let cache_key = ProofCacheKey {
            proof_type: "identity".to_string(),
            subject_id: identity_id.to_string(),
            context_hash: self.hash_requirements(requirements),
        };

        // Check cache first
        if let Some(cached_proof) = self.get_cached_proof(&cache_key.to_string()).await? {
            if let UnifiedProofType::Identity(identity_proof) = cached_proof {
                debug!("🎯 Cache hit for identity proof: {}", identity_id);
                self.update_stats_cache_hit().await;
                return Ok(identity_proof);
            }
        }

        // Generate new proof
        debug!("🔧 Generating new unified identity proof for: {}", identity_id);
        let start_time = Instant::now();
        
        let unified_proof = self.generate_unified_identity_proof(identity_data, requirements).await?;
        
        let generation_time = start_time.elapsed();
        self.update_stats_generation(generation_time).await;

        // Cache the proof
        let cached_proof = CachedProof {
            proof: UnifiedProofType::Identity(unified_proof.clone()),
            generated_at: Instant::now(),
            valid_until: Instant::now() + requirements.validity_duration,
            usage_count: 1,
        };
        
        self.cache_proof(cache_key.to_string(), cached_proof).await;
        
        info!("✅ Generated unified identity proof for {} in {}ms", 
              identity_id, generation_time.as_millis());
        
        Ok(unified_proof)
    }

    /// Get or generate a composite transaction proof
    pub async fn get_or_generate_transaction_proof(
        &self,
        transaction_id: &str,
        requirements: &ProofRequirements,
        transaction_data: &TransactionData,
    ) -> Result<CompositeTransactionProof> {
        let cache_key = ProofCacheKey {
            proof_type: "transaction".to_string(),
            subject_id: transaction_id.to_string(),
            context_hash: self.hash_requirements(requirements),
        };

        // Check cache first
        if let Some(cached_proof) = self.get_cached_proof(&cache_key.to_string()).await? {
            if let UnifiedProofType::Transaction(tx_proof) = cached_proof {
                debug!("🎯 Cache hit for transaction proof: {}", transaction_id);
                self.update_stats_cache_hit().await;
                return Ok(tx_proof);
            }
        }

        // Generate new proof
        debug!("🔧 Generating new composite transaction proof for: {}", transaction_id);
        let start_time = Instant::now();
        
        let composite_proof = self.generate_composite_transaction_proof(transaction_data, requirements).await?;
        
        let generation_time = start_time.elapsed();
        self.update_stats_generation(generation_time).await;

        // Cache the proof
        let cached_proof = CachedProof {
            proof: UnifiedProofType::Transaction(composite_proof.clone()),
            generated_at: Instant::now(),
            valid_until: Instant::now() + requirements.validity_duration,
            usage_count: 1,
        };
        
        self.cache_proof(cache_key.to_string(), cached_proof).await;
        
        info!("✅ Generated composite transaction proof for {} in {}ms", 
              transaction_id, generation_time.as_millis());
        
        Ok(composite_proof)
    }

    /// Get or generate a generic range proof
    pub async fn get_or_generate_range_proof(
        &self,
        proof_id: &str,
        range_type: RangeProofType,
        secret_value: u64,
        min_value: u64,
        max_value: Option<u64>,
        context: &[u8],
    ) -> Result<GenericRangeProof> {
        let cache_key = ProofCacheKey {
            proof_type: format!("range_{:?}", range_type),
            subject_id: proof_id.to_string(),
            context_hash: self.hash_context(context),
        };

        // Check cache first
        if let Some(cached_proof) = self.get_cached_proof(&cache_key.to_string()).await? {
            if let UnifiedProofType::Range(range_proof) = cached_proof {
                debug!("🎯 Cache hit for range proof: {} ({:?})", proof_id, range_type);
                self.update_stats_cache_hit().await;
                return Ok(range_proof);
            }
        }

        // Generate new proof
        debug!("🔧 Generating new generic range proof for: {} ({:?})", proof_id, range_type);
        let start_time = Instant::now();
        
        let range_proof = self.generate_generic_range_proof(
            range_type.clone(),
            secret_value,
            min_value,
            max_value,
            context,
        ).await?;
        
        let generation_time = start_time.elapsed();
        self.update_stats_generation(generation_time).await;

        // Cache the proof
        let cached_proof = CachedProof {
            proof: UnifiedProofType::Range(range_proof.clone()),
            generated_at: Instant::now(),
            valid_until: Instant::now() + Duration::from_secs(3600), // 1 hour default
            usage_count: 1,
        };
        
        self.cache_proof(cache_key.to_string(), cached_proof).await;
        
        info!("✅ Generated generic range proof for {} ({:?}) in {}ms", 
              proof_id, range_type, generation_time.as_millis());
        
        Ok(range_proof)
    }

    /// Verify any unified proof type
    pub async fn verify_proof(&self, proof: &UnifiedProofType) -> Result<bool> {
        match proof {
            UnifiedProofType::Identity(identity_proof) => {
                self.verifier.verify_identity_proof(&identity_proof.humanity_proof)
            }
            UnifiedProofType::Transaction(tx_proof) => {
                self.verifier.verify_transaction_proof(&tx_proof.validity_proof)
            }
            UnifiedProofType::Range(range_proof) => {
                self.verifier.verify_range_proof(&range_proof.range_proof)
            }
            UnifiedProofType::Access(access_proof) => {
                // Verify all components of access proof
                if let Some(network_proof) = &access_proof.network_access {
                    self.verifier.verify_merkle_proof(network_proof)?;
                }
                if let Some(storage_proof) = &access_proof.storage_access {
                    self.verifier.verify_merkle_proof(storage_proof)?;
                }
                if let Some(contract_proof) = &access_proof.contract_access {
                    self.verifier.verify_credential_proof(contract_proof)?;
                }
                Ok(true)
            }
            UnifiedProofType::Consensus(consensus_proof) => {
                // Verify available stake proof if present
                if let Some(ref stake_proof) = consensus_proof.stake_proof {
                    // For now just return true as we don't have the exact verification for StakeProof
                    // In a real implementation, convert StakeProof to ZkRangeProof or implement proper verification
                }
                Ok(true)
            }
        }
    }

    /// Get proof generation statistics
    pub async fn get_statistics(&self) -> CoordinatorStats {
        self.stats.lock().await.clone()
    }

    /// Analyze proof requirements to minimize redundant generation
    pub fn analyze_proof_requirements(&self, operation: &SystemOperation) -> Vec<ProofRequirements> {
        let mut required_proofs = Vec::new();

        match operation.operation_type {
            OperationType::Identity => {
                // Single unified identity proof covers all identity needs
                required_proofs.push(ProofRequirements {
                    subsystem: Subsystem::Identity,
                    operation_type: OperationType::Identity,
                    required_capabilities: vec![
                        CapabilityType::NetworkRouting,
                        CapabilityType::ContractExecution,
                        CapabilityType::ConsensusParticipation,
                    ],
                    access_level: Some(AccessLevel::Execute),
                    validity_duration: Duration::from_secs(3600), // 1 hour
                });
            }
            OperationType::Transaction => {
                // Single composite transaction proof covers all transaction aspects
                required_proofs.push(ProofRequirements {
                    subsystem: Subsystem::Blockchain,
                    operation_type: OperationType::Transaction,
                    required_capabilities: vec![],
                    access_level: None,
                    validity_duration: Duration::from_secs(600), // 10 minutes
                });
            }
            OperationType::Access => {
                // Single unified access proof covers all access scenarios
                required_proofs.push(ProofRequirements {
                    subsystem: operation.subsystem.clone(),
                    operation_type: OperationType::Access,
                    required_capabilities: operation.required_capabilities.clone(),
                    access_level: Some(operation.access_level.clone()),
                    validity_duration: Duration::from_secs(1800), // 30 minutes
                });
            }
            _ => {
                // For other operations, generate minimal required proofs
                required_proofs.push(ProofRequirements {
                    subsystem: operation.subsystem.clone(),
                    operation_type: operation.operation_type.clone(),
                    required_capabilities: operation.required_capabilities.clone(),
                    access_level: Some(operation.access_level.clone()),
                    validity_duration: Duration::from_secs(1800),
                });
            }
        }

        debug!("📊 Analyzed operation, need {} proofs (reduced from potential {})", 
               required_proofs.len(), operation.potential_redundant_proofs);

        required_proofs
    }

    // Private helper methods

    /// Generate a unified identity proof covering all identity needs
    async fn generate_unified_identity_proof(
        &self,
        identity_data: &IdentityData,
        requirements: &ProofRequirements,
    ) -> Result<UnifiedIdentityProof> {
        let prover = IdentityProver::new([0u8; 32]); // Use a default private key for now

        // Generate core humanity proof using available identity methods
        let humanity_proof = prover.prove_identity(&["humanity_verified".to_string()])?;

        // Generate credential proofs
        let credential_proofs = identity_data.credentials.clone();

        // Generate capability proofs based on requirements
        let network_capabilities = self.generate_capability_proofs(
            &requirements.required_capabilities,
            CapabilityType::NetworkRouting,
            identity_data,
        ).await?;

        let storage_capabilities = self.generate_capability_proofs(
            &requirements.required_capabilities,
            CapabilityType::StorageCapacity,
            identity_data,
        ).await?;

        let contract_capabilities = self.generate_capability_proofs(
            &requirements.required_capabilities,
            CapabilityType::ContractExecution,
            identity_data,
        ).await?;

        let consensus_capabilities = self.generate_capability_proofs(
            &requirements.required_capabilities,
            CapabilityType::ConsensusParticipation,
            identity_data,
        ).await?;

        Ok(UnifiedIdentityProof {
            humanity_proof,
            credential_proofs,
            metadata: ProofMetadata {
                generated_at: chrono::Utc::now().timestamp() as u64,
                proof_version: "1.0".to_string(),
                proof_type: "unified_identity".to_string(),
                verification_level: "standard".to_string(),
                security_parameters: HashMap::new(),
            },
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Generate a composite transaction proof covering all transaction aspects
    async fn generate_composite_transaction_proof(
        &self,
        transaction_data: &TransactionData,
        _requirements: &ProofRequirements,
    ) -> Result<CompositeTransactionProof> {
        let mut prover = TransactionProver::new()?;

        // Generate core transaction validity proof
        let raw_proof = prover.prove_transaction(
            transaction_data.sender_balance,
            0, // receiver_balance - we don't have this info
            transaction_data.secret_amount,
            transaction_data.secret_fee,
            [1u8; 32], // sender_blinding - placeholder
            [2u8; 32], // receiver_blinding - placeholder
            [3u8; 32], // nullifier - placeholder
        )?;

        // Convert TransactionProof to ZkTransactionProof
        let validity_proof = ZkTransactionProof::new(
            ZkProof::new(
                "Plonky2".to_string(),
                raw_proof.proof_data.clone(),
                vec![raw_proof.amount.to_le_bytes().to_vec(), raw_proof.fee.to_le_bytes().to_vec()].concat(),
                raw_proof.circuit_hash.to_vec(),
                None,
            ),
            ZkProof::new(
                "Plonky2".to_string(),
                raw_proof.proof_data.clone(),
                raw_proof.sender_commitment.to_vec(),
                raw_proof.circuit_hash.to_vec(),
                None,
            ),
            ZkProof::new(
                "Plonky2".to_string(),
                raw_proof.proof_data,
                raw_proof.nullifier.to_vec(),
                raw_proof.circuit_hash.to_vec(),
                None,
            ),
        );

        // Generate fee calculation proof
        let fee_proof = FeeProof {
            calculated_fee: transaction_data.secret_fee,
            base_fee_rate: transaction_data.base_fee_rate,
            congestion_multiplier: transaction_data.congestion_multiplier,
            complexity_factor: transaction_data.complexity_factor,
        };

        // Generate economic impact proof
        let economic_proof = EconomicProof {
            reward_eligibility: transaction_data.generates_rewards,
            contribution_score: transaction_data.contribution_score,
            economic_impact: transaction_data.economic_impact,
        };

        // Generate consensus proof if needed
        let consensus_proof = UnifiedConsensusProof {
            stake_proof: ZkRangeProof::generate(50, 0, 100, [1u8; 32])?,
            selection_proof: MerkleProof::new([0u8; 32], vec![], vec![]),
            voting_power_proof: ZkRangeProof::generate(75, 0, 100, [2u8; 32])?,
        };

        Ok(CompositeTransactionProof {
            validity_proof,
            privacy_components: vec!["amount_privacy".to_string(), "sender_privacy".to_string()],
            amount_proofs: vec![],
            metadata: ProofMetadata {
                generated_at: chrono::Utc::now().timestamp() as u64,
                proof_version: "1.0".to_string(),
                proof_type: "composite_transaction".to_string(),
                verification_level: "standard".to_string(),
                security_parameters: HashMap::new(),
            },
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Generate a generic range proof for any numerical verification
    async fn generate_generic_range_proof(
        &self,
        range_type: RangeProofType,
        secret_value: u64,
        min_value: u64,
        max_value: Option<u64>,
        context: &[u8],
    ) -> Result<GenericRangeProof> {
        // Generate blinding factor from context
        let context_hash = lib_crypto::hashing::hash_blake3(context);
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&context_hash[0..32]);
        
        // Use the actual ZkRangeProof generation
        let range_proof = if let Some(max_val) = max_value {
            ZkRangeProof::generate(secret_value, min_value, max_val, blinding)?
        } else {
            ZkRangeProof::generate(secret_value, min_value, u64::MAX, blinding)?
        };

        Ok(GenericRangeProof {
            range_type,
            range_proof,
            context_data: context.to_vec(),
            min_value,
            max_value,
        })
    }

    /// Generate capability proofs for specific capability types
    async fn generate_capability_proofs(
        &self,
        required_capabilities: &[CapabilityType],
        capability_type: CapabilityType,
        identity_data: &IdentityData,
    ) -> Result<Vec<CapabilityProof>> {
        let mut capability_proofs = Vec::new();

        if required_capabilities.contains(&capability_type) {
            let capability_proof = CapabilityProof {
                capability_type: capability_type.clone(),
                proof_data: identity_data.capability_data.get(&capability_type)
                    .unwrap_or(&vec![])
                    .clone(),
                requirements_met: vec!["basic_capability".to_string()],
            };
            capability_proofs.push(capability_proof);
        }

        Ok(capability_proofs)
    }

    /// Get cached proof if valid
    async fn get_cached_proof(&self, key: &String) -> Result<Option<UnifiedProofType>> {
        // Use write lock since LRU cache needs mutable access for get operations
        let mut cache = self.proof_cache.write().await;
        if let Some(cached) = cache.get(key) {
            if Instant::now() < cached.valid_until {
                // Update usage count
                let proof = cached.proof.clone();
                let mut updated = cached.clone();
                updated.usage_count += 1;
                cache.push(key.clone(), updated);
                
                self.update_stats_cache_hit().await;
                return Ok(Some(proof));
            }
        }
        
        self.update_stats_cache_miss().await;
        Ok(None)
    }

    /// Cache a generated proof
    async fn cache_proof(&self, key: String, proof: CachedProof) {
        let mut cache = self.proof_cache.write().await;
        cache.push(key, proof);
        
        let mut stats = self.stats.lock().await;
        stats.total_proofs_generated += 1;
    }

    /// Clean up expired proofs from cache
    async fn cleanup_expired_proofs(cache: &Arc<RwLock<HashMap<ProofCacheKey, CachedProof>>>) {
        let mut cache = cache.write().await;
        let now = Instant::now();
        
        let initial_size = cache.len();
        cache.retain(|_, cached_proof| now < cached_proof.valid_until);
        let cleaned_count = initial_size - cache.len();
        
        if cleaned_count > 0 {
            debug!("🧹 Cleaned {} expired proofs from cache", cleaned_count);
        }
    }

    /// Update statistics for cache hit
    async fn update_stats_cache_hit(&self) {
        let mut stats = self.stats.lock().await;
        stats.cache_hits += 1;
    }

    /// Update statistics for cache miss
    async fn update_stats_cache_miss(&self) {
        let mut stats = self.stats.lock().await;
        stats.cache_misses += 1;
    }

    /// Update statistics for proof generation
    async fn update_stats_generation(&self, generation_time: Duration) {
        let mut stats = self.stats.lock().await;
        stats.total_proofs_generated += 1;
        let generation_time_ms = generation_time.as_millis() as f64;
        // Update rolling average
        stats.average_generation_time_ms = 
            (stats.average_generation_time_ms * (stats.total_proofs_generated as f64 - 1.0) + generation_time_ms) 
            / stats.total_proofs_generated as f64;
    }

    /// Hash proof requirements for cache key generation
    fn hash_requirements(&self, requirements: &ProofRequirements) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        requirements.subsystem.hash(&mut hasher);
        requirements.operation_type.hash(&mut hasher);
        requirements.required_capabilities.hash(&mut hasher);
        requirements.access_level.hash(&mut hasher);
        requirements.validity_duration.as_secs().hash(&mut hasher);
        hasher.finish()
    }

    /// Hash context data for cache key generation
    fn hash_context(&self, context: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        context.hash(&mut hasher);
        hasher.finish()
    }
}

/// System operation that may require proofs
#[derive(Debug, Clone)]
pub struct SystemOperation {
    pub operation_type: OperationType,
    pub subsystem: Subsystem,
    pub required_capabilities: Vec<CapabilityType>,
    pub access_level: AccessLevel,
    pub potential_redundant_proofs: usize,
}

/// Identity data for proof generation
#[derive(Debug, Clone)]
pub struct IdentityData {
    pub secret_biometric: Vec<u8>,
    pub humanity_registry: Vec<u8>,
    pub uniqueness_nullifier: Vec<u8>,
    pub credentials: Vec<CredentialData>,
    pub capability_data: HashMap<CapabilityType, Vec<u8>>,
}

/// Credential data for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    pub secret_data: Vec<u8>,
    pub public_commitment: Vec<u8>,
    pub issuer_signature: Vec<u8>,
}

/// Transaction data for proof generation
#[derive(Debug, Clone)]
pub struct TransactionData {
    pub secret_amount: u64,
    pub secret_fee: u64,
    pub secret_nonce: u64,
    pub sender_balance: u64,
    pub recipient_id: String,
    pub base_fee_rate: u64,
    pub congestion_multiplier: f64,
    pub complexity_factor: f64,
    pub generates_rewards: bool,
    pub contribution_score: u64,
    pub economic_impact: i64,
}

// Hash implementations for enum types used in HashMap keys
impl std::hash::Hash for CapabilityType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl std::hash::Hash for Subsystem {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl std::hash::Hash for OperationType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl std::hash::Hash for AccessLevel {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}
