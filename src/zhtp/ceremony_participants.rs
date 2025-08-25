use crate::zhtp::{
    consensus_engine::{ZkValidator, ValidatorStatus},
    p2p_network::ZhtpP2PNetwork,
};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};

/// Trusted Setup Ceremony Participant Manager
/// Coordinates multi-party ceremony participation across different participant types
pub struct CeremonyParticipantManager {
    /// Registered participants by type
    participants: Arc<RwLock<HashMap<ParticipantType, Vec<CeremonyParticipant>>>>,
    /// Ceremony state and progress
    ceremony_state: Arc<RwLock<CeremonyState>>,
    /// Network interface for participant communication
    _network: Arc<ZhtpP2PNetwork>,
    /// Ceremony configuration
    config: CeremonyConfig,
}

/// Types of ceremony participants
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParticipantType {
    /// Core blockchain validators (highest trust)
    CoreValidator,
    /// Storage and routing network operators
    NetworkOperator,
    /// External community representatives (academics, security firms)
    CommunityRepresentative,
    /// General public participants
    IndependentParticipant,
}

/// Individual ceremony participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyParticipant {
    /// Unique participant identifier
    pub participant_id: String,
    /// Participant type classification
    pub participant_type: ParticipantType,
    /// Cryptographic identity and verification
    pub identity: ParticipantIdentity,
    /// Participation status and progress
    pub status: ParticipationStatus,
    /// Contribution metadata
    pub contribution: Option<ParticipantContribution>,
    /// Registration timestamp
    pub registered_at: u64,
    /// Trust score and weighting in ceremony
    pub trust_weight: f64,
}

/// Participant identity and verification info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantIdentity {
    /// Public key for ceremony communication
    pub public_key: Vec<u8>,
    /// Identity commitment (hash of private info)
    pub identity_commitment: [u8; 32],
    /// Optional validator info (for CoreValidator type)
    pub validator_info: Option<ZkValidator>,
    /// Network reputation metrics (for NetworkOperator type)
    pub network_metrics: Option<NetworkReputationMetrics>,
    /// External verification (for CommunityRepresentative type)
    pub external_verification: Option<ExternalVerification>,
    /// Contact and communication info
    pub contact_info: ContactInfo,
}

/// Network reputation for network operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReputationMetrics {
    /// Storage space provided (in GB)
    pub storage_provided: u64,
    /// Packets successfully routed
    pub packets_routed: u64,
    /// Uptime percentage
    pub uptime_percentage: f64,
    /// Reputation score (0.0 to 1.0)
    pub reputation_score: f64,
    /// Time actively participating in network
    pub network_tenure_days: u32,
}

/// External verification for community representatives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalVerification {
    /// Organization name (university, company, etc.)
    pub organization: String,
    /// Public profile or website
    pub public_profile: String,
    /// Cryptographic expertise verification
    pub expertise_verification: String,
    /// Third-party attestations
    pub attestations: Vec<String>,
}

/// Contact information for participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Email for ceremony coordination
    pub email: String,
    /// Optional GitHub profile
    pub github: Option<String>,
    /// Optional Twitter/X profile
    pub twitter: Option<String>,
    /// Preferred communication method
    pub preferred_contact: String,
}

/// Participation status tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParticipationStatus {
    /// Registered but not yet verified
    Registered,
    /// Identity verified, awaiting ceremony start
    Verified,
    /// Currently participating in ceremony
    Active,
    /// Completed contribution successfully
    Completed,
    /// Failed to complete contribution
    Failed,
    /// Excluded from ceremony
    Excluded,
}

/// Individual participant contribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantContribution {
    /// Contribution round number
    pub round: u32,
    /// Contribution hash for verification
    pub contribution_hash: [u8; 32],
    /// Entropy source used
    pub entropy_source: String,
    /// Timestamp of contribution
    pub contributed_at: u64,
    /// Verification status
    pub verified: bool,
}

/// Overall ceremony state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyState {
    /// Current ceremony phase
    pub current_phase: CeremonyPhase,
    /// Current round number
    pub current_round: u32,
    /// Total participants registered
    pub total_participants: usize,
    /// Participants who have completed contributions
    pub completed_participants: usize,
    /// Ceremony start time
    pub started_at: Option<u64>,
    /// Expected completion time
    pub expected_completion: Option<u64>,
    /// Current participant (if ceremony is active)
    pub current_participant: Option<String>,
}

/// Ceremony phases
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CeremonyPhase {
    /// Registration and verification phase
    Registration,
    /// Phase 1: Universal SRS generation
    Phase1UniversalSRS,
    /// Phase 2: Circuit-specific setup
    Phase2CircuitSetup,
    /// Final verification and publication
    Verification,
    /// Ceremony completed
    Completed,
    /// Ceremony failed
    Failed,
}

/// Ceremony configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyConfig {
    /// Minimum participants required
    pub min_participants: usize,
    /// Maximum participants allowed
    pub max_participants: usize,
    /// Minimum participants per type
    pub min_per_type: HashMap<ParticipantType, usize>,
    /// Maximum participants per type  
    pub max_per_type: HashMap<ParticipantType, usize>,
    /// Registration deadline
    pub registration_deadline: u64,
    /// Ceremony timeout (hours)
    pub ceremony_timeout_hours: u64,
    /// Contribution timeout per participant (minutes)
    pub contribution_timeout_minutes: u64,
}

impl CeremonyParticipantManager {
    /// Create new ceremony participant manager
    pub fn new(network: Arc<ZhtpP2PNetwork>) -> Self {
        let mut min_per_type = HashMap::new();
        min_per_type.insert(ParticipantType::CoreValidator, 5);
        min_per_type.insert(ParticipantType::NetworkOperator, 10);
        min_per_type.insert(ParticipantType::CommunityRepresentative, 10);
        min_per_type.insert(ParticipantType::IndependentParticipant, 5);

        let mut max_per_type = HashMap::new();
        max_per_type.insert(ParticipantType::CoreValidator, 20);
        max_per_type.insert(ParticipantType::NetworkOperator, 30);
        max_per_type.insert(ParticipantType::CommunityRepresentative, 40);
        max_per_type.insert(ParticipantType::IndependentParticipant, 50);

        let config = CeremonyConfig {
            min_participants: 30,
            max_participants: 140,
            min_per_type,
            max_per_type,
            registration_deadline: crate::utils::get_current_timestamp() + (30 * 24 * 60 * 60), // 30 days from now
            ceremony_timeout_hours: 72,
            contribution_timeout_minutes: 60,
        };

        Self {
            participants: Arc::new(RwLock::new(HashMap::new())),
            ceremony_state: Arc::new(RwLock::new(CeremonyState {
                current_phase: CeremonyPhase::Registration,
                current_round: 0,
                total_participants: 0,
                completed_participants: 0,
                started_at: None,
                expected_completion: None,
                current_participant: None,
            })),
            _network: network,
            config,
        }
    }

    /// Register a new participant for the ceremony
    pub async fn register_participant(
        &self,
        participant_type: ParticipantType,
        identity: ParticipantIdentity,
    ) -> Result<String> {
        let mut participants = self.participants.write().await;
        let mut state = self.ceremony_state.write().await;

        // Check if registration is still open
        if state.current_phase != CeremonyPhase::Registration {
            return Err(anyhow!("Registration phase has ended"));
        }

        // Check participant type limits
        let current_count = participants
            .get(&participant_type)
            .map(|v| v.len())
            .unwrap_or(0);
        
        if current_count >= *self.config.max_per_type.get(&participant_type).unwrap_or(&0) {
            return Err(anyhow!("Maximum participants reached for type: {:?}", participant_type));
        }

        // Generate participant ID
        let participant_id = self.generate_participant_id(&identity, &participant_type).await?;

        // Calculate trust weight based on participant type and credentials
        let trust_weight = self.calculate_trust_weight(&participant_type, &identity).await?;

        let participant = CeremonyParticipant {
            participant_id: participant_id.clone(),
            participant_type: participant_type.clone(),
            identity,
            status: ParticipationStatus::Registered,
            contribution: None,
            registered_at: crate::utils::get_current_timestamp(),
            trust_weight,
        };

        // Add to participants list
        participants
            .entry(participant_type.clone())
            .or_insert_with(Vec::new)
            .push(participant);

        // Update state
        state.total_participants += 1;

        println!("✅ Registered participant {} (type: {:?}, trust: {:.3})", 
                 participant_id, participant_type, trust_weight);

        Ok(participant_id)
    }

    /// Verify a registered participant's identity and credentials
    pub async fn verify_participant(&self, participant_id: &str) -> Result<bool> {
        let mut participants = self.participants.write().await;
        
        for participant_list in participants.values_mut() {
            if let Some(participant) = participant_list.iter_mut()
                .find(|p| p.participant_id == participant_id) {
                
                // Perform verification based on participant type
                let verified = match participant.participant_type {
                    ParticipantType::CoreValidator => {
                        self.verify_validator_credentials(&participant.identity).await?
                    },
                    ParticipantType::NetworkOperator => {
                        self.verify_network_operator_credentials(&participant.identity).await?
                    },
                    ParticipantType::CommunityRepresentative => {
                        self.verify_community_representative_credentials(&participant.identity).await?
                    },
                    ParticipantType::IndependentParticipant => {
                        self.verify_independent_participant_credentials(&participant.identity).await?
                    },
                };

                if verified {
                    participant.status = ParticipationStatus::Verified;
                    println!("✅ Verified participant: {}", participant_id);
                } else {
                    participant.status = ParticipationStatus::Excluded;
                    println!("❌ Failed to verify participant: {}", participant_id);
                }

                return Ok(verified);
            }
        }

        Err(anyhow!("Participant not found: {}", participant_id))
    }

    /// Start the trusted setup ceremony with verified participants
    pub async fn start_ceremony(&self) -> Result<()> {
        let participants = self.participants.read().await;
        let mut state = self.ceremony_state.write().await;

        // Check if we have minimum participants
        if state.total_participants < self.config.min_participants {
            return Err(anyhow!("Insufficient participants: {} (minimum: {})", 
                              state.total_participants, self.config.min_participants));
        }

        // Check minimum per type
        for (participant_type, min_count) in &self.config.min_per_type {
            let current_count = participants
                .get(participant_type)
                .map(|v| v.iter().filter(|p| p.status == ParticipationStatus::Verified).count())
                .unwrap_or(0);
            
            if current_count < *min_count {
                return Err(anyhow!("Insufficient verified participants for type {:?}: {} (minimum: {})", 
                                  participant_type, current_count, min_count));
            }
        }

        // Update state to start ceremony
        state.current_phase = CeremonyPhase::Phase1UniversalSRS;
        state.current_round = 1;
        state.started_at = Some(crate::utils::get_current_timestamp());
        state.expected_completion = Some(
            state.started_at.unwrap_or(0) + (self.config.ceremony_timeout_hours * 60 * 60)
        );

        println!("🚀 Starting ZHTP Trusted Setup Ceremony with {} participants", state.total_participants);
        println!("   Phase 1: Universal SRS Generation");
        
        Ok(())
    }

    /// Get the next participant for contribution
    pub async fn get_next_participant(&self) -> Result<Option<CeremonyParticipant>> {
        let participants = self.participants.read().await;
        let state = self.ceremony_state.read().await;

        if state.current_phase == CeremonyPhase::Completed || 
           state.current_phase == CeremonyPhase::Failed {
            return Ok(None);
        }

        // Find the next participant who hasn't contributed yet
        for participant_list in participants.values() {
            for participant in participant_list {
                if participant.status == ParticipationStatus::Verified {
                    return Ok(Some(participant.clone()));
                }
            }
        }

        Ok(None)
    }

    /// Record a participant's contribution
    pub async fn record_contribution(
        &self,
        participant_id: &str,
        contribution_hash: [u8; 32],
        entropy_source: String,
    ) -> Result<()> {
        let mut participants = self.participants.write().await;
        let mut state = self.ceremony_state.write().await;

        for participant_list in participants.values_mut() {
            if let Some(participant) = participant_list.iter_mut()
                .find(|p| p.participant_id == participant_id) {
                
                let contribution = ParticipantContribution {
                    round: state.current_round,
                    contribution_hash,
                    entropy_source,
                    contributed_at: crate::utils::get_current_timestamp(),
                    verified: false, // Will be verified later
                };

                participant.contribution = Some(contribution);
                participant.status = ParticipationStatus::Completed;
                state.completed_participants += 1;

                println!("📝 Recorded contribution from participant: {}", participant_id);
                return Ok(());
            }
        }

        Err(anyhow!("Participant not found: {}", participant_id))
    }

    /// Get ceremony statistics and progress
    pub async fn get_ceremony_stats(&self) -> CeremonyStats {
        let participants = self.participants.read().await;
        let state = self.ceremony_state.read().await;

        let mut stats_by_type = HashMap::new();
        for (participant_type, participant_list) in participants.iter() {
            let type_stats = ParticipantTypeStats {
                registered: participant_list.len(),
                verified: participant_list.iter().filter(|p| p.status == ParticipationStatus::Verified).count(),
                completed: participant_list.iter().filter(|p| p.status == ParticipationStatus::Completed).count(),
            };
            stats_by_type.insert(participant_type.clone(), type_stats);
        }

        CeremonyStats {
            current_phase: state.current_phase.clone(),
            total_participants: state.total_participants,
            verified_participants: participants.values()
                .flat_map(|v| v.iter())
                .filter(|p| p.status == ParticipationStatus::Verified)
                .count(),
            completed_participants: state.completed_participants,
            stats_by_type,
            started_at: state.started_at,
            expected_completion: state.expected_completion,
        }
    }

    // Private helper methods

    async fn generate_participant_id(
        &self,
        identity: &ParticipantIdentity,
        participant_type: &ParticipantType,
    ) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(&identity.public_key);
        hasher.update(&identity.identity_commitment);
        hasher.update(format!("{:?}", participant_type).as_bytes());
        hasher.update(crate::utils::get_current_timestamp().to_le_bytes());
        
        let hash = hasher.finalize();
        Ok(hex::encode(&hash[..8])) // Use first 8 bytes as ID
    }

    async fn calculate_trust_weight(
        &self,
        participant_type: &ParticipantType,
        identity: &ParticipantIdentity,
    ) -> Result<f64> {
        let base_weight = match participant_type {
            ParticipantType::CoreValidator => 1.0,
            ParticipantType::NetworkOperator => 0.8,
            ParticipantType::CommunityRepresentative => 0.6,
            ParticipantType::IndependentParticipant => 0.4,
        };

        // Adjust based on specific credentials
        let credential_bonus = match participant_type {
            ParticipantType::CoreValidator => {
                if let Some(validator_info) = &identity.validator_info {
                    // Higher stake = higher trust
                    (validator_info.stake / 1000000.0).min(0.5)
                } else {
                    0.0
                }
            },
            ParticipantType::NetworkOperator => {
                if let Some(metrics) = &identity.network_metrics {
                    // Higher reputation = higher trust
                    metrics.reputation_score * 0.3
                } else {
                    0.0
                }
            },
            _ => 0.0,
        };

        Ok(base_weight + credential_bonus)
    }

    async fn verify_validator_credentials(&self, identity: &ParticipantIdentity) -> Result<bool> {
        // Verify validator is actually registered and has sufficient stake
        if let Some(validator_info) = &identity.validator_info {
            // Check if validator is active and has minimum stake
            Ok(validator_info.status == ValidatorStatus::Active && validator_info.stake >= 100000.0)
        } else {
            Ok(false)
        }
    }

    async fn verify_network_operator_credentials(&self, identity: &ParticipantIdentity) -> Result<bool> {
        // Verify network operator has good reputation and sufficient activity
        if let Some(metrics) = &identity.network_metrics {
            Ok(metrics.reputation_score >= 0.7 && 
               metrics.network_tenure_days >= 30 &&
               metrics.uptime_percentage >= 0.9)
        } else {
            Ok(false)
        }
    }

    async fn verify_community_representative_credentials(&self, identity: &ParticipantIdentity) -> Result<bool> {
        // Verify external credentials and attestations
        if let Some(verification) = &identity.external_verification {
            // Check if organization is known and has attestations
            Ok(!verification.organization.is_empty() && 
               !verification.attestations.is_empty())
        } else {
            Ok(false)
        }
    }

    async fn verify_independent_participant_credentials(&self, identity: &ParticipantIdentity) -> Result<bool> {
        // Basic verification for independent participants
        // Mainly check that they have valid contact info and identity commitment
        Ok(!identity.contact_info.email.is_empty() && 
           identity.identity_commitment != [0u8; 32])
    }
}

/// Ceremony statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyStats {
    pub current_phase: CeremonyPhase,
    pub total_participants: usize,
    pub verified_participants: usize,
    pub completed_participants: usize,
    pub stats_by_type: HashMap<ParticipantType, ParticipantTypeStats>,
    pub started_at: Option<u64>,
    pub expected_completion: Option<u64>,
}

/// Statistics per participant type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantTypeStats {
    pub registered: usize,
    pub verified: usize,
    pub completed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zhtp::{
        crypto::Keypair,
    };
    use std::net::SocketAddr;
    use tokio;

    /// Helper function to create a test network instance
    async fn create_test_network() -> Result<Arc<ZhtpP2PNetwork>> {
        // Use a random available port for testing
        let local_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let bootstrap_nodes = vec![]; // No bootstrap nodes for isolated test
        
        ZhtpP2PNetwork::new(local_addr, bootstrap_nodes).await.map(Arc::new)
    }

    /// Helper function to create test participant identity
    fn create_test_identity(participant_type: &ParticipantType) -> ParticipantIdentity {
        let keypair = Keypair::generate();
        let mut identity_commitment = [0u8; 32];
        
        // Create a unique identity commitment based on type
        let type_hash = sha2::Sha256::digest(format!("{:?}", participant_type).as_bytes());
        identity_commitment.copy_from_slice(&type_hash[..32]);

        ParticipantIdentity {
            public_key: keypair.public_key(),
            identity_commitment,
            validator_info: if matches!(participant_type, ParticipantType::CoreValidator) {
                Some(ZkValidator {
                    encrypted_identity: vec![1, 2, 3, 4],
                    stake: 150000.0, // Sufficient stake for validation (>= 100,000)
                    stake_proof: crate::zhtp::zk_proofs::ByteRoutingProof {
                        commitments: vec![],
                        elements: vec![],
                        inputs: vec![],
                    },
                    identity_commitment,
                    metrics: crate::zhtp::consensus_engine::ZkNetworkMetrics::new(0.95),
                    registered_at: crate::utils::get_current_timestamp(),
                    last_activity: crate::utils::get_current_timestamp(),
                    status: ValidatorStatus::Active,
                })
            } else {
                None
            },
            network_metrics: if matches!(participant_type, ParticipantType::NetworkOperator) {
                Some(NetworkReputationMetrics {
                    storage_provided: 1000, // 1TB
                    packets_routed: 100000,
                    uptime_percentage: 0.95,
                    reputation_score: 0.9,
                    network_tenure_days: 60,
                })
            } else {
                None
            },
            external_verification: if matches!(participant_type, ParticipantType::CommunityRepresentative) {
                Some(ExternalVerification {
                    organization: "Test University".to_string(),
                    public_profile: "https://test-university.edu/crypto-lab".to_string(),
                    expertise_verification: "PhD in Cryptography".to_string(),
                    attestations: vec!["Academic Credential".to_string(), "Research Publication".to_string()],
                })
            } else {
                None
            },
            contact_info: ContactInfo {
                email: format!("test-{:?}@example.com", participant_type).to_lowercase(),
                github: Some("test-participant".to_string()),
                twitter: Some("@test_participant".to_string()),
                preferred_contact: "email".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_participant_registration_integration() -> Result<()> {
        // Create a real ZHTP network instance for testing
        let network = create_test_network().await?;
        let manager = CeremonyParticipantManager::new(network);

        // Test registering different types of participants
        let core_validator_identity = create_test_identity(&ParticipantType::CoreValidator);
        let validator_id = manager.register_participant(
            ParticipantType::CoreValidator,
            core_validator_identity,
        ).await?;

        let network_operator_identity = create_test_identity(&ParticipantType::NetworkOperator);
        let operator_id = manager.register_participant(
            ParticipantType::NetworkOperator,
            network_operator_identity,
        ).await?;

        let community_rep_identity = create_test_identity(&ParticipantType::CommunityRepresentative);
        let community_id = manager.register_participant(
            ParticipantType::CommunityRepresentative,
            community_rep_identity,
        ).await?;

        let independent_identity = create_test_identity(&ParticipantType::IndependentParticipant);
        let independent_id = manager.register_participant(
            ParticipantType::IndependentParticipant,
            independent_identity,
        ).await?;

        // Verify all participants were registered
        let stats = manager.get_ceremony_stats().await;
        assert_eq!(stats.total_participants, 4);
        assert_eq!(stats.verified_participants, 0); // Not verified yet

        // Verify participants
        assert!(manager.verify_participant(&validator_id).await?);
        assert!(manager.verify_participant(&operator_id).await?);
        assert!(manager.verify_participant(&community_id).await?);
        assert!(manager.verify_participant(&independent_id).await?);

        // Check updated stats
        let stats = manager.get_ceremony_stats().await;
        assert_eq!(stats.verified_participants, 4);
        
        println!("✅ Successfully registered and verified 4 participants");
        Ok(())
    }

    #[tokio::test]
    async fn test_ceremony_flow_integration() -> Result<()> {
        // Create a real network and manager
        let network = create_test_network().await?;
        let manager = CeremonyParticipantManager::new(network);

        // Register minimum required participants for ceremony start
        let mut participant_ids = Vec::new();

        // Register 5 core validators (minimum required)
        for _i in 0..5 {
            let identity = create_test_identity(&ParticipantType::CoreValidator);
            let id = manager.register_participant(ParticipantType::CoreValidator, identity).await?;
            manager.verify_participant(&id).await?;
            participant_ids.push(id);
        }

        // Register 10 network operators (minimum required)
        for _i in 0..10 {
            let identity = create_test_identity(&ParticipantType::NetworkOperator);
            let id = manager.register_participant(ParticipantType::NetworkOperator, identity).await?;
            manager.verify_participant(&id).await?;
            participant_ids.push(id);
        }

        // Register 10 community representatives (minimum required)
        for _i in 0..10 {
            let identity = create_test_identity(&ParticipantType::CommunityRepresentative);
            let id = manager.register_participant(ParticipantType::CommunityRepresentative, identity).await?;
            manager.verify_participant(&id).await?;
            participant_ids.push(id);
        }

        // Register 5 independent participants (minimum required)
        for _i in 0..5 {
            let identity = create_test_identity(&ParticipantType::IndependentParticipant);
            let id = manager.register_participant(ParticipantType::IndependentParticipant, identity).await?;
            manager.verify_participant(&id).await?;
            participant_ids.push(id);
        }

        // Verify we have minimum participants
        let stats = manager.get_ceremony_stats().await;
        assert_eq!(stats.total_participants, 30); // Total registered
        assert_eq!(stats.verified_participants, 30); // All verified
        assert!(stats.total_participants >= manager.config.min_participants);

        // Start the ceremony
        manager.start_ceremony().await?;

        // Verify ceremony state changed
        let stats = manager.get_ceremony_stats().await;
        assert_eq!(stats.current_phase, CeremonyPhase::Phase1UniversalSRS);
        assert!(stats.started_at.is_some());
        assert!(stats.expected_completion.is_some());

        // Test getting next participant for contribution
        let next_participant = manager.get_next_participant().await?;
        assert!(next_participant.is_some());
        
        if let Some(participant) = next_participant {
            // Record a test contribution
            let contribution_hash = [1u8; 32]; // Mock contribution hash
            manager.record_contribution(
                &participant.participant_id,
                contribution_hash,
                "test_entropy_source".to_string(),
            ).await?;

            // Verify contribution was recorded
            let updated_stats = manager.get_ceremony_stats().await;
            assert_eq!(updated_stats.completed_participants, 1);
        }

        println!("✅ Successfully completed full ceremony flow test");
        Ok(())
    }

    #[tokio::test]
    async fn test_participant_verification_rules() -> Result<()> {
        let network = create_test_network().await?;
        let manager = CeremonyParticipantManager::new(network);

        // Test validator with insufficient stake (should fail verification)
        let mut validator_identity = create_test_identity(&ParticipantType::CoreValidator);
        if let Some(ref mut validator_info) = validator_identity.validator_info {
            validator_info.stake = 50000.0; // Below minimum of 100,000
        }
        
        let validator_id = manager.register_participant(
            ParticipantType::CoreValidator,
            validator_identity,
        ).await?;
        
        let verification_result = manager.verify_participant(&validator_id).await?;
        assert!(!verification_result, "Validator with insufficient stake should not be verified");

        // Test network operator with poor reputation (should fail)
        let mut operator_identity = create_test_identity(&ParticipantType::NetworkOperator);
        if let Some(ref mut metrics) = operator_identity.network_metrics {
            metrics.reputation_score = 0.5; // Below minimum of 0.7
        }

        let operator_id = manager.register_participant(
            ParticipantType::NetworkOperator,
            operator_identity,
        ).await?;
        
        let verification_result = manager.verify_participant(&operator_id).await?;
        assert!(!verification_result, "Network operator with poor reputation should not be verified");

        println!("✅ Verification rules working correctly");
        Ok(())
    }

    #[tokio::test]
    async fn test_ceremony_limits_and_constraints() -> Result<()> {
        let network = create_test_network().await?;
        let manager = CeremonyParticipantManager::new(network);

        // Test participant type limits
        let max_validators = *manager.config.max_per_type.get(&ParticipantType::CoreValidator).unwrap_or(&20);
        
        // Try to register more than maximum allowed validators
        for i in 0..=max_validators {
            let identity = create_test_identity(&ParticipantType::CoreValidator);
            let result = manager.register_participant(ParticipantType::CoreValidator, identity).await;
            
            if i < max_validators {
                assert!(result.is_ok(), "Registration should succeed within limits");
            } else {
                assert!(result.is_err(), "Registration should fail when exceeding limits");
            }
        }

        // Test ceremony start with insufficient participants
        let insufficient_manager = CeremonyParticipantManager::new(create_test_network().await?);
        let start_result = insufficient_manager.start_ceremony().await;
        assert!(start_result.is_err(), "Ceremony should not start with insufficient participants");

        println!("✅ Ceremony limits and constraints working correctly");
        Ok(())
    }

    #[tokio::test]
    async fn test_trust_weight_calculation() -> Result<()> {
        let network = create_test_network().await?;
        let manager = CeremonyParticipantManager::new(network);

        // Test different participant types have different base trust weights
        let validator_identity = create_test_identity(&ParticipantType::CoreValidator);
        let operator_identity = create_test_identity(&ParticipantType::NetworkOperator);
        let community_identity = create_test_identity(&ParticipantType::CommunityRepresentative);
        let independent_identity = create_test_identity(&ParticipantType::IndependentParticipant);

        let _validator_id = manager.register_participant(ParticipantType::CoreValidator, validator_identity).await?;
        let _operator_id = manager.register_participant(ParticipantType::NetworkOperator, operator_identity).await?;
        let _community_id = manager.register_participant(ParticipantType::CommunityRepresentative, community_identity).await?;
        let _independent_id = manager.register_participant(ParticipantType::IndependentParticipant, independent_identity).await?;

        // Access participants to check trust weights
        let participants = manager.participants.read().await;
        
        let validator_weight = participants.get(&ParticipantType::CoreValidator)
            .and_then(|v| v.first())
            .map(|p| p.trust_weight)
            .unwrap_or(0.0);
            
        let operator_weight = participants.get(&ParticipantType::NetworkOperator)
            .and_then(|v| v.first())
            .map(|p| p.trust_weight)
            .unwrap_or(0.0);

        // Validators should have higher trust weight than operators
        assert!(validator_weight > operator_weight, 
               "Validator trust weight ({}) should be higher than operator trust weight ({})", 
               validator_weight, operator_weight);

        println!("✅ Trust weight calculation working correctly");
        println!("   Validator weight: {:.3}", validator_weight);
        println!("   Operator weight: {:.3}", operator_weight);
        
        Ok(())
    }
}
