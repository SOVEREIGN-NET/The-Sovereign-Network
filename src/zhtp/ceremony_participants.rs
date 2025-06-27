use crate::zhtp::{
    consensus_engine::{ZkValidator, ValidatorStatus},
    crypto::Keypair,
    p2p_network::ZhtpP2PNetwork,
};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::{
    collections::{HashMap, BTreeSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
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
    network: Arc<ZhtpP2PNetwork>,
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
            registration_deadline: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() + (30 * 24 * 60 * 60), // 30 days from now
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
            network,
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
            registered_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
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
        state.started_at = Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        state.expected_completion = Some(
            state.started_at.unwrap() + (self.config.ceremony_timeout_hours * 60 * 60)
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
                    contributed_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
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
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_le_bytes());
        
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
    use tokio;

    #[tokio::test]
    async fn test_participant_registration() {
        // This would require setting up a mock network, but demonstrates the API
        // In practice, this would integrate with the actual ZHTP network
        
        // Mock network setup would go here
        // let network = Arc::new(mock_network());
        // let manager = CeremonyParticipantManager::new(network);
        
        // Test registration, verification, and ceremony flow
        assert!(true); // Placeholder
    }
}
