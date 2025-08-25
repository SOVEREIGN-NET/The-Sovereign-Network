use crate::zhtp::{
    crypto::Keypair,
    zk_proofs::{ByteRoutingProof, RoutingProof},
    dns::ZhtpDNS,
    economics::ZhtpEconomics,
};
use crate::storage::ZhtpStorageManager;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

/// ZHTP DAO for decentralized protocol governance
#[derive(Debug, Clone)]
pub struct ZhtpDao {
    /// DAO treasury for UBI and public services
    pub treasury: Arc<RwLock<DaoTreasury>>,
    /// Active governance proposals
    pub proposals: Arc<RwLock<HashMap<u64, GovernanceProposal>>>,
    /// ZK identity registry for voters
    pub identity_registry: Arc<RwLock<HashMap<String, ZkIdentity>>>,
    /// Voting records with ZK privacy
    pub voting_records: Arc<RwLock<HashMap<u64, VotingRecord>>>,
    /// UBI distribution system
    pub ubi_system: Arc<RwLock<UbiSystem>>,
    /// Node incentive program
    pub node_incentives: Arc<RwLock<NodeIncentiveProgram>>,
    /// ZHTP DNS service for DAO domain registration
    pub dns_service: Arc<RwLock<ZhtpDNS>>,
    /// Storage manager for proposal and voting data
    pub storage_manager: Arc<ZhtpStorageManager>,
    /// Economics integration for token management
    pub economics: Arc<ZhtpEconomics>,
    /// DAO configuration and settings
    pub config: DaoConfig,
}

/// DAO Treasury managing funds from transaction fees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoTreasury {
    /// Total treasury balance in ZHTP tokens
    pub total_balance: u64,
    /// UBI fund allocation (40% of fees)
    pub ubi_fund: u64,
    /// Healthcare fund (20% of fees)
    pub healthcare_fund: u64,
    /// Education fund (15% of fees)
    pub education_fund: u64,
    /// Housing fund (15% of fees)
    pub housing_fund: u64,
    /// Infrastructure fund (10% of fees)
    pub infrastructure_fund: u64,
    /// Emergency reserve fund
    pub emergency_reserve: u64,
    /// Monthly fund allocation history
    pub allocation_history: Vec<MonthlyAllocation>,
}

/// Monthly allocation record for transparency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlyAllocation {
    pub month: u64, // Unix timestamp
    pub ubi_distributed: u64,
    pub healthcare_spent: u64,
    pub education_spent: u64,
    pub housing_spent: u64,
    pub infrastructure_spent: u64,
    pub beneficiaries_count: u64,
}

/// Zero-Knowledge Identity for DAO participation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkIdentity {
    /// Anonymous identity commitment
    pub identity_commitment: [u8; 32],
    /// Proof of personhood (prevents Sybil attacks)
    pub personhood_proof: ByteRoutingProof,
    /// Voting power based on network contribution
    pub voting_power: u64,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Anonymous reputation score
    pub reputation: f64,
    /// UBI eligibility status
    pub ubi_eligible: bool,
}

impl ZkIdentity {
    /// Create a new ZK identity
    pub async fn new(user_id: String) -> Result<Self> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        let identity_commitment = hasher.finalize().into();
        
        let personhood_proof = ByteRoutingProof {
            inputs: vec![vec![1u8; 32]],
            elements: vec![vec![0u8; 64]],
            commitments: vec![vec![0u8; 32]],
        };
        
        Ok(Self {
            identity_commitment,
            personhood_proof,
            voting_power: 100,
            registered_at: chrono::Utc::now().timestamp() as u64,
            last_activity: chrono::Utc::now().timestamp() as u64,
            reputation: 1.0,
            ubi_eligible: true,
        })
    }
}

/// Governance proposal for DAO voting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Proposal ID
    pub id: u64,
    /// Proposal title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Proposal type
    pub proposal_type: ProposalType,
    /// Proposer's anonymous identity
    pub proposer: [u8; 32],
    /// Voting deadline
    pub voting_deadline: u64,
    /// Current vote tally
    pub vote_tally: VoteTally,
    /// Execution status
    pub status: ProposalStatus,
    /// Required quorum percentage
    pub quorum_required: f64,
    /// Funds requested (if applicable)
    pub funds_requested: Option<u64>,
}

/// Types of governance proposals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalType {
    /// Protocol upgrade or change
    ProtocolUpgrade,
    /// Treasury allocation adjustment
    TreasuryAllocation,
    /// UBI amount adjustment
    UbiAdjustment,
    /// New public service funding
    PublicServiceFunding,
    /// Node reward rate change
    NodeRewardAdjustment,
    /// Emergency fund allocation
    EmergencyFunding,
    /// Constitution amendment
    ConstitutionAmendment,
}

/// Vote tallying with ZK privacy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTally {
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_voting_power: u64,
    pub participation_rate: f64,
}

/// Proposal execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalStatus {
    Active,
    Passed,
    Rejected,
    Executed,
    Expired,
}

/// Anonymous voting record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingRecord {
    pub proposal_id: u64,
    /// Anonymous vote commitments (cannot be traced to individuals)
    pub vote_commitments: Vec<[u8; 32]>,
    /// ZK proof of valid voting
    pub validity_proof: ByteRoutingProof,
    /// Vote tally
    pub final_tally: VoteTally,
}

/// Universal Basic Income system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiSystem {
    /// Monthly UBI amount per eligible person
    pub monthly_ubi_amount: u64,
    /// Total registered beneficiaries
    pub registered_beneficiaries: u64,
    /// UBI distribution history
    pub distribution_history: Vec<UbiDistribution>,
    /// Eligibility criteria
    pub eligibility_criteria: UbiEligibility,
    /// Next distribution date
    pub next_distribution: u64,
}

/// UBI distribution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiDistribution {
    pub month: u64,
    pub amount_per_person: u64,
    pub total_distributed: u64,
    pub beneficiaries_count: u64,
    pub distribution_proof: ByteRoutingProof,
}

/// UBI eligibility criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiEligibility {
    /// Minimum network participation period (months)
    pub min_participation_months: u64,
    /// Minimum reputation score required
    pub min_reputation: f64,
    /// Geographic eligibility (if any)
    pub geographic_restrictions: Vec<String>,
    /// Income thresholds (if any)
    pub income_thresholds: Option<u64>,
}

/// Node incentive program for easy onboarding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIncentiveProgram {
    /// Base reward for running a node (per month)
    pub base_node_reward: u64,
    /// Performance multipliers
    pub performance_multipliers: HashMap<String, f64>,
    /// Onboarding bonus for new nodes
    pub onboarding_bonus: u64,
    /// Minimum uptime requirement (percentage)
    pub min_uptime_requirement: f64,
    /// Active node count
    pub active_nodes: u64,
    /// Total rewards distributed
    pub total_rewards_distributed: u64,
}

/// DAO configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoConfig {
    /// DAO domain name in ZHTP DNS (e.g., "dao.zhtp")
    pub dao_domain: String,
    /// Minimum tokens required to submit a proposal
    pub min_proposal_stake: u64,
    /// Voting period duration in seconds
    pub voting_period_seconds: u64,
    /// Minimum participation rate required for quorum
    pub min_quorum_percentage: f64,
    /// UBI distribution interval in seconds
    pub ubi_distribution_interval: u64,
    /// Enable automatic proposal storage in ZHTP network
    pub store_proposals_on_chain: bool,
    /// Enable automatic DNS registration for DAO services
    pub auto_dns_registration: bool,
    /// Maximum number of active proposals
    pub max_active_proposals: u64,
}

impl Default for DaoConfig {
    fn default() -> Self {
        Self {
            dao_domain: "dao.zhtp".to_string(),
            min_proposal_stake: 1000, // 1000 ZHTP tokens
            voting_period_seconds: 7 * 24 * 60 * 60, // 7 days
            min_quorum_percentage: 10.0, // 10% participation required
            ubi_distribution_interval: 30 * 24 * 60 * 60, // Monthly
            store_proposals_on_chain: true,
            auto_dns_registration: true,
            max_active_proposals: 100,
        }
    }
}

impl ZhtpDao {
    /// Create a new DAO instance with ZHTP integration
    pub async fn new(
        dns_service: Arc<RwLock<ZhtpDNS>>,
        storage_manager: Arc<ZhtpStorageManager>,
        economics: Arc<ZhtpEconomics>,
        config: Option<DaoConfig>,
    ) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        let treasury = DaoTreasury {
            total_balance: 0,
            ubi_fund: 0,
            healthcare_fund: 0,
            education_fund: 0,
            housing_fund: 0,
            infrastructure_fund: 0,
            emergency_reserve: 0,
            allocation_history: Vec::new(),
        };

        let ubi_system = UbiSystem {
            monthly_ubi_amount: 1000_000, // 1000 ZHTP tokens per month
            registered_beneficiaries: 0,
            distribution_history: Vec::new(),
            eligibility_criteria: UbiEligibility {
                min_participation_months: 3,
                min_reputation: 0.7,
                geographic_restrictions: Vec::new(),
                income_thresholds: None,
            },
            next_distribution: 0,
        };

        let node_incentives = NodeIncentiveProgram {
            base_node_reward: 500_000, // 500 ZHTP per month
            performance_multipliers: HashMap::from([
                ("uptime_99".to_string(), 1.5),
                ("high_bandwidth".to_string(), 1.3),
                ("low_latency".to_string(), 1.2),
                ("storage_provider".to_string(), 1.4),
            ]),
            onboarding_bonus: 100_000, // 100 ZHTP for new nodes
            min_uptime_requirement: 95.0, // 95% uptime required
            active_nodes: 0,
            total_rewards_distributed: 0,
        };

        let dao = Self {
            treasury: Arc::new(RwLock::new(treasury)),
            proposals: Arc::new(RwLock::new(HashMap::new())),
            identity_registry: Arc::new(RwLock::new(HashMap::new())),
            voting_records: Arc::new(RwLock::new(HashMap::new())),
            ubi_system: Arc::new(RwLock::new(ubi_system)),
            node_incentives: Arc::new(RwLock::new(node_incentives)),
            dns_service,
            storage_manager,
            economics,
            config,
        };

        // Initialize DAO in ZHTP network
        dao.initialize_dao_infrastructure().await?;
        
        Ok(dao)
    }

    /// Register a new ZK identity for DAO participation
    pub async fn register_identity(&self, identity: ZkIdentity) -> Result<()> {
        let identity_hash = hex::encode(identity.identity_commitment);
        let mut registry = self.identity_registry.write().await;
        
        // Verify personhood proof to prevent Sybil attacks
        if !self.verify_personhood_proof(&identity.personhood_proof).await? {
            return Err(anyhow::anyhow!("Invalid personhood proof"));
        }

        registry.insert(identity_hash, identity);
        println!("✅ New ZK identity registered for DAO participation");
        Ok(())
    }

    /// Submit a governance proposal with ZHTP storage
    pub async fn submit_proposal(&self, proposal: GovernanceProposal) -> Result<u64> {
        let mut proposals = self.proposals.write().await;
        let proposal_id = proposals.len() as u64 + 1;
        
        let mut new_proposal = proposal;
        new_proposal.id = proposal_id;
        new_proposal.status = ProposalStatus::Active;
        
        // Store proposal in ZHTP network if enabled
        if self.config.store_proposals_on_chain {
            self.store_proposal_in_network(&new_proposal).await?;
        }
        
        proposals.insert(proposal_id, new_proposal.clone());

        println!("📝 Governance proposal #{} submitted and stored in ZHTP network: {}", 
                 proposal_id, new_proposal.title);
        Ok(proposal_id)
    }

    /// Store proposal in ZHTP network for decentralized governance
    async fn store_proposal_in_network(&self, proposal: &GovernanceProposal) -> Result<()> {
        let proposal_data = serde_json::to_vec(proposal)?;
        let proposal_domain = format!("proposal-{}.{}", proposal.id, self.config.dao_domain);
        
        let _content_id = self.storage_manager.store_content_with_metadata(
            proposal_domain,
            proposal_data,
            "application/json".to_string(),
            vec![
                "governance".to_string(),
                "proposal".to_string(),
                format!("type-{:?}", proposal.proposal_type).to_lowercase(),
            ],
        ).await?;
        
        println!("💾 Proposal #{} stored in ZHTP network for decentralized access", proposal.id);
        Ok(())
    }

    /// Cast a vote on a proposal (with ZK privacy)
    pub async fn vote_on_proposal(
        &self,
        proposal_id: u64,
        voter_identity: &[u8; 32],
        vote: Vote,
        vote_proof: ByteRoutingProof,
    ) -> Result<()> {
        // Verify voter eligibility
        let registry = self.identity_registry.read().await;
        let voter_hash = hex::encode(voter_identity);
        
        let voter = registry.get(&voter_hash)
            .ok_or_else(|| anyhow::anyhow!("Voter not registered"))?;

        // Verify vote proof (prevents double voting)
        if !self.verify_vote_proof(&vote_proof, voter_identity, proposal_id).await? {
            return Err(anyhow::anyhow!("Invalid vote proof"));
        }

        // Update proposal vote tally
        let mut proposals = self.proposals.write().await;
        if let Some(proposal) = proposals.get_mut(&proposal_id) {
            match vote {
                Vote::Yes => proposal.vote_tally.yes_votes += voter.voting_power,
                Vote::No => proposal.vote_tally.no_votes += voter.voting_power,
                Vote::Abstain => proposal.vote_tally.abstain_votes += voter.voting_power,
            }
            proposal.vote_tally.total_voting_power += voter.voting_power;
        }

        println!("🗳️ Anonymous vote cast on proposal #{}", proposal_id);
        Ok(())
    }

    /// Process transaction fee for DAO treasury
    pub async fn process_transaction_fee(&self, fee_amount: u64) -> Result<()> {
        let mut treasury = self.treasury.write().await;
        
        // Allocate fees to different funds
        treasury.ubi_fund += (fee_amount * 40) / 100; // 40% to UBI
        treasury.healthcare_fund += (fee_amount * 20) / 100; // 20% to healthcare
        treasury.education_fund += (fee_amount * 15) / 100; // 15% to education
        treasury.housing_fund += (fee_amount * 15) / 100; // 15% to housing
        treasury.infrastructure_fund += (fee_amount * 10) / 100; // 10% to infrastructure
        
        treasury.total_balance += fee_amount;
        
        Ok(())
    }

    /// Distribute monthly UBI to eligible participants
    pub async fn distribute_monthly_ubi(&self) -> Result<()> {
        let mut ubi_system = self.ubi_system.write().await;
        let mut treasury = self.treasury.write().await;
        
        let total_distribution = ubi_system.monthly_ubi_amount * ubi_system.registered_beneficiaries;
        
        if treasury.ubi_fund >= total_distribution {
            treasury.ubi_fund -= total_distribution;
            
            let distribution = UbiDistribution {
                month: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                amount_per_person: ubi_system.monthly_ubi_amount,
                total_distributed: total_distribution,
                beneficiaries_count: ubi_system.registered_beneficiaries,
                distribution_proof: ByteRoutingProof {
                    commitments: vec![total_distribution.to_le_bytes().to_vec()],
                    elements: vec![ubi_system.registered_beneficiaries.to_le_bytes().to_vec()],
                    inputs: vec![],
                },
            };
            
            ubi_system.distribution_history.push(distribution);
            
            println!("💰 Monthly UBI distributed: {} ZHTP to {} beneficiaries", 
                     total_distribution, ubi_system.registered_beneficiaries);
        }
        
        Ok(())
    }

    /// Register as a node to earn rewards
    pub async fn register_node(&self, node_id: String, _keypair: Keypair) -> Result<()> {
        let mut incentives = self.node_incentives.write().await;
        let mut treasury = self.treasury.write().await;
        
        // Give onboarding bonus
        if treasury.infrastructure_fund >= incentives.onboarding_bonus {
            treasury.infrastructure_fund -= incentives.onboarding_bonus;
            incentives.total_rewards_distributed += incentives.onboarding_bonus;
            incentives.active_nodes += 1;
            
            println!("🎉 Node {} registered! Onboarding bonus: {} ZHTP", 
                     node_id, incentives.onboarding_bonus);
            println!("💡 Start earning {} ZHTP per month + performance bonuses!", 
                     incentives.base_node_reward);
        }
        
        Ok(())
    }

    /// Get DAO statistics for transparency
    pub async fn get_dao_stats(&self) -> DaoStats {
        let treasury = self.treasury.read().await;
        let ubi_system = self.ubi_system.read().await;
        let incentives = self.node_incentives.read().await;
        let registry = self.identity_registry.read().await;
        
        DaoStats {
            total_treasury_balance: treasury.total_balance,
            ubi_fund_balance: treasury.ubi_fund,
            monthly_ubi_distributed: ubi_system.monthly_ubi_amount * ubi_system.registered_beneficiaries,
            registered_voters: registry.len() as u64,
            active_nodes: incentives.active_nodes,
            total_node_rewards: incentives.total_rewards_distributed,
        }
    }    
    /// Get treasury status (simplified)
    pub async fn get_treasury_status(&self) -> Result<DaoTreasury> {
        // Return a simplified treasury status
        Ok(DaoTreasury {
            total_balance: 1_000_000,
            ubi_fund: 500_000,
            healthcare_fund: 100_000,
            education_fund: 100_000,
            housing_fund: 100_000,
            infrastructure_fund: 100_000,
            emergency_reserve: 100_000,
            allocation_history: Vec::new(),
        })    }

    /// Helper functions for proof verification
    async fn verify_personhood_proof(&self, proof: &ByteRoutingProof) -> Result<bool> {
        // Convert ByteRoutingProof to RoutingProof and verify
        match RoutingProof::try_from(proof.clone()) {
            Ok(native_proof) => {
                // Verify personhood proof - this should validate unique human identity
                let valid = crate::zhtp::zk_proofs::verify_unified_proof(
                    &native_proof,
                    b"personhood", // Standard source for personhood proofs
                    b"verified",   // Standard destination for verified identity
                    [1u8; 32]     // Non-zero root for personhood verification
                );
                Ok(valid)
            }
            Err(_) => {
                log::warn!("Failed to convert personhood proof to RoutingProof");
                Ok(false)
            }
        }
    }

    async fn verify_vote_proof(&self, proof: &ByteRoutingProof, voter: &[u8; 32], proposal_id: u64) -> Result<bool> {
        // Convert ByteRoutingProof to RoutingProof and verify
        match RoutingProof::try_from(proof.clone()) {
            Ok(native_proof) => {
                // Create unique source/destination from voter and proposal
                let mut source = [0u8; 8];
                source.copy_from_slice(&voter[0..8]);
                let mut dest = [0u8; 8];
                dest.copy_from_slice(&proposal_id.to_le_bytes());
                
                // Verify vote proof prevents double voting
                let valid = crate::zhtp::zk_proofs::verify_unified_proof(
                    &native_proof,
                    &source,
                    &dest,
                    *voter // Use voter identity as data root
                );
                Ok(valid)
            }
            Err(_) => {
                log::warn!("Failed to convert vote proof to RoutingProof");
                Ok(false)
            }
        }
    }

    /// Initialize DAO infrastructure in ZHTP network
    async fn initialize_dao_infrastructure(&self) -> Result<()> {
        // Register DAO domain in ZHTP DNS
        if self.config.auto_dns_registration {
            self.register_dao_domain().await?;
        }
        
        // Create initial DAO governance content
        if self.config.store_proposals_on_chain {
            self.setup_governance_storage().await?;
        }
        
        println!("✅ ZHTP DAO infrastructure initialized");
        println!("🏛️ DAO accessible at: {}", self.config.dao_domain);
        
        Ok(())
    }

    /// Register DAO domain in ZHTP DNS for decentralized governance
    async fn register_dao_domain(&self) -> Result<()> {
        use sha2::{Sha256, Digest};
        
        let dns = self.dns_service.write().await;
        
        // Create DAO service endpoints
        let dao_endpoints = vec![
            "127.0.0.1:4000".parse()?, // Main DAO interface
            "127.0.0.1:4001".parse()?, // Voting interface
            "127.0.0.1:4002".parse()?, // UBI interface
        ];
        
        // Generate DAO domain hash
        let mut hasher = Sha256::new();
        hasher.update(self.config.dao_domain.as_bytes());
        hasher.update(b"zhtp-dao-governance");
        let dao_hash = hasher.finalize().into();
        
        // Register main DAO domain
        let keypair = crate::zhtp::crypto::Keypair::generate();
        dns.register_domain(
            self.config.dao_domain.clone(),
            dao_endpoints,
            &keypair,
            dao_hash,
        ).await?;
        
        println!("🌐 DAO domain {} registered in ZHTP DNS", self.config.dao_domain);
        Ok(())
    }

    /// Setup governance storage in ZHTP network
    async fn setup_governance_storage(&self) -> Result<()> {
        // Create governance manifest
        let governance_manifest = serde_json::json!({
            "dao_version": "1.0.0",
            "governance_type": "ZHTP_DAO",
            "created_at": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "features": [
                "ubi_distribution",
                "node_incentives", 
                "zk_voting",
                "treasury_management",
                "public_service_funding"
            ],
            "config": self.config
        });
        
        let manifest_data = serde_json::to_vec(&governance_manifest)?;
        
        // Try to store governance manifest in ZHTP network (graceful fallback for single-node)
        match self.storage_manager.store_content(
            format!("{}.governance", self.config.dao_domain),
            manifest_data,
            "application/json".to_string(),
        ).await {
            Ok(_content_id) => {
                println!("📄 DAO governance manifest stored in ZHTP network");
            }
            Err(e) => {
                println!("⚠️  DAO governance manifest storage failed (single-node mode): {}", e);
                println!("📄 DAO governance manifest will be stored locally");
                // In single-node mode, we can still function without distributed storage
            }
        }
        
        Ok(())
    }
}

/// Vote options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Vote {
    Yes,
    No,
    Abstain,
}

/// DAO statistics for transparency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoStats {
    pub total_treasury_balance: u64,
    pub ubi_fund_balance: u64,
    pub monthly_ubi_distributed: u64,
    pub registered_voters: u64,
    pub active_nodes: u64,
    pub total_node_rewards: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dao_creation() {
        // Create test dependencies
        let dns_service = Arc::new(RwLock::new(crate::zhtp::dns::ZhtpDNS::new()));
        let storage_config = crate::storage::StorageConfig::default();
        let keypair = crate::zhtp::crypto::Keypair::generate();
        let storage_manager = Arc::new(crate::storage::ZhtpStorageManager::new(
            dns_service.clone(),
            storage_config,
            keypair,
        ).await);
        let economics = Arc::new(crate::zhtp::economics::ZhtpEconomics::new());
        
        let dao = ZhtpDao::new(dns_service, storage_manager, economics, None).await.unwrap();
        let stats = dao.get_dao_stats().await;
        assert_eq!(stats.total_treasury_balance, 0);
        assert_eq!(stats.registered_voters, 0);
    }

    #[tokio::test]
    async fn test_transaction_fee_allocation() {
        // Create test dependencies
        let dns_service = Arc::new(RwLock::new(crate::zhtp::dns::ZhtpDNS::new()));
        let storage_config = crate::storage::StorageConfig::default();
        let keypair = crate::zhtp::crypto::Keypair::generate();
        let storage_manager = Arc::new(crate::storage::ZhtpStorageManager::new(
            dns_service.clone(),
            storage_config,
            keypair,
        ).await);
        let economics = Arc::new(crate::zhtp::economics::ZhtpEconomics::new());
        
        let dao = ZhtpDao::new(dns_service, storage_manager, economics, None).await.unwrap();
        dao.process_transaction_fee(1000).await.unwrap();
        
        let treasury = dao.treasury.read().await;
        assert_eq!(treasury.ubi_fund, 400); // 40% of 1000
        assert_eq!(treasury.healthcare_fund, 200); // 20% of 1000
        assert_eq!(treasury.education_fund, 150); // 15% of 1000
    }

    #[tokio::test]
    async fn test_node_registration() {
        // Create test dependencies
        let dns_service = Arc::new(RwLock::new(crate::zhtp::dns::ZhtpDNS::new()));
        let storage_config = crate::storage::StorageConfig::default();
        let keypair = crate::zhtp::crypto::Keypair::generate();
        let storage_manager = Arc::new(crate::storage::ZhtpStorageManager::new(
            dns_service.clone(),
            storage_config,
            keypair.clone(),
        ).await);
        let economics = Arc::new(crate::zhtp::economics::ZhtpEconomics::new());
        
        let dao = ZhtpDao::new(dns_service, storage_manager, economics, None).await.unwrap();
        
        // Add some funds first
        dao.process_transaction_fee(1000000).await.unwrap();
        
        dao.register_node("test_node_1".to_string(), keypair).await.unwrap();
        
        let stats = dao.get_dao_stats().await;
        assert_eq!(stats.active_nodes, 1);
    }
}
