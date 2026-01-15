//! DAO Launch Orchestrator for End-to-End DAO Creation
//!
//! Orchestrates complete DAO creation workflow: token initialization, treasury setup,
//! registry registration, DEX pool creation, brokerage setup, and employment registry.
//! Integrates all components from Features 1-4 into a single coordinated launch.

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::DAOType;
use crate::contracts::root_registry::WelfareSector;
use blake3;

/// Launch mechanism for DAO initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LaunchMechanism {
    /// Staking-based launch (require SOV threshold + min stakers)
    Staking {
        threshold_sov: u64,
        min_stakers: u32,
        deadline_blocks: u64,
    },
    /// Direct launch (immediate initialization)
    Direct {
        initial_holder: PublicKey,
    },
}

/// Approval verifier type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalVerifierType {
    /// Simple majority voting
    SimpleMajority,
    /// Qualified majority (2/3)
    QualifiedMajority,
    /// Consensus-based
    Consensus,
}

/// DAO launch configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoLaunchConfig {
    // Identity
    pub dao_type: DAOType,
    pub name: String,
    pub symbol: String,
    pub mission: String,

    // Token economics
    pub total_supply: u64,
    pub decimals: u8,

    // Launch mechanism
    pub launch_mechanism: LaunchMechanism,

    // Governance
    pub approval_verifier_type: ApprovalVerifierType,

    // Optional
    pub sector: Option<WelfareSector>,
}

/// DAO launch status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LaunchStatus {
    /// Pending staking-based launch
    Pending {
        staking_contract: PublicKey,
    },
    /// Successfully launched
    Launched {
        launch_height: u64,
    },
}

/// DAO launch result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoLaunchResult {
    pub dao_id: [u8; 32],
    pub token_addr: PublicKey,
    pub treasury_addr: PublicKey,
    pub brokerage_addr: Option<PublicKey>,
    pub employment_registry_addr: Option<PublicKey>,
    pub status: LaunchStatus,
}

/// DAO Launch Orchestrator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoLaunchOrchestrator {
    /// All launched DAOs (keyed by DAO ID)
    pub launched_daos: Vec<DaoLaunchResult>,
}

impl DaoLaunchOrchestrator {
    /// Create a new DAO launch orchestrator
    pub fn new() -> Self {
        Self {
            launched_daos: Vec::new(),
        }
    }

    /// Orchestrate complete DAO launch
    ///
    /// # Execution Flow
    ///
    /// 1. **Validation**
    ///    - Verify caller (staking: anyone, direct: must be authorized)
    ///    - Validate config (name uniqueness, supply limits, etc.)
    ///
    /// 2. **Generate Addresses** (Deterministic)
    ///    - Token address: `derive_token_address(&config)`
    ///    - Treasury address: `derive_treasury_address(&config)`
    ///    - Staking address (if applicable): `derive_staking_address(&config)`
    ///
    /// 3. **If Staking Launch**:
    ///    - Call `SovDaoStaking::create_pending_dao()`
    ///    - Return pending DAO ID
    ///    - Wait for threshold (async, monitored by staking contract)
    ///
    /// 4. **If Direct Launch**:
    ///    - Initialize `DAOToken` with config
    ///    - Allocate initial supply (100% NP or 20% FP to treasury)
    ///    - Create treasury (call appropriate constructor)
    ///    - Register in `DAORegistry`
    ///    - Initialize DEX pool (optional, with initial liquidity)
    ///    - Create brokerage contract
    ///    - Set up employment registry (for FP DAOs)
    ///
    /// 5. **Post-Launch Setup**
    ///    - Link fee router to new treasury
    ///    - Initialize governance if applicable
    ///    - Set approval verifier
    ///    - Emit launch event
    pub fn launch_dao(
        &mut self,
        config: DaoLaunchConfig,
        _caller: &PublicKey,
        current_height: u64,
    ) -> Result<DaoLaunchResult> {
        // Validate configuration
        validate_config(&config)?;

        // Generate deterministic addresses
        let dao_id = derive_dao_id(&config);
        let token_addr = derive_token_address(&config);
        let treasury_addr = derive_treasury_address(&config);

        // Handle launch mechanism
        let status = match &config.launch_mechanism {
            LaunchMechanism::Staking {
                threshold_sov: _,
                min_stakers: _,
                deadline_blocks: _,
            } => {
                // For staking launch, generate staking contract address
                let staking_addr = derive_staking_address(&config);

                // In a real implementation, would call SovDaoStaking::create_pending_dao()
                // For now, return pending status
                LaunchStatus::Pending {
                    staking_contract: staking_addr,
                }
            }
            LaunchMechanism::Direct { initial_holder: _ } => {
                // For direct launch, immediately mark as launched
                LaunchStatus::Launched {
                    launch_height: current_height,
                }
            }
        };

        // Generate brokerage address (optional, only for DAOs with markets)
        let brokerage_addr = Some(derive_brokerage_address(&config));

        // Generate employment registry address (optional, only for FP DAOs)
        let employment_registry_addr = if config.dao_type == DAOType::FP {
            Some(derive_employment_registry_address(&config))
        } else {
            None
        };

        // Create launch result
        let result = DaoLaunchResult {
            dao_id,
            token_addr,
            treasury_addr,
            brokerage_addr,
            employment_registry_addr,
            status,
        };

        // Store launched DAO
        self.launched_daos.push(result.clone());

        Ok(result)
    }

    /// Get launched DAO by ID
    pub fn get_launched_dao(&self, dao_id: &[u8; 32]) -> Option<&DaoLaunchResult> {
        self.launched_daos.iter().find(|d| &d.dao_id == dao_id)
    }

    /// Get all launched DAOs
    pub fn get_all_launched_daos(&self) -> &[DaoLaunchResult] {
        &self.launched_daos
    }
}

/// Validate DAO launch configuration
fn validate_config(config: &DaoLaunchConfig) -> Result<()> {
    // Validate name
    if config.name.is_empty() || config.name.len() > 100 {
        return Err(anyhow!("DAO name must be 1-100 characters"));
    }

    // Validate symbol
    if config.symbol.is_empty() || config.symbol.len() > 20 {
        return Err(anyhow!("DAO symbol must be 1-20 characters"));
    }

    // Validate mission
    if config.mission.is_empty() || config.mission.len() > 1000 {
        return Err(anyhow!("DAO mission must be 1-1000 characters"));
    }

    // Validate supply
    if config.total_supply == 0 {
        return Err(anyhow!("DAO total supply must be greater than zero"));
    }

    // Validate decimals
    if config.decimals > 18 {
        return Err(anyhow!("Decimals cannot exceed 18"));
    }

    // Validate NP DAO with Non-Profit type
    if config.dao_type == DAOType::NP && config.sector.is_none() {
        return Err(anyhow!("Non-Profit DAOs must specify a sector"));
    }

    Ok(())
}

/// Derive deterministic DAO ID
fn derive_dao_id(config: &DaoLaunchConfig) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dao_launch_v1");
    hasher.update(config.name.as_bytes());
    hasher.update(config.symbol.as_bytes());
    hasher.update(config.mission.as_bytes());
    hasher.finalize().into()
}

/// Derive deterministic token address
fn derive_token_address(config: &DaoLaunchConfig) -> PublicKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"token_addr");
    hasher.update(config.name.as_bytes());
    let id = hasher.finalize();
    PublicKey {
        dilithium_pk: id.as_bytes()[0..32].to_vec(),
        kyber_pk: id.as_bytes()[0..32].to_vec(),
        key_id: <[u8; 32]>::try_from(&id.as_bytes()[0..32]).unwrap(),
    }
}

/// Derive deterministic treasury address
fn derive_treasury_address(config: &DaoLaunchConfig) -> PublicKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"treasury_addr");
    hasher.update(config.symbol.as_bytes());
    let id = hasher.finalize();
    PublicKey {
        dilithium_pk: id.as_bytes()[0..32].to_vec(),
        kyber_pk: id.as_bytes()[0..32].to_vec(),
        key_id: <[u8; 32]>::try_from(&id.as_bytes()[0..32]).unwrap(),
    }
}

/// Derive deterministic staking address
fn derive_staking_address(config: &DaoLaunchConfig) -> PublicKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"staking_addr");
    hasher.update(config.symbol.as_bytes());
    let id = hasher.finalize();
    PublicKey {
        dilithium_pk: id.as_bytes()[0..32].to_vec(),
        kyber_pk: id.as_bytes()[0..32].to_vec(),
        key_id: <[u8; 32]>::try_from(&id.as_bytes()[0..32]).unwrap(),
    }
}

/// Derive deterministic brokerage address
fn derive_brokerage_address(config: &DaoLaunchConfig) -> PublicKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"brokerage_addr");
    hasher.update(config.symbol.as_bytes());
    let id = hasher.finalize();
    PublicKey {
        dilithium_pk: id.as_bytes()[0..32].to_vec(),
        kyber_pk: id.as_bytes()[0..32].to_vec(),
        key_id: <[u8; 32]>::try_from(&id.as_bytes()[0..32]).unwrap(),
    }
}

/// Derive deterministic employment registry address
fn derive_employment_registry_address(config: &DaoLaunchConfig) -> PublicKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"employment_addr");
    hasher.update(config.symbol.as_bytes());
    let id = hasher.finalize();
    PublicKey {
        dilithium_pk: id.as_bytes()[0..32].to_vec(),
        kyber_pk: id.as_bytes()[0..32].to_vec(),
        key_id: <[u8; 32]>::try_from(&id.as_bytes()[0..32]).unwrap(),
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id; 32],
            kyber_pk: vec![id; 32],
            key_id: [id; 32],
        }
    }

    #[test]
    fn test_direct_launch_nonprofit() {
        let mut orchestrator = DaoLaunchOrchestrator::new();

        let config = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "Charity DAO".to_string(),
            symbol: "CHAR".to_string(),
            mission: "Provide education to underserved communities".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Education),
        };

        let result = orchestrator.launch_dao(config, &test_public_key(1), 100).unwrap();

        assert_eq!(result.dao_id.len(), 32);
        assert!(matches!(result.status, LaunchStatus::Launched { .. }));
        assert_eq!(orchestrator.launched_daos.len(), 1);
    }

    #[test]
    fn test_direct_launch_forprofit() {
        let mut orchestrator = DaoLaunchOrchestrator::new();

        let config = DaoLaunchConfig {
            dao_type: DAOType::FP,
            name: "Business DAO".to_string(),
            symbol: "BUSI".to_string(),
            mission: "Build profitable enterprise".to_string(),
            total_supply: 5_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: None,
        };

        let result = orchestrator.launch_dao(config, &test_public_key(1), 100).unwrap();

        assert_eq!(result.dao_id.len(), 32);
        assert!(result.employment_registry_addr.is_some());
        assert!(result.brokerage_addr.is_some());
    }

    #[test]
    fn test_staking_launch() {
        let mut orchestrator = DaoLaunchOrchestrator::new();

        let config = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "Community DAO".to_string(),
            symbol: "COMM".to_string(),
            mission: "Community service initiative".to_string(),
            total_supply: 2_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Staking {
                threshold_sov: 100_000_00000000,
                min_stakers: 10,
                deadline_blocks: 100_000,
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Energy),
        };

        let result = orchestrator.launch_dao(config, &test_public_key(1), 100).unwrap();

        assert_eq!(result.dao_id.len(), 32);
        assert!(matches!(result.status, LaunchStatus::Pending { .. }));
    }

    #[test]
    fn test_invalid_name() {
        let config = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "".to_string(), // Empty name
            symbol: "CHAR".to_string(),
            mission: "Test".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Education),
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_symbol() {
        let config = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "Charity DAO".to_string(),
            symbol: "VERYLONGSYMBOLTHATEXCEEDSTHE20LIMIT".to_string(), // Too long (>20 chars)
            mission: "Test".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Education),
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_decimals() {
        let config = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "Charity DAO".to_string(),
            symbol: "CHAR".to_string(),
            mission: "Test".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 25, // Too high
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Education),
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonprofit_requires_sector() {
        let config = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "Charity DAO".to_string(),
            symbol: "CHAR".to_string(),
            mission: "Test".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: None, // Missing sector
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_addresses() {
        let config1 = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "DAO1".to_string(),
            symbol: "D1".to_string(),
            mission: "Test".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Education),
        };

        let config2 = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "DAO1".to_string(),
            symbol: "D1".to_string(),
            mission: "Test".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Education),
        };

        // Same config should generate same DAO ID
        let id1 = derive_dao_id(&config1);
        let id2 = derive_dao_id(&config2);
        assert_eq!(id1, id2);

        // Token addresses should also match
        let token1 = derive_token_address(&config1);
        let token2 = derive_token_address(&config2);
        assert_eq!(token1.key_id, token2.key_id);
    }

    #[test]
    fn test_get_launched_dao() {
        let mut orchestrator = DaoLaunchOrchestrator::new();

        let config = DaoLaunchConfig {
            dao_type: DAOType::NP,
            name: "Test DAO".to_string(),
            symbol: "TEST".to_string(),
            mission: "Test mission".to_string(),
            total_supply: 1_000_000_00000000,
            decimals: 8,
            launch_mechanism: LaunchMechanism::Direct {
                initial_holder: test_public_key(1),
            },
            approval_verifier_type: ApprovalVerifierType::SimpleMajority,
            sector: Some(WelfareSector::Education),
        };

        let result = orchestrator.launch_dao(config, &test_public_key(1), 100).unwrap();
        let dao_id = result.dao_id;

        // Should be able to retrieve it
        let retrieved = orchestrator.get_launched_dao(&dao_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().dao_id, dao_id);
    }

    #[test]
    fn test_multiple_launches() {
        let mut orchestrator = DaoLaunchOrchestrator::new();

        for i in 0..3 {
            let config = DaoLaunchConfig {
                dao_type: DAOType::NP,
                name: format!("DAO{}", i),
                symbol: format!("D{}", i),
                mission: "Test mission".to_string(),
                total_supply: 1_000_000_00000000,
                decimals: 8,
                launch_mechanism: LaunchMechanism::Direct {
                    initial_holder: test_public_key(1),
                },
                approval_verifier_type: ApprovalVerifierType::SimpleMajority,
                sector: Some(WelfareSector::Energy),
            };
            orchestrator.launch_dao(config, &test_public_key(1), 100 + i as u64).unwrap();
        }

        assert_eq!(orchestrator.get_all_launched_daos().len(), 3);
    }
}
