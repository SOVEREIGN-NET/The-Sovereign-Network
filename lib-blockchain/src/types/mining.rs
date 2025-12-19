//! Mining profiles and configuration
//!
//! Provides environment-aware mining settings to ensure alpha/testnet
//! boots fast while mainnet uses real difficulty.

use serde::{Serialize, Deserialize};
use super::Difficulty;

/// Mining profile determines difficulty and iteration limits
///
/// # Profiles
/// - **Bootstrap**: Trivial difficulty for genesis/alpha, mines in <100ms
/// - **Testnet**: Low difficulty, target <1s per block
/// - **Mainnet**: Real adaptive difficulty
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiningProfile {
    /// Trivial difficulty for bootstrap/alpha/development
    /// Target: <100ms mining time
    /// Use case: Single node, genesis, alpha testing
    Bootstrap,

    /// Low difficulty for testnet
    /// Target: <1s mining time
    /// Use case: Multi-node testing, integration tests
    Testnet,

    /// Real adaptive difficulty for mainnet
    /// Target: ~10s average block time with adjustment
    /// Use case: Production network
    Mainnet,
}

impl MiningProfile {
    /// Get mining configuration for this profile
    pub fn config(&self) -> MiningConfig {
        match self {
            MiningProfile::Bootstrap => MiningConfig {
                difficulty: Difficulty::from_bits(0x207fffff), // Very easy - most hashes pass
                max_iterations: 1_000,                         // Will find in <100 iterations typically
                target_block_time_ms: 100,
                allow_instant_mining: true,
            },
            MiningProfile::Testnet => MiningConfig {
                difficulty: Difficulty::from_bits(0x2000ffff), // Easy - finds quickly
                max_iterations: 100_000,                       // Enough for low difficulty
                target_block_time_ms: 1_000,
                allow_instant_mining: false,
            },
            MiningProfile::Mainnet => MiningConfig {
                difficulty: Difficulty::from_bits(0x1d00ffff), // Bitcoin-style initial difficulty
                max_iterations: 100_000_000,                   // 100M for real mining
                target_block_time_ms: 10_000,                  // 10 second blocks
                allow_instant_mining: false,
            },
        }
    }

    /// Get profile from chain ID
    /// - 0x01: Mainnet
    /// - 0x02: Testnet
    /// - 0x03: Development/Bootstrap
    pub fn from_chain_id(chain_id: u8) -> Self {
        match chain_id {
            0x01 => MiningProfile::Mainnet,
            0x02 => MiningProfile::Testnet,
            _ => MiningProfile::Bootstrap,
        }
    }

    /// Get chain ID for this profile
    pub fn chain_id(&self) -> u8 {
        match self {
            MiningProfile::Bootstrap => 0x03,
            MiningProfile::Testnet => 0x02,
            MiningProfile::Mainnet => 0x01,
        }
    }

    /// Check if this profile allows bootstrap-mode features
    pub fn is_bootstrap_allowed(&self) -> bool {
        matches!(self, MiningProfile::Bootstrap)
    }

    /// Check if this is a production profile requiring full security
    pub fn is_production(&self) -> bool {
        matches!(self, MiningProfile::Mainnet)
    }
}

impl Default for MiningProfile {
    fn default() -> Self {
        MiningProfile::Bootstrap
    }
}

impl std::fmt::Display for MiningProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiningProfile::Bootstrap => write!(f, "Bootstrap"),
            MiningProfile::Testnet => write!(f, "Testnet"),
            MiningProfile::Mainnet => write!(f, "Mainnet"),
        }
    }
}

/// Mining configuration derived from profile
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MiningConfig {
    /// Initial/base difficulty for this profile
    pub difficulty: Difficulty,

    /// Maximum iterations before mining fails
    pub max_iterations: u64,

    /// Target block time in milliseconds
    pub target_block_time_ms: u64,

    /// Allow instant mining (skip PoW entirely for first blocks)
    pub allow_instant_mining: bool,
}

impl MiningConfig {
    /// Create config for bootstrap/alpha (trivial difficulty)
    pub fn bootstrap() -> Self {
        MiningProfile::Bootstrap.config()
    }

    /// Create config for testnet (low difficulty)
    pub fn testnet() -> Self {
        MiningProfile::Testnet.config()
    }

    /// Create config for mainnet (real difficulty)
    pub fn mainnet() -> Self {
        MiningProfile::Mainnet.config()
    }

    /// Check if difficulty is appropriate for iteration limit
    pub fn validate(&self) -> Result<(), &'static str> {
        // Bootstrap mode should have very high difficulty bits (= easy mining)
        if self.max_iterations < 10_000 && self.difficulty.bits() < 0x20000000 {
            return Err("Low iteration limit requires high difficulty bits (easy mining)");
        }

        // Configs with instant mining disabled need enough iterations
        // Testnet: 100K iterations is acceptable
        // Mainnet: needs 1M+ iterations
        if !self.allow_instant_mining && self.max_iterations < 100_000 {
            return Err("Non-bootstrap configs require at least 100K max iterations");
        }

        // Instant mining should only be used with easy difficulty
        if self.allow_instant_mining && self.difficulty.bits() < 0x20000000 {
            return Err("Instant mining requires easy difficulty (bits >= 0x20000000)");
        }

        Ok(())
    }
}

impl Default for MiningConfig {
    fn default() -> Self {
        MiningProfile::default().config()
    }
}

/// Get mining config from environment variables
///
/// This is a convenience function for code that doesn't have direct access
/// to the Environment enum. It checks:
/// 1. ZHTP_CHAIN_ID set but malformed → Mainnet (fail-safe)
/// 2. ZHTP_CHAIN_ID=1 (mainnet) → ALWAYS uses Mainnet profile (guardrail)
/// 3. ZHTP_ALLOW_BOOTSTRAP=1 → Bootstrap profile (only for dev/testnet)
/// 4. ZHTP_CHAIN_ID → Uses chain ID to determine profile
/// 5. Default (no env vars) → Bootstrap (safe for alpha)
///
/// # Security Guardrails
/// - Bootstrap mode is NEVER allowed on mainnet (chain_id=1), even if
///   ZHTP_ALLOW_BOOTSTRAP=1 is set
/// - Malformed ZHTP_CHAIN_ID values (e.g., "mainnet" instead of "1") default
///   to Mainnet for safety, NOT Bootstrap
pub fn get_mining_config_from_env() -> MiningConfig {
    // GUARDRAIL: Check for ZHTP_CHAIN_ID first
    if let Ok(chain_id_str) = std::env::var("ZHTP_CHAIN_ID") {
        match chain_id_str.parse::<u8>() {
            Ok(chain_id) => {
                if chain_id == 0x01 {
                    // Mainnet - ALWAYS use full difficulty regardless of other settings
                    if std::env::var("ZHTP_ALLOW_BOOTSTRAP").ok().map(|v| v == "1").unwrap_or(false) {
                        tracing::warn!("⚠️ ZHTP_ALLOW_BOOTSTRAP ignored on mainnet - security guardrail active");
                    }
                    tracing::info!("🔒 Mainnet detected: Using Mainnet mining profile (full difficulty)");
                    return MiningProfile::Mainnet.config();
                }
                // Valid non-mainnet chain ID - continue to check ZHTP_ALLOW_BOOTSTRAP
            }
            Err(_) => {
                // SECURITY: Malformed chain ID - fail safe to Mainnet
                tracing::error!(
                    "⚠️ ZHTP_CHAIN_ID='{}' is invalid (expected 1/2/3). Defaulting to MAINNET for safety!",
                    chain_id_str
                );
                return MiningProfile::Mainnet.config();
            }
        }
    }

    // Check for explicit bootstrap mode (only works when ZHTP_CHAIN_ID is not mainnet or not set)
    if std::env::var("ZHTP_ALLOW_BOOTSTRAP")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        tracing::info!("⚡ ZHTP_ALLOW_BOOTSTRAP=1: Using Bootstrap mining profile");
        return MiningProfile::Bootstrap.config();
    }

    // Check for explicit chain ID (we already validated it parses above)
    if let Ok(chain_id_str) = std::env::var("ZHTP_CHAIN_ID") {
        if let Ok(chain_id) = chain_id_str.parse::<u8>() {
            let profile = MiningProfile::from_chain_id(chain_id);
            tracing::info!("Using {} mining profile from ZHTP_CHAIN_ID={}", profile, chain_id);
            return profile.config();
        }
    }

    // Default to Bootstrap for alpha safety (only when NO env vars are set)
    tracing::info!("Using default Bootstrap mining profile (no ZHTP_CHAIN_ID set)");
    MiningProfile::Bootstrap.config()
}

/// Validate that mining config is appropriate for the chain
///
/// Returns an error if bootstrap/testnet config is used with mainnet chain_id
pub fn validate_mining_for_chain(config: &MiningConfig, chain_id: u8) -> Result<(), &'static str> {
    if chain_id == 0x01 {
        // Mainnet checks
        if config.allow_instant_mining {
            return Err("Instant mining not allowed on mainnet");
        }
        if config.max_iterations < 1_000_000 {
            return Err("Mainnet requires at least 1M max iterations");
        }
        if config.difficulty.bits() > 0x20000000 {
            return Err("Mainnet requires difficulty below 0x20000000 (not too easy)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_mines_instantly() {
        let config = MiningConfig::bootstrap();
        // Bootstrap should have very easy difficulty (high bits = easy)
        assert!(config.difficulty.bits() >= 0x20000000);
        assert!(config.max_iterations <= 1_000);
    }

    #[test]
    fn test_testnet_reasonable_difficulty() {
        let config = MiningConfig::testnet();
        assert!(config.max_iterations <= 100_000);
        assert!(config.max_iterations >= 10_000);
    }

    #[test]
    fn test_mainnet_real_difficulty() {
        let config = MiningConfig::mainnet();
        assert!(config.max_iterations >= 10_000_000);
        assert!(!config.allow_instant_mining);
    }

    #[test]
    fn test_chain_id_mapping() {
        assert_eq!(MiningProfile::from_chain_id(0x01), MiningProfile::Mainnet);
        assert_eq!(MiningProfile::from_chain_id(0x02), MiningProfile::Testnet);
        assert_eq!(MiningProfile::from_chain_id(0x03), MiningProfile::Bootstrap);
        assert_eq!(MiningProfile::from_chain_id(0xFF), MiningProfile::Bootstrap); // Unknown defaults to bootstrap
    }

    #[test]
    fn test_profile_guardrails() {
        assert!(MiningProfile::Bootstrap.is_bootstrap_allowed());
        assert!(!MiningProfile::Testnet.is_bootstrap_allowed());
        assert!(!MiningProfile::Mainnet.is_bootstrap_allowed());

        assert!(!MiningProfile::Bootstrap.is_production());
        assert!(!MiningProfile::Testnet.is_production());
        assert!(MiningProfile::Mainnet.is_production());
    }

    #[test]
    fn test_mainnet_validation_rejects_bootstrap() {
        let bootstrap_config = MiningConfig::bootstrap();
        let testnet_config = MiningConfig::testnet();
        let mainnet_config = MiningConfig::mainnet();

        // Bootstrap config should be rejected on mainnet
        assert!(validate_mining_for_chain(&bootstrap_config, 0x01).is_err());

        // Testnet config should be rejected on mainnet (too few iterations)
        assert!(validate_mining_for_chain(&testnet_config, 0x01).is_err());

        // Mainnet config should pass on mainnet
        assert!(validate_mining_for_chain(&mainnet_config, 0x01).is_ok());

        // All configs should pass on dev/testnet
        assert!(validate_mining_for_chain(&bootstrap_config, 0x03).is_ok());
        assert!(validate_mining_for_chain(&testnet_config, 0x02).is_ok());
    }
}
