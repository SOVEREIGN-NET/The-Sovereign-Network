//! Auto-Graduation Service
//!
//! Background task that periodically checks bonding curve tokens for graduation eligibility
//! and automatically graduates them when thresholds are met.
//!
//! ## Operation
//! - Runs every `check_interval` seconds (default: 60)
//! - Scans all tokens in Curve phase
//! - For each token ready to graduate:
//!   1. Transitions token to Graduated phase
//!   2. Creates AMM pool with seed liquidity
//!   3. Submits graduation transaction to blockchain
//!
//! ## Configuration
//! - `enabled`: Whether auto-graduation is active (default: true)
//! - `check_interval_seconds`: How often to check (default: 60)
//! - `min_seed_liquidity_sov`: Minimum SOV for pool seed (default: 1000 SOV)
//! - `min_seed_liquidity_token`: Minimum tokens for pool seed (default: 1000 tokens)

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{info, warn, debug, error};

use lib_blockchain::Blockchain;
use lib_blockchain::contracts::bonding_curve::{Phase, Threshold};
use lib_blockchain::contracts::sov_swap::SovSwapPool;
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::types::dao::DAOType;

/// Configuration for auto-graduation service
#[derive(Debug, Clone)]
pub struct AutoGraduationConfig {
    /// Whether auto-graduation is enabled
    pub enabled: bool,
    /// How often to check for graduation (seconds)
    pub check_interval_seconds: u64,
    /// Minimum SOV liquidity for pool seed
    pub min_seed_liquidity_sov: u64,
    /// Minimum token liquidity for pool seed  
    pub min_seed_liquidity_token: u64,
    /// Governance address for created pools
    pub pool_governance_address: Option<PublicKey>,
    /// Treasury address for fee collection
    pub pool_treasury_address: Option<PublicKey>,
}

impl Default for AutoGraduationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 60,
            min_seed_liquidity_sov: 1_000_000_000, // 10 SOV (8 decimals)
            min_seed_liquidity_token: 1_000_000_000, // 10 tokens (8 decimals)
            pool_governance_address: None,
            pool_treasury_address: None,
        }
    }
}

/// Auto-graduation service for bonding curve tokens
#[derive(Debug)]
pub struct AutoGraduationService {
    blockchain: Arc<RwLock<Blockchain>>,
    config: AutoGraduationConfig,
    service_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl AutoGraduationService {
    /// Create a new auto-graduation service
    pub fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        config: AutoGraduationConfig,
    ) -> Self {
        Self {
            blockchain,
            config,
            service_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with default configuration
    pub fn with_defaults(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        Self::new(blockchain, AutoGraduationConfig::default())
    }

    /// Start the auto-graduation service
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Auto-graduation service disabled");
            return Ok(());
        }

        if self.service_handle.read().await.is_some() {
            warn!("Auto-graduation service already running");
            return Ok(());
        }

        let blockchain_clone = self.blockchain.clone();
        let config = self.config.clone();

        let service_handle = tokio::spawn(async move {
            Self::graduation_loop(blockchain_clone, config).await;
            warn!("Auto-graduation loop exited unexpectedly!");
        });

        *self.service_handle.write().await = Some(service_handle);
        info!(
            "Auto-graduation service started (check interval: {}s)",
            self.config.check_interval_seconds
        );
        Ok(())
    }

    /// Stop the auto-graduation service
    pub async fn stop(&self) -> Result<()> {
        if let Some(handle) = self.service_handle.write().await.take() {
            handle.abort();
            info!("Auto-graduation service stopped");
        }
        Ok(())
    }

    /// Check if service is running
    pub async fn is_running(&self) -> bool {
        self.service_handle.read().await.is_some()
    }

    /// Main graduation loop
    async fn graduation_loop(
        blockchain: Arc<RwLock<Blockchain>>,
        config: AutoGraduationConfig,
    ) {
        let mut ticker = interval(Duration::from_secs(config.check_interval_seconds));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!("Auto-graduation loop started");

        loop {
            ticker.tick().await;

            if let Err(e) = Self::check_and_graduate_tokens(&blockchain, &config).await {
                error!("Error during graduation check: {}", e);
            }
        }
    }

    /// Check all tokens and graduate eligible ones
    async fn check_and_graduate_tokens(
        blockchain: &Arc<RwLock<Blockchain>>,
        config: &AutoGraduationConfig,
    ) -> Result<()> {
        let mut blockchain_guard = blockchain.write().await;
        
        // Get current timestamp
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Get tokens ready to graduate
        let tokens_to_graduate: Vec<([u8; 32], String)> = {
            let registry = &blockchain_guard.bonding_curve_registry;
            registry.get_ready_to_graduate(current_timestamp)
                .into_iter()
                .map(|token| (token.token_id, token.symbol.clone()))
                .collect()
        };

        if tokens_to_graduate.is_empty() {
            debug!("No tokens ready for graduation");
            return Ok(());
        }

        info!(
            "Found {} token(s) ready to graduate: {:?}",
            tokens_to_graduate.len(),
            tokens_to_graduate.iter().map(|(_, symbol)| symbol).collect::<Vec<_>>()
        );

        for (token_id, symbol) in tokens_to_graduate {
            match Self::graduate_token(
                &mut blockchain_guard,
                &token_id,
                &symbol,
                config,
                current_timestamp,
            ).await {
                Ok(pool_id) => {
                    info!(
                        "Successfully graduated token '{}' with pool {}",
                        symbol,
                        hex::encode(&pool_id[..8])
                    );
                }
                Err(e) => {
                    error!("Failed to graduate token '{}': {}", symbol, e);
                }
            }
        }

        Ok(())
    }

    /// Graduate a single token
    async fn graduate_token(
        blockchain: &mut Blockchain,
        token_id: &[u8; 32],
        symbol: &str,
        config: &AutoGraduationConfig,
        current_timestamp: u64,
    ) -> Result<[u8; 32]> {
        info!("Graduating token '{}' ({})...", symbol, hex::encode(&token_id[..8]));

        // Get token details before graduation
        let (reserve_balance, total_supply) = {
            let token = blockchain.bonding_curve_registry.get(token_id)
                .ok_or_else(|| anyhow::anyhow!("Token not found in registry"))?;
            
            if !token.phase.is_curve_active() {
                return Err(anyhow::anyhow!("Token not in curve phase"));
            }
            
            // Double-check graduation eligibility
            if !token.can_graduate(current_timestamp) {
                return Err(anyhow::anyhow!("Token not eligible for graduation"));
            }

            (token.reserve_balance, token.total_supply)
        };

        // Transition token to Graduated phase
        blockchain.bonding_curve_registry.update_phase(token_id, Phase::Graduated)?;

        // Generate pool ID deterministically
        let pool_id = Self::derive_pool_id(token_id);

        // Update token with pool ID
        {
            let token = blockchain.bonding_curve_registry.get_mut(token_id)
                .ok_or_else(|| anyhow::anyhow!("Token not found after phase update"))?;
            token.amm_pool_id = Some(pool_id);
        }

        // Create AMM pool with seed liquidity
        // Seed liquidity is based on the token's reserve balance
        let seed_sov = reserve_balance.max(config.min_seed_liquidity_sov);
        let seed_tokens = total_supply.max(config.min_seed_liquidity_token);

        // Use provided governance/treasury or create defaults
        let governance = config.pool_governance_address.clone()
            .unwrap_or_else(|| Self::default_governance_address());
        let treasury = config.pool_treasury_address.clone()
            .unwrap_or_else(|| Self::default_treasury_address());

        // Create the pool
        let pool = SovSwapPool::init_pool(
            *token_id,
            DAOType::FP, // Default to FP for graduated tokens
            seed_sov,
            seed_tokens,
            governance,
            treasury,
        )?;

        // Store pool in blockchain
        blockchain.amm_pools.insert(pool_id, pool);

        // Transition to AMM phase
        blockchain.bonding_curve_registry.update_phase(token_id, Phase::AMM)?;

        info!(
            "Token '{}' graduated: pool_id={}, seed_sov={}, seed_tokens={}",
            symbol,
            hex::encode(&pool_id[..8]),
            seed_sov,
            seed_tokens
        );

        Ok(pool_id)
    }

    /// Derive deterministic pool ID from token ID
    fn derive_pool_id(token_id: &[u8; 32]) -> [u8; 32] {
        use blake3::Hasher;
        
        let mut hasher = Hasher::new();
        hasher.update(b"SOV_SWAP_POOL_V1");
        hasher.update(token_id);
        
        let hash = hasher.finalize();
        let mut pool_id = [0u8; 32];
        pool_id.copy_from_slice(hash.as_bytes());
        pool_id
    }

    /// Default governance address for created pools
    fn default_governance_address() -> PublicKey {
        // Use a zero key - should be configured in production
        PublicKey::new(vec![0u8; 1312])
    }

    /// Default treasury address for created pools
    fn default_treasury_address() -> PublicKey {
        // Use a zero key - should be configured in production
        PublicKey::new(vec![0u8; 1312])
    }

    /// Manually trigger graduation check (for testing or API)
    pub async fn manual_check(&self) -> Result<Vec<([u8; 32], String)>> {
        let mut blockchain_guard = self.blockchain.write().await;
        
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let tokens_to_graduate: Vec<([u8; 32], String)> = {
            let registry = &blockchain_guard.bonding_curve_registry;
            registry.get_ready_to_graduate(current_timestamp)
                .into_iter()
                .map(|token| (token.token_id, token.symbol.clone()))
                .collect()
        };

        Ok(tokens_to_graduate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::contracts::bonding_curve::{BondingCurveToken, CurveType, Threshold};

    fn test_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    fn test_token_id(id: u8) -> [u8; 32] {
        [id; 32]
    }

    #[tokio::test]
    async fn test_auto_graduation_service() {
        // Create blockchain with a token ready to graduate
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
        
        let creator = test_key(1);
        let token_id = test_token_id(1);
        
        let mut token = BondingCurveToken::deploy(
            token_id,
            "Test Token".to_string(),
            "TEST".to_string(),
            CurveType::Linear { base_price: 1_000_000, slope: 100 },
            Threshold::ReserveAmount(10_000_000), // 100 USD threshold
            true,
            creator,
            0,
            1_600_000_000,
        ).expect("Failed to deploy token");
        
        // Set token to threshold
        token.reserve_balance = 10_000_000;
        token.total_supply = 1_000_000;
        
        blockchain.bonding_curve_registry.register(token)
            .expect("Failed to register token");
        
        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        
        // Create service
        let config = AutoGraduationConfig {
            enabled: true,
            check_interval_seconds: 1,
            min_seed_liquidity_sov: 1_000,
            min_seed_liquidity_token: 1_000,
            ..Default::default()
        };
        
        let service = AutoGraduationService::new(blockchain_arc.clone(), config);
        
        // Manual check should find the token
        let ready = service.manual_check().await.expect("Check failed");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].1, "TEST");
        
        println!("✅ Auto-graduation service test passed!");
    }
}
