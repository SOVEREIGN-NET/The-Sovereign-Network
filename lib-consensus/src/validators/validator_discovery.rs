//! Validator Discovery Protocol
//!
//! Consensus-layer protocol for validators to announce themselves and discover other validators.
//! Validators publish their information for network-wide discovery and consensus participation.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug};

use lib_crypto::{Hash, PublicKey};

/// Validator announcement for consensus network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAnnouncement {
    /// Validator's identity hash (DID hash)
    pub identity_id: Hash,
    
    /// Validator's consensus public key
    pub consensus_key: PublicKey,
    
    /// Amount of ZHTP tokens staked
    pub stake: u64,
    
    /// Storage capacity provided (bytes)
    pub storage_provided: u64,
    
    /// Commission rate (basis points, 0-10000)
    pub commission_rate: u16,
    
    /// Network endpoints for P2P communication
    pub endpoints: Vec<ValidatorEndpoint>,
    
    /// Current validator status
    pub status: ValidatorStatus,
    
    /// Timestamp of last update
    pub last_updated: u64,
    
    /// Signature over announcement data
    pub signature: Vec<u8>,
}

/// Network endpoint for validator communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEndpoint {
    /// Protocol type (TCP, UDP, etc.)
    pub protocol: String,
    
    /// Network address (IP:port or multiaddr)
    pub address: String,
    
    /// Priority (higher = preferred)
    pub priority: u8,
}

/// Validator operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Validator is active and participating
    Active,
    
    /// Validator is temporarily offline
    Offline,
    
    /// Validator is in unstaking period
    Unstaking,
    
    /// Validator has been slashed
    Slashed,
}

/// Discovery query filter
#[derive(Debug, Clone, Default)]
pub struct ValidatorDiscoveryFilter {
    /// Minimum stake required
    pub min_stake: Option<u64>,
    
    /// Minimum storage capacity
    pub min_storage: Option<u64>,
    
    /// Maximum commission rate
    pub max_commission: Option<u16>,
    
    /// Required status
    pub status: Option<ValidatorStatus>,
    
    /// Maximum results to return
    pub limit: Option<usize>,
}

/// Validator Discovery Protocol for Consensus Layer
pub struct ValidatorDiscoveryProtocol {
    /// Local cache of discovered validators
    validator_cache: Arc<RwLock<HashMap<Hash, ValidatorAnnouncement>>>,
    
    /// Cache TTL in seconds
    cache_ttl: u64,
}

impl ValidatorDiscoveryProtocol {
    /// Create a new validator discovery protocol instance
    pub fn new(cache_ttl: u64) -> Self {
        Self {
            validator_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
        }
    }
    
    /// Announce this validator to the consensus network
    pub async fn announce_validator(
        &self,
        announcement: ValidatorAnnouncement,
    ) -> Result<()> {
        info!(
            "Announcing validator {} with stake {} ZHTP for consensus",
            announcement.identity_id,
            announcement.stake
        );
        
        // Verify announcement is properly signed
        // TODO: Add signature verification
        
        // Update local cache for consensus operations
        let mut cache = self.validator_cache.write().await;
        cache.insert(announcement.identity_id.clone(), announcement.clone());
        
        info!(
            "Validator {} announced to consensus discovery cache",
            announcement.identity_id
        );
        
        // Note: Validators are synchronized from blockchain via
        // ConsensusComponent.sync_validators_from_blockchain() (Gap 3)
        // and can be shared across consensus nodes via network protocols
        
        Ok(())
    }
    
    /// Discover a specific validator by identity for consensus operations
    pub async fn discover_validator(
        &self,
        identity_id: &Hash,
    ) -> Result<Option<ValidatorAnnouncement>> {
        debug!("Discovering validator {} for consensus", identity_id);
        
        // Check local cache
        let cache = self.validator_cache.read().await;
        if let Some(cached) = cache.get(identity_id) {
            // Check if cache entry is still fresh
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            if now - cached.last_updated < self.cache_ttl {
                debug!("Found validator {} in consensus cache", identity_id);
                return Ok(Some(cached.clone()));
            }
        }
        
        // Validator not found in cache or expired
        // Validators are populated via ConsensusComponent.sync_validators_from_blockchain()
        debug!("Validator {} not found in consensus cache", identity_id);
        Ok(None)
    }
    
    /// Discover all active validators matching filter for consensus rounds
    pub async fn discover_validators(
        &self,
        filter: ValidatorDiscoveryFilter,
    ) -> Result<Vec<ValidatorAnnouncement>> {
        info!("Discovering validators for consensus with filter: {:?}", filter);
        
        let cache = self.validator_cache.read().await;
        let mut results: Vec<ValidatorAnnouncement> = cache
            .values()
            .filter(|v| self.matches_filter(v, &filter))
            .cloned()
            .collect();
        
        // Sort by stake (descending) - higher stake validators get priority
        results.sort_by(|a, b| b.stake.cmp(&a.stake));
        
        // Apply limit
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        
        info!("Discovered {} validators for consensus matching filter", results.len());
        Ok(results)
    }
    
    /// Update validator status in consensus network
    pub async fn update_validator_status(
        &self,
        identity_id: &Hash,
        new_status: ValidatorStatus,
    ) -> Result<()> {
        info!("Updating validator {} status to {:?} in consensus", identity_id, new_status);
        
        // Retrieve current announcement
        let mut announcement = self.discover_validator(identity_id).await?
            .ok_or_else(|| anyhow!("Validator not found in consensus: {}", identity_id))?;
        
        // Update status and timestamp
        announcement.status = new_status;
        announcement.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Re-sign announcement
        // TODO: Add signing logic
        
        // Re-announce to consensus network
        self.announce_validator(announcement).await
    }
    
    /// Remove validator from consensus network (called when unstaking completes)
    pub async fn remove_validator(&self, identity_id: &Hash) -> Result<()> {
        info!("Removing validator {} from consensus network", identity_id);
        
        // Remove from local cache
        let mut cache = self.validator_cache.write().await;
        cache.remove(identity_id);
        
        // Update status to Offline for consensus tracking
        drop(cache); // Release lock before calling update_validator_status
        
        self.update_validator_status(identity_id, ValidatorStatus::Offline).await
    }
    
    /// Clear expired entries from cache
    pub async fn cleanup_cache(&self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut cache = self.validator_cache.write().await;
        let initial_count = cache.len();
        
        cache.retain(|_, v| now - v.last_updated < self.cache_ttl);
        
        let removed = initial_count - cache.len();
        if removed > 0 {
            debug!("Cleaned up {} expired validator entries from consensus cache", removed);
        }
        
        Ok(())
    }
    
    /// Get current validator cache statistics for consensus monitoring
    pub async fn get_cache_stats(&self) -> ValidatorCacheStats {
        let cache = self.validator_cache.read().await;
        
        let active_count = cache.values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .count();
        
        ValidatorCacheStats {
            total_validators: cache.len(),
            active_validators: active_count,
            cache_ttl: self.cache_ttl,
        }
    }
    
    /// Populate validator cache from blockchain data (called by ConsensusComponent)
    pub async fn populate_from_blockchain(&self, validators: Vec<ValidatorAnnouncement>) -> Result<()> {
        info!("Populating consensus validator cache from blockchain: {} validators", validators.len());
        
        let mut cache = self.validator_cache.write().await;
        cache.clear();
        
        for validator in validators {
            cache.insert(validator.identity_id.clone(), validator);
        }
        
        info!("Consensus validator cache populated with {} entries", cache.len());
        Ok(())
    }
    
    // Private helper methods
    
    /// Check if validator matches discovery filter
    fn matches_filter(&self, validator: &ValidatorAnnouncement, filter: &ValidatorDiscoveryFilter) -> bool {
        if let Some(min_stake) = filter.min_stake {
            if validator.stake < min_stake {
                return false;
            }
        }
        
        if let Some(min_storage) = filter.min_storage {
            if validator.storage_provided < min_storage {
                return false;
            }
        }
        
        if let Some(max_commission) = filter.max_commission {
            if validator.commission_rate > max_commission {
                return false;
            }
        }
        
        if let Some(required_status) = filter.status {
            if validator.status != required_status {
                return false;
            }
        }
        
        true
    }
}

/// Validator cache statistics for consensus monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCacheStats {
    pub total_validators: usize,
    pub active_validators: usize,
    pub cache_ttl: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validator_discovery_filter() {
        let protocol = ValidatorDiscoveryProtocol::new(3600);
        
        let validator = ValidatorAnnouncement {
            identity_id: Hash::from_bytes(&[0u8; 32]),
            consensus_key: PublicKey {
                dilithium_pk: vec![0u8; 32],
                kyber_pk: Vec::new(),
                key_id: [0u8; 32],
            },
            stake: 1_000_000,
            storage_provided: 10_000_000_000,
            commission_rate: 500, // 5%
            endpoints: vec![],
            status: ValidatorStatus::Active,
            last_updated: 0,
            signature: vec![],
        };
        
        // Test minimum stake filter
        let filter = ValidatorDiscoveryFilter {
            min_stake: Some(500_000),
            ..Default::default()
        };
        assert!(protocol.matches_filter(&validator, &filter));
        
        let filter = ValidatorDiscoveryFilter {
            min_stake: Some(2_000_000),
            ..Default::default()
        };
        assert!(!protocol.matches_filter(&validator, &filter));
        
        // Test status filter
        let filter = ValidatorDiscoveryFilter {
            status: Some(ValidatorStatus::Active),
            ..Default::default()
        };
        assert!(protocol.matches_filter(&validator, &filter));
        
        let filter = ValidatorDiscoveryFilter {
            status: Some(ValidatorStatus::Offline),
            ..Default::default()
        };
        assert!(!protocol.matches_filter(&validator, &filter));
    }
}