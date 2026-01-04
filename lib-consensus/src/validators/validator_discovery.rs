//! Validator Discovery Protocol
//!
//! Consensus-layer protocol for validators to announce themselves and discover other validators.
//! Validators publish their information for network-wide discovery and consensus participation.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use lib_crypto::{Hash, PublicKey};

const MAX_CLOCK_SKEW_SECS: u64 = 300;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorAnnouncementPayload {
    identity_id: Hash,
    consensus_key: PublicKey,
    stake: u64,
    storage_provided: u64,
    commission_rate: u16,
    endpoints: Vec<ValidatorEndpoint>,
    status: ValidatorStatus,
    last_updated: u64,
}

impl ValidatorAnnouncement {
    pub fn sign(mut self, keypair: &lib_crypto::keypair::generation::KeyPair) -> Result<Self> {
        if keypair.public_key.dilithium_pk != self.consensus_key.dilithium_pk {
            return Err(anyhow!(
                "Keypair does not match announcement consensus key"
            ));
        }

        self.endpoints = canonicalize_endpoints(&self.endpoints);
        let payload = self.payload_bytes()?;
        let signature = keypair.sign(&payload)?;
        self.signature = signature.signature;
        Ok(self)
    }

    pub fn verify_signature(&self) -> Result<bool> {
        if self.consensus_key.dilithium_pk.is_empty() {
            return Ok(false);
        }

        let payload = self.payload_bytes()?;
        lib_crypto::verification::verify_signature(
            &payload,
            &self.signature,
            &self.consensus_key.dilithium_pk,
        )
    }

    fn payload_bytes(&self) -> Result<Vec<u8>> {
        let payload = ValidatorAnnouncementPayload {
            identity_id: self.identity_id.clone(),
            consensus_key: self.consensus_key.clone(),
            stake: self.stake,
            storage_provided: self.storage_provided,
            commission_rate: self.commission_rate,
            endpoints: canonicalize_endpoints(&self.endpoints),
            status: self.status,
            last_updated: self.last_updated,
        };
        bincode::serialize(&payload).map_err(|e| anyhow!("ValidatorAnnouncement encode failed: {e}"))
    }
}

fn canonicalize_endpoints(endpoints: &[ValidatorEndpoint]) -> Vec<ValidatorEndpoint> {
    let mut endpoints = endpoints.to_vec();
    endpoints.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.address.cmp(&b.address))
    });
    endpoints
}

/// Network endpoint for validator communication
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

    /// Optional transport for gossip/network discovery
    transport: Option<Arc<dyn ValidatorDiscoveryTransport>>,
}

impl ValidatorDiscoveryProtocol {
    /// Create a new validator discovery protocol instance
    pub fn new(cache_ttl: u64) -> Self {
        Self {
            validator_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            transport: None,
        }
    }

    /// Create a new discovery protocol with a transport implementation
    pub fn with_transport(
        cache_ttl: u64,
        transport: Arc<dyn ValidatorDiscoveryTransport>,
    ) -> Self {
        Self {
            validator_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            transport: Some(transport),
        }
    }

    /// Announce this validator to the consensus network
    pub async fn announce_validator(&self, announcement: ValidatorAnnouncement) -> Result<()> {
        info!(
            "Announcing validator {} with stake {} ZHTP for consensus",
            announcement.identity_id, announcement.stake
        );

        self.validate_announcement(&announcement).await?;

        // Update local cache for consensus operations
        let mut cache = self.validator_cache.write().await;
        cache.insert(announcement.identity_id.clone(), announcement.clone());

        info!(
            "Validator {} announced to consensus discovery cache",
            announcement.identity_id
        );

        if let Some(transport) = &self.transport {
            transport.publish_announcement(announcement).await?;
        }

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

        drop(cache);

        if let Some(transport) = &self.transport {
            if let Some(remote) = transport.fetch_validator(identity_id).await? {
                if self.ingest_announcement(remote.clone()).await? {
                    return Ok(Some(remote));
                }
            }
        }

        debug!("Validator {} not found in consensus cache", identity_id);
        Ok(None)
    }

    /// Discover all active validators matching filter for consensus rounds
    pub async fn discover_validators(
        &self,
        filter: ValidatorDiscoveryFilter,
    ) -> Result<Vec<ValidatorAnnouncement>> {
        info!(
            "Discovering validators for consensus with filter: {:?}",
            filter
        );

        let cache = self.validator_cache.read().await;
        let mut results: Vec<ValidatorAnnouncement> = cache
            .values()
            .filter(|v| self.matches_filter(v, &filter))
            .cloned()
            .collect();
        drop(cache);

        if let Some(transport) = &self.transport {
            let remote = transport.fetch_validators(filter.clone()).await?;
            for announcement in remote {
                if self.ingest_announcement(announcement.clone()).await? {
                    results.push(announcement);
                }
            }
        }

        // Sort by stake (descending) - higher stake validators get priority
        results.sort_by(|a, b| b.stake.cmp(&a.stake));

        // Apply limit
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        info!(
            "Discovered {} validators for consensus matching filter",
            results.len()
        );
        Ok(results)
    }

    /// Update validator status in consensus network
    pub async fn update_validator_status(
        &self,
        identity_id: &Hash,
        new_status: ValidatorStatus,
        keypair: &lib_crypto::keypair::generation::KeyPair,
    ) -> Result<()> {
        info!(
            "Updating validator {} status to {:?} in consensus",
            identity_id, new_status
        );

        // Retrieve current announcement
        let mut announcement = self
            .discover_validator(identity_id)
            .await?
            .ok_or_else(|| anyhow!("Validator not found in consensus: {}", identity_id))?;

        if keypair.public_key.dilithium_pk != announcement.consensus_key.dilithium_pk {
            return Err(anyhow!(
                "Keypair does not match validator consensus key"
            ));
        }

        announcement.status = new_status;
        announcement.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        announcement = announcement.sign(keypair)?;

        // Re-announce to consensus network
        self.announce_validator(announcement).await
    }

    /// Remove validator from consensus network (called when unstaking completes)
    pub async fn remove_validator(
        &self,
        identity_id: &Hash,
        keypair: &lib_crypto::keypair::generation::KeyPair,
    ) -> Result<()> {
        info!("Removing validator {} from consensus network", identity_id);

        // Remove from local cache
        let mut cache = self.validator_cache.write().await;
        cache.remove(identity_id);

        // Update status to Offline for consensus tracking
        drop(cache); // Release lock before calling update_validator_status

        self.update_validator_status(identity_id, ValidatorStatus::Offline, keypair)
            .await
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
            debug!(
                "Cleaned up {} expired validator entries from consensus cache",
                removed
            );
        }

        Ok(())
    }

    /// Get current validator cache statistics for consensus monitoring
    pub async fn get_cache_stats(&self) -> ValidatorCacheStats {
        let cache = self.validator_cache.read().await;

        let active_count = cache
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .count();

        ValidatorCacheStats {
            total_validators: cache.len(),
            active_validators: active_count,
            cache_ttl: self.cache_ttl,
        }
    }

    /// Populate validator cache from blockchain data (called by ConsensusComponent)
    pub async fn populate_from_blockchain(
        &self,
        validators: Vec<ValidatorAnnouncement>,
    ) -> Result<()> {
        info!(
            "Populating consensus validator cache from blockchain: {} validators",
            validators.len()
        );

        let mut cache = self.validator_cache.write().await;
        cache.clear();

        for validator in validators {
            if self.validate_announcement(&validator).await.is_err() {
                continue;
            }
            cache.insert(validator.identity_id.clone(), validator);
        }

        info!(
            "Consensus validator cache populated with {} entries",
            cache.len()
        );
        Ok(())
    }

    /// Select the best endpoint for a validator, respecting priority
    ///
    /// # Invariants
    /// - Endpoint selection is deterministic across all consensus nodes
    /// - Blockchain-sourced announcements are authoritative
    /// - Gossip may add endpoints but never overrides priority semantics
    /// - Consensus selects endpoints; lib-network executes connections
    ///
    /// # Determinism Guarantees
    /// Selection uses a stable sort order:
    /// 1. Higher priority wins (higher u8 values preferred)
    /// 2. Stable tie-breaker on protocol (alphabetical)
    /// 3. Stable tie-breaker on address (alphabetical)
    pub async fn select_validator_endpoint(
        &self,
        identity_id: &Hash,
    ) -> Result<Option<ValidatorEndpoint>> {
        let cache = self.validator_cache.read().await;
        let validator = match cache.get(identity_id) {
            Some(v) => v,
            None => return Ok(None),
        };

        if validator.endpoints.is_empty() {
            return Ok(None);
        }

        // Deterministic priority selection
        let mut endpoints = validator.endpoints.clone();
        endpoints.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority) // higher priority first
                .then_with(|| a.protocol.cmp(&b.protocol))
                .then_with(|| a.address.cmp(&b.address))
        });

        debug!(
            "Selected endpoint for validator {}: protocol={}, address={}",
            identity_id,
            endpoints[0].protocol,
            endpoints[0].address
        );

        Ok(endpoints.into_iter().next())
    }

    /// Resolve validator endpoint for routing to lib-network
    ///
    /// Returns the protocol and address of the best endpoint, ready for
    /// network routing. This is the primary method for consensus to obtain
    /// actionable network endpoints.
    ///
    /// # Invariants
    /// - No network capability checks performed (consensus domain)
    /// - No connection attempts or fallback logic (network domain)
    /// - Endpoint selection is deterministic and consensus-driven
    ///
    /// # Returns
    /// Some((protocol, address)) if validator has endpoints, None otherwise
    pub async fn resolve_validator_route(
        &self,
        identity_id: &Hash,
    ) -> Result<Option<(String, String)>> {
        if let Some(endpoint) = self.select_validator_endpoint(identity_id).await? {
            return Ok(Some((endpoint.protocol, endpoint.address)));
        }
        Ok(None)
    }

    /// Ingest a remote announcement with validation
    pub async fn ingest_announcement(&self, announcement: ValidatorAnnouncement) -> Result<bool> {
        if self.validate_announcement(&announcement).await.is_err() {
            return Ok(false);
        }

        let mut cache = self.validator_cache.write().await;
        cache.insert(announcement.identity_id.clone(), announcement);
        Ok(true)
    }

    // Private helper methods

    /// Check if validator matches discovery filter
    fn matches_filter(
        &self,
        validator: &ValidatorAnnouncement,
        filter: &ValidatorDiscoveryFilter,
    ) -> bool {
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

    async fn validate_announcement(&self, announcement: &ValidatorAnnouncement) -> Result<()> {
        if announcement.commission_rate > 10_000 {
            return Err(anyhow!("Invalid commission rate"));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow!("System clock error: {}", e))?
            .as_secs();

        if announcement.last_updated > now + MAX_CLOCK_SKEW_SECS {
            return Err(anyhow!("Announcement timestamp too far in future"));
        }

        if now.saturating_sub(announcement.last_updated) > self.cache_ttl {
            return Err(anyhow!("Announcement is stale"));
        }

        if announcement.status == ValidatorStatus::Active && announcement.endpoints.is_empty() {
            return Err(anyhow!("Active announcement has no endpoints"));
        }

        if !announcement.verify_signature()? {
            return Err(anyhow!("Invalid announcement signature"));
        }

        Ok(())
    }
}

#[async_trait]
pub trait ValidatorDiscoveryTransport: Send + Sync {
    async fn publish_announcement(&self, announcement: ValidatorAnnouncement) -> Result<()>;
    async fn fetch_validator(&self, identity_id: &Hash) -> Result<Option<ValidatorAnnouncement>>;
    async fn fetch_validators(
        &self,
        filter: ValidatorDiscoveryFilter,
    ) -> Result<Vec<ValidatorAnnouncement>>;
}

/// In-memory transport for tests or single-process deployments.
pub struct InMemoryDiscoveryTransport {
    entries: Arc<RwLock<HashMap<Hash, ValidatorAnnouncement>>>,
}

impl InMemoryDiscoveryTransport {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ValidatorDiscoveryTransport for InMemoryDiscoveryTransport {
    async fn publish_announcement(&self, announcement: ValidatorAnnouncement) -> Result<()> {
        let mut entries = self.entries.write().await;
        entries.insert(announcement.identity_id.clone(), announcement);
        Ok(())
    }

    async fn fetch_validator(&self, identity_id: &Hash) -> Result<Option<ValidatorAnnouncement>> {
        let entries = self.entries.read().await;
        Ok(entries.get(identity_id).cloned())
    }

    async fn fetch_validators(
        &self,
        _filter: ValidatorDiscoveryFilter,
    ) -> Result<Vec<ValidatorAnnouncement>> {
        let entries = self.entries.read().await;
        Ok(entries.values().cloned().collect())
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
    use lib_crypto::keypair::generation::KeyPair;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn create_signed_announcement(
        identity_id: Hash,
        endpoints: Vec<ValidatorEndpoint>,
        status: ValidatorStatus,
    ) -> ValidatorAnnouncement {
        let keypair = KeyPair::generate().expect("keypair");
        ValidatorAnnouncement {
            identity_id,
            consensus_key: keypair.public_key.clone(),
            stake: 1_000_000,
            storage_provided: 10_000_000_000,
            commission_rate: 500,
            endpoints,
            status,
            last_updated: now_timestamp(),
            signature: Vec::new(),
        }
        .sign(&keypair)
        .expect("signed")
    }

    #[test]
    fn test_validator_discovery_filter() {
        let protocol = ValidatorDiscoveryProtocol::new(3600);

        let validator = create_signed_announcement(
            Hash::from_bytes(&[0u8; 32]),
            vec![ValidatorEndpoint {
                protocol: "quic".into(),
                address: "1.2.3.4:1234".into(),
                priority: 1,
            }],
            ValidatorStatus::Active,
        );

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

    #[tokio::test]
    async fn test_endpoint_priority_selection() {
        let protocol = ValidatorDiscoveryProtocol::new(3600);

        let validator = create_signed_announcement(
            Hash::from_bytes(&[1u8; 32]),
            vec![
                ValidatorEndpoint {
                    protocol: "ble".into(),
                    address: "ble://a".into(),
                    priority: 1,
                },
                ValidatorEndpoint {
                    protocol: "quic".into(),
                    address: "1.2.3.4:1234".into(),
                    priority: 10,
                },
            ],
            ValidatorStatus::Active,
        );

        protocol.announce_validator(validator).await.unwrap();

        // Test deterministic selection: higher priority (10) should win over (1)
        let ep = protocol
            .select_validator_endpoint(&Hash::from_bytes(&[1u8; 32]))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(ep.protocol, "quic");
        assert_eq!(ep.address, "1.2.3.4:1234");
        assert_eq!(ep.priority, 10);
    }

    #[tokio::test]
    async fn test_endpoint_selection_with_tie_breaker() {
        let protocol = ValidatorDiscoveryProtocol::new(3600);

        let validator = create_signed_announcement(
            Hash::from_bytes(&[2u8; 32]),
            vec![
                ValidatorEndpoint {
                    protocol: "tcp".into(),
                    address: "1.2.3.4:1234".into(),
                    priority: 5,
                },
                ValidatorEndpoint {
                    protocol: "quic".into(),
                    address: "1.2.3.4:4321".into(),
                    priority: 5,
                },
            ],
            ValidatorStatus::Active,
        );

        protocol.announce_validator(validator).await.unwrap();

        let ep = protocol
            .select_validator_endpoint(&Hash::from_bytes(&[2u8; 32]))
            .await
            .unwrap()
            .unwrap();

        // With equal priority, alphabetically first protocol wins ("quic" before "tcp")
        assert_eq!(ep.protocol, "quic");
    }

    #[tokio::test]
    async fn test_resolve_validator_route() {
        let protocol = ValidatorDiscoveryProtocol::new(3600);

        let validator = create_signed_announcement(
            Hash::from_bytes(&[3u8; 32]),
            vec![ValidatorEndpoint {
                protocol: "quic".into(),
                address: "1.2.3.4:1234".into(),
                priority: 10,
            }],
            ValidatorStatus::Active,
        );

        protocol.announce_validator(validator).await.unwrap();

        // Test routing resolution
        let route = protocol
            .resolve_validator_route(&Hash::from_bytes(&[3u8; 32]))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(route.0, "quic");
        assert_eq!(route.1, "1.2.3.4:1234");
    }

    #[tokio::test]
    async fn test_endpoint_selection_no_endpoints() {
        let protocol = ValidatorDiscoveryProtocol::new(3600);

        let validator = create_signed_announcement(
            Hash::from_bytes(&[4u8; 32]),
            vec![],
            ValidatorStatus::Offline,
        );

        protocol.announce_validator(validator).await.unwrap();

        let ep = protocol
            .select_validator_endpoint(&Hash::from_bytes(&[4u8; 32]))
            .await
            .unwrap();

        assert_eq!(ep, None);
    }

    #[tokio::test]
    async fn test_endpoint_selection_missing_validator() {
        let protocol = ValidatorDiscoveryProtocol::new(3600);

        let ep = protocol
            .select_validator_endpoint(&Hash::from_bytes(&[255u8; 32]))
            .await
            .unwrap();

        assert_eq!(ep, None);
    }
}
