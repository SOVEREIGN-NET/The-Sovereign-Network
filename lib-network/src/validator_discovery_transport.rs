//! Mesh-based Validator Discovery Transport
//!
//! Implements the `ValidatorDiscoveryTransport` trait using mesh network DHT operations
//! for validator announcement storage and retrieval.
//!
//! # Architecture
//!
//! This transport uses:
//! - **DHT Storage**: For persistent validator announcement storage across the network
//! - **Mesh Broadcast**: For propagating new announcements to peers
//! - **Local Cache**: For fast lookups (managed by ValidatorDiscoveryProtocol)
//!
//! # Key Format
//!
//! Validator announcements are stored in DHT with key: `validator:{identity_hash_hex}`
//! This allows efficient lookup by validator identity.
//!
//! # Gossip Protocol
//!
//! When a validator announces:
//! 1. Store in local DHT
//! 2. Broadcast to connected peers via mesh
//! 3. Peers validate and re-broadcast (gossip propagation)

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use lib_consensus::validators::validator_discovery::{
    ValidatorAnnouncement, ValidatorDiscoveryFilter, ValidatorDiscoveryTransport, ValidatorStatus,
};
use lib_crypto::Hash;

use crate::peer_registry::SharedPeerRegistry;
use crate::types::mesh_message::ZhtpMeshMessage;

/// DHT key prefix for validator announcements
const VALIDATOR_KEY_PREFIX: &str = "validator:";

/// TTL for DHT entries (24 hours in seconds)
const DHT_ENTRY_TTL: u64 = 86400;

/// Mesh-based transport for validator discovery
///
/// Uses DHT operations over mesh network for storing and retrieving
/// validator announcements. Implements gossip-style propagation.
///
/// # Usage
///
/// This transport is designed to be wired into the ZHTP application layer
/// where the full mesh router is available. Create with `new()` and pass
/// to `ValidatorDiscoveryProtocol::with_transport()`.
pub struct MeshValidatorDiscoveryTransport {
    /// Peer registry for finding peers to gossip to
    peer_registry: SharedPeerRegistry,

    /// Local identity for signing DHT operations
    local_identity: lib_crypto::PublicKey,

    /// Local announcement cache (for fast lookups before DHT query)
    local_cache: Arc<RwLock<HashMap<Hash, ValidatorAnnouncement>>>,

    /// Cache TTL in seconds
    cache_ttl: u64,

    /// Optional sender for outbound DHT messages
    /// This is set by the application layer when wiring up the transport
    dht_message_sender: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<(lib_crypto::PublicKey, ZhtpMeshMessage)>>>>,
}

impl MeshValidatorDiscoveryTransport {
    /// Create a new mesh validator discovery transport
    ///
    /// # Arguments
    /// * `peer_registry` - Registry of connected peers
    /// * `local_identity` - This node's public key for DHT operations
    pub fn new(
        peer_registry: SharedPeerRegistry,
        local_identity: lib_crypto::PublicKey,
    ) -> Self {
        Self {
            peer_registry,
            local_identity,
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: DHT_ENTRY_TTL,
            dht_message_sender: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the message sender for outbound DHT messages
    ///
    /// This allows the application layer to wire up message delivery
    /// without creating circular dependencies.
    pub async fn set_message_sender(
        &self,
        sender: tokio::sync::mpsc::UnboundedSender<(lib_crypto::PublicKey, ZhtpMeshMessage)>,
    ) {
        *self.dht_message_sender.write().await = Some(sender);
    }

    /// Create DHT key from validator identity
    fn make_dht_key(identity_id: &Hash) -> Vec<u8> {
        format!("{}{}", VALIDATOR_KEY_PREFIX, hex::encode(identity_id.as_bytes())).into_bytes()
    }

    /// Extract identity hash from DHT key
    fn parse_dht_key(key: &[u8]) -> Option<Hash> {
        let key_str = std::str::from_utf8(key).ok()?;
        if !key_str.starts_with(VALIDATOR_KEY_PREFIX) {
            return None;
        }
        let hex_str = &key_str[VALIDATOR_KEY_PREFIX.len()..];
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Hash(arr))
    }

    /// Check if this is a validator announcement DHT key
    pub fn is_validator_key(key: &[u8]) -> bool {
        key.starts_with(VALIDATOR_KEY_PREFIX.as_bytes())
    }

    /// Store announcement in local cache
    async fn cache_announcement(&self, announcement: &ValidatorAnnouncement) {
        let mut cache = self.local_cache.write().await;
        cache.insert(announcement.identity_id.clone(), announcement.clone());
    }

    /// Get announcement from local cache if fresh
    async fn get_cached(&self, identity_id: &Hash) -> Option<ValidatorAnnouncement> {
        let cache = self.local_cache.read().await;
        if let Some(announcement) = cache.get(identity_id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now - announcement.last_updated < self.cache_ttl {
                return Some(announcement.clone());
            }
        }
        None
    }

    /// Send a message to a peer (uses the wired sender)
    async fn send_to_peer(&self, peer_id: &lib_crypto::PublicKey, message: ZhtpMeshMessage) -> Result<()> {
        let sender = self.dht_message_sender.read().await;
        let sender = sender.as_ref()
            .ok_or_else(|| anyhow!("Message sender not configured - call set_message_sender() first"))?;

        sender.send((peer_id.clone(), message))
            .map_err(|e| anyhow!("Failed to queue message: {}", e))?;

        Ok(())
    }

    /// Broadcast announcement to connected peers via gossip
    async fn gossip_announcement(&self, announcement: &ValidatorAnnouncement) -> Result<()> {
        let key = Self::make_dht_key(&announcement.identity_id);
        let value = bincode::serialize(announcement)
            .map_err(|e| anyhow!("Failed to serialize announcement: {}", e))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create DHT store message
        let message = ZhtpMeshMessage::DhtStore {
            requester: self.local_identity.clone(),
            request_id: timestamp, // Use timestamp as simple request ID
            key,
            value,
            ttl: DHT_ENTRY_TTL,
            signature: Vec::new(), // TODO: Sign with node key when needed
        };

        // Get connected peers to gossip to (authenticated peers with active connection)
        let peers = {
            let registry = self.peer_registry.read().await;
            registry
                .all_peers()
                .filter(|p| p.authenticated && p.connection_metrics.connected_at > 0)
                .map(|p| p.peer_id.public_key().clone())
                .collect::<Vec<_>>()
        };

        if peers.is_empty() {
            debug!("No connected peers for validator announcement gossip");
            return Ok(());
        }

        info!(
            "Gossiping validator announcement {} to {} peers",
            announcement.identity_id,
            peers.len()
        );

        // Send to each peer via message sender
        for peer_pubkey in peers {
            if let Err(e) = self.send_to_peer(&peer_pubkey, message.clone()).await {
                debug!("Failed to gossip to peer: {}", e);
                // Continue gossiping to other peers
            }
        }

        Ok(())
    }

    /// Query DHT for validator announcement
    async fn query_dht(&self, identity_id: &Hash) -> Result<Option<ValidatorAnnouncement>> {
        let key = Self::make_dht_key(identity_id);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create DHT find value message
        let message = ZhtpMeshMessage::DhtFindValue {
            requester: self.local_identity.clone(),
            request_id: timestamp,
            key: key.clone(),
            max_hops: 8,
        };

        // Get peers to query (authenticated peers with active connection)
        let peers = {
            let registry = self.peer_registry.read().await;
            registry
                .all_peers()
                .filter(|p| p.authenticated && p.connection_metrics.connected_at > 0)
                .take(3) // Query up to 3 peers
                .map(|p| p.peer_id.public_key().clone())
                .collect::<Vec<_>>()
        };

        if peers.is_empty() {
            debug!("No connected peers for DHT query");
            return Ok(None);
        }

        // For now, just send the query and return None
        // In a full implementation, we'd wait for DhtFindValueResponse
        for peer_pubkey in peers {
            if let Err(e) = self.send_to_peer(&peer_pubkey, message.clone()).await {
                debug!("Failed to query peer: {}", e);
            }
        }

        // TODO: Implement response handling with request/response correlation
        // For now, rely on cache population from gossip
        Ok(None)
    }

    /// Handle incoming DHT store message (called by message handler)
    pub async fn handle_dht_store(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        _ttl: u64,
    ) -> Result<bool> {
        // Check if this is a validator announcement
        if !key.starts_with(VALIDATOR_KEY_PREFIX.as_bytes()) {
            return Ok(false);
        }

        // Deserialize announcement
        let announcement: ValidatorAnnouncement = bincode::deserialize(&value)
            .map_err(|e| anyhow!("Invalid validator announcement: {}", e))?;

        // Verify signature
        if !announcement.verify_signature()? {
            warn!(
                "Invalid signature on validator announcement {}",
                announcement.identity_id
            );
            return Ok(false);
        }

        // Cache locally
        self.cache_announcement(&announcement).await;

        info!(
            "Stored validator announcement {} from DHT gossip",
            announcement.identity_id
        );

        Ok(true)
    }

    /// Handle incoming DHT find value response (called by message handler)
    pub async fn handle_dht_find_value_response(
        &self,
        _request_id: u64,
        found: bool,
        value: Option<Vec<u8>>,
    ) -> Result<()> {
        if !found {
            return Ok(());
        }

        if let Some(data) = value {
            // Try to deserialize as validator announcement
            if let Ok(announcement) = bincode::deserialize::<ValidatorAnnouncement>(&data) {
                if announcement.verify_signature().unwrap_or(false) {
                    self.cache_announcement(&announcement).await;
                    debug!(
                        "Cached validator announcement {} from DHT response",
                        announcement.identity_id
                    );
                }
            }
        }

        Ok(())
    }

    /// Get all cached validators (for discover_validators queries)
    async fn get_all_cached(&self) -> Vec<ValidatorAnnouncement> {
        let cache = self.local_cache.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        cache
            .values()
            .filter(|a| now - a.last_updated < self.cache_ttl)
            .cloned()
            .collect()
    }

    /// Check if announcement matches filter
    fn matches_filter(announcement: &ValidatorAnnouncement, filter: &ValidatorDiscoveryFilter) -> bool {
        if let Some(min_stake) = filter.min_stake {
            if announcement.stake < min_stake {
                return false;
            }
        }

        if let Some(min_storage) = filter.min_storage {
            if announcement.storage_provided < min_storage {
                return false;
            }
        }

        if let Some(max_commission) = filter.max_commission {
            if announcement.commission_rate > max_commission {
                return false;
            }
        }

        if let Some(required_status) = filter.status {
            if announcement.status != required_status {
                return false;
            }
        }

        true
    }
}

#[async_trait]
impl ValidatorDiscoveryTransport for MeshValidatorDiscoveryTransport {
    /// Publish validator announcement to the network
    ///
    /// Stores in local cache and gossips to connected peers via DHT store messages.
    async fn publish_announcement(&self, announcement: ValidatorAnnouncement) -> Result<()> {
        info!(
            "Publishing validator announcement {} via mesh gossip",
            announcement.identity_id
        );

        // Verify signature before publishing
        if !announcement.verify_signature()? {
            return Err(anyhow!("Invalid signature on announcement"));
        }

        // Store in local cache
        self.cache_announcement(&announcement).await;

        // Gossip to connected peers
        self.gossip_announcement(&announcement).await?;

        Ok(())
    }

    /// Fetch a specific validator's announcement
    ///
    /// Checks local cache first, then queries DHT if not found.
    async fn fetch_validator(&self, identity_id: &Hash) -> Result<Option<ValidatorAnnouncement>> {
        debug!("Fetching validator {} from mesh network", identity_id);

        // Check local cache first
        if let Some(cached) = self.get_cached(identity_id).await {
            debug!("Found validator {} in local cache", identity_id);
            return Ok(Some(cached));
        }

        // Query DHT
        self.query_dht(identity_id).await
    }

    /// Fetch validators matching filter
    ///
    /// Returns validators from local cache matching the filter criteria.
    /// In a full implementation, would also query DHT for additional validators.
    async fn fetch_validators(
        &self,
        filter: ValidatorDiscoveryFilter,
    ) -> Result<Vec<ValidatorAnnouncement>> {
        debug!("Fetching validators with filter: {:?}", filter);

        // Get all cached validators
        let all = self.get_all_cached().await;

        // Apply filter
        let mut results: Vec<ValidatorAnnouncement> = all
            .into_iter()
            .filter(|a| Self::matches_filter(a, &filter))
            .collect();

        // Sort by stake (descending)
        results.sort_by(|a, b| b.stake.cmp(&a.stake));

        // Apply limit
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        info!("Found {} validators matching filter", results.len());
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_key_format() {
        let identity = Hash::from_bytes(&[1u8; 32]);
        let key = MeshValidatorDiscoveryTransport::make_dht_key(&identity);
        let key_str = String::from_utf8(key.clone()).unwrap();

        assert!(key_str.starts_with("validator:"));
        assert_eq!(key_str.len(), 10 + 64); // "validator:" + 64 hex chars

        // Parse back
        let parsed = MeshValidatorDiscoveryTransport::parse_dht_key(&key).unwrap();
        assert_eq!(parsed, identity);
    }

    #[test]
    fn test_parse_invalid_key() {
        let invalid = b"invalid:key";
        assert!(MeshValidatorDiscoveryTransport::parse_dht_key(invalid).is_none());

        let wrong_prefix = b"other:0101010101010101010101010101010101010101010101010101010101010101";
        assert!(MeshValidatorDiscoveryTransport::parse_dht_key(wrong_prefix).is_none());
    }

    #[test]
    fn test_filter_matching() {
        use lib_consensus::validators::validator_discovery::{ValidatorEndpoint, ValidatorStatus};
        use lib_crypto::PublicKey;

        let announcement = ValidatorAnnouncement {
            identity_id: Hash::from_bytes(&[1u8; 32]),
            consensus_key: PublicKey::new(vec![1, 2, 3]),
            stake: 1_000_000,
            storage_provided: 10_000_000_000,
            commission_rate: 500,
            endpoints: vec![ValidatorEndpoint {
                protocol: "quic".into(),
                address: "1.2.3.4:1234".into(),
                priority: 1,
            }],
            status: ValidatorStatus::Active,
            last_updated: 0,
            signature: Vec::new(),
        };

        // Test min_stake filter
        let filter = ValidatorDiscoveryFilter {
            min_stake: Some(500_000),
            ..Default::default()
        };
        assert!(MeshValidatorDiscoveryTransport::matches_filter(&announcement, &filter));

        let filter = ValidatorDiscoveryFilter {
            min_stake: Some(2_000_000),
            ..Default::default()
        };
        assert!(!MeshValidatorDiscoveryTransport::matches_filter(&announcement, &filter));

        // Test status filter
        let filter = ValidatorDiscoveryFilter {
            status: Some(ValidatorStatus::Active),
            ..Default::default()
        };
        assert!(MeshValidatorDiscoveryTransport::matches_filter(&announcement, &filter));

        let filter = ValidatorDiscoveryFilter {
            status: Some(ValidatorStatus::Offline),
            ..Default::default()
        };
        assert!(!MeshValidatorDiscoveryTransport::matches_filter(&announcement, &filter));

        // Test combined filters
        let filter = ValidatorDiscoveryFilter {
            min_stake: Some(500_000),
            max_commission: Some(1000),
            status: Some(ValidatorStatus::Active),
            ..Default::default()
        };
        assert!(MeshValidatorDiscoveryTransport::matches_filter(&announcement, &filter));
    }
}
