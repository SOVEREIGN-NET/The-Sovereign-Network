//! WiFi Direct Group Manager
//!
//! Handles:
//! - P2P Group Owner (GO) negotiation
//! - Group formation and creation
//! - Joining existing groups
//! - Persistent group management
//! - Device capability scoring

pub mod negotiation;
pub mod formation;
pub mod joining;

pub use negotiation::GoNegotiator;
pub use formation::GroupFormation;
pub use joining::GroupJoiner;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use crate::protocols::wifi_direct::wifi_direct::{
    P2PGoNegotiation, WiFiDirectConnection, PersistentGroup,
};

/// Group manager handling all WiFi Direct group operations
pub struct GroupManager {
    negotiator: Arc<GoNegotiator>,
    formation: Arc<GroupFormation>,
    joiner: Arc<GroupJoiner>,
    persistent_groups: Arc<RwLock<HashMap<String, PersistentGroup>>>,
}

impl GroupManager {
    /// Create a new group manager
    pub fn new(
        node_id: [u8; 32],
        persistent_groups: Arc<RwLock<HashMap<String, PersistentGroup>>>,
    ) -> Result<Self> {
        debug!("Initializing WiFi Direct Group Manager");

        Ok(Self {
            negotiator: Arc::new(GoNegotiator::new(node_id)?),
            formation: Arc::new(GroupFormation::new()?),
            joiner: Arc::new(GroupJoiner::new()?),
            persistent_groups,
        })
    }

    /// Perform GO negotiation with a peer
    pub async fn negotiate_group_owner(
        &self,
        peer_address: &str,
        peer_negotiation: &P2PGoNegotiation,
    ) -> Result<bool> {
        self.negotiator
            .perform_negotiation(peer_address, peer_negotiation)
            .await
    }

    /// Create a P2P group (as Group Owner)
    pub async fn create_group(&self) -> Result<()> {
        self.formation.create_group().await
    }

    /// Join an existing P2P group
    pub async fn join_group(&self, ssid: &str, passphrase: &str) -> Result<()> {
        self.joiner.join_group(ssid, passphrase).await
    }

    /// Join existing P2P groups
    pub async fn join_existing_groups(&self) -> Result<()> {
        self.joiner.join_existing_groups().await
    }

    /// Scan for available P2P groups
    pub async fn scan_for_groups(&self) -> Result<Vec<String>> {
        self.joiner.scan_for_groups().await
    }

    /// Get P2P Group Owner negotiation parameters
    pub fn get_go_negotiation(&self) -> P2PGoNegotiation {
        self.negotiator.get_default_negotiation()
    }

    /// Add a persistent group
    pub async fn add_persistent_group(&self, group: PersistentGroup) -> Result<()> {
        debug!(group_id = &group.group_id, "Adding persistent group");
        self.persistent_groups
            .write()
            .await
            .insert(group.group_id.clone(), group);
        Ok(())
    }

    /// Get persistent groups
    pub async fn get_persistent_groups(&self) -> Vec<PersistentGroup> {
        self.persistent_groups
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }
}
