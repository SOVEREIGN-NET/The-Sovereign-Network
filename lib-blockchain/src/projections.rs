//! Rebuildable hot-state projections for restart hydration.
//!
//! These tables mirror state that is fully derivable from committed block
//! history but too expensive to rebuild on every restart. Projection metadata
//! pins the table set to a concrete chain tip; startup may hydrate from the
//! projections only when that tip matches the block store tip.

use serde::{Deserialize, Serialize};

use crate::blockchain::{DaoRegistryIndexEntry, GatewayInfo, PouwMintRecord, ValidatorInfo};
use crate::storage::table::Table;

pub const HOT_STATE_PROJECTION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStateProjectionMeta {
    pub version: u32,
    pub height: u64,
    pub block_hash: [u8; 32],
    pub completed_at_unix: u64,
    // Reviewer #2692/L29: fixed-width counts so the bincode payload is
    // architecture-independent. `usize` round-trips differently between
    // 32-bit and 64-bit targets and can fail deserialization if a count
    // ever exceeds the local `usize` width.
    pub validators: u64,
    pub gateways: u64,
    pub domains: u64,
    pub credentials: u64,
    pub employment_contracts: u64,
    pub dao_entries: u64,
    pub pouw_mints: u64,
    pub contract_blocks: u64,
}

impl HotStateProjectionMeta {
    pub fn is_current_for(&self, height: u64, block_hash: [u8; 32]) -> bool {
        self.version == HOT_STATE_PROJECTION_VERSION
            && self.height == height
            && self.block_hash == block_hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorProjectionRecord {
    pub info: ValidatorInfo,
    pub committed_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProjectionRecord {
    pub info: GatewayInfo,
    pub committed_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainProjectionRecord {
    pub record: crate::transaction::OnChainDomainRecord,
    pub committed_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProjectionRecord {
    pub credential: crate::transaction::UserCredential,
    pub committed_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidUsernameProjectionRecord {
    pub username: String,
    pub committed_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentProjectionRecord {
    pub contract: crate::contracts::employment::EmploymentContract,
    pub committed_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoRegistryProjectionRecord {
    pub entry: DaoRegistryIndexEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PouwMintProjectionRecord {
    pub recipient: [u8; 32],
    pub mint: PouwMintRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractBlockProjectionRecord {
    pub contract_id: [u8; 32],
    pub block_height: u64,
}

pub struct HotStateProjectionMetaTable;
impl Table for HotStateProjectionMetaTable {
    const NAME: &'static str = "projection_hot_state_meta";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = str;
    type Value = HotStateProjectionMeta;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
}

pub struct ValidatorProjectionTable;
impl Table for ValidatorProjectionTable {
    const NAME: &'static str = "projection_validators";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = str;
    type Value = ValidatorProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
}

pub struct GatewayProjectionTable;
impl Table for GatewayProjectionTable {
    const NAME: &'static str = "projection_gateways";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = str;
    type Value = GatewayProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
}

pub struct DomainProjectionTable;
impl Table for DomainProjectionTable {
    const NAME: &'static str = "projection_domains";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = str;
    type Value = DomainProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
}

pub struct CredentialProjectionTable;
impl Table for CredentialProjectionTable {
    const NAME: &'static str = "projection_credentials";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = str;
    type Value = CredentialProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
}

pub struct DidUsernameProjectionTable;
impl Table for DidUsernameProjectionTable {
    const NAME: &'static str = "projection_did_usernames";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = str;
    type Value = DidUsernameProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
}

pub struct EmploymentProjectionTable;
impl Table for EmploymentProjectionTable {
    const NAME: &'static str = "projection_employment";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = str;
    type Value = EmploymentProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
}

pub struct DaoRegistryProjectionTable;
impl Table for DaoRegistryProjectionTable {
    const NAME: &'static str = "projection_dao_registry";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = [u8; 32];
    type Value = DaoRegistryProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.to_vec()
    }
}

pub struct PouwMintProjectionTable;
impl Table for PouwMintProjectionTable {
    const NAME: &'static str = "projection_pouw_mints";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = [u8; 64];
    type Value = PouwMintProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.to_vec()
    }
}

pub struct ContractBlockProjectionTable;
impl Table for ContractBlockProjectionTable {
    const NAME: &'static str = "projection_contract_blocks";
    const VERSION: u32 = HOT_STATE_PROJECTION_VERSION;
    type Key = [u8; 32];
    type Value = ContractBlockProjectionRecord;
    fn encode_key(key: &Self::Key) -> Vec<u8> {
        key.to_vec()
    }
}

pub fn pouw_mint_key(recipient: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(recipient);
    key[32..].copy_from_slice(tx_hash);
    key
}
