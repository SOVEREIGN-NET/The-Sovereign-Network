//! Scoped identity views for access-controlled identity retrieval.
//!
//! These structs represent the ONLY shapes that may be returned to callers.
//! No raw `ZhtpIdentity` objects are exposed through the view APIs.

use serde::{Deserialize, Serialize};

use crate::types::{AccessLevel, IdentityId, IdentityType, NodeId};
use lib_crypto::PublicKey;

/// Minimal public-safe identity view.
///
/// Contains only fields that are safe to expose to any unauthenticated or
/// external caller. All cryptographic secrets, wallet references, and graph
/// edges are excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentityView {
    pub id: IdentityId,
    pub did: String,
    pub identity_type: IdentityType,
    pub public_key: PublicKey,
    pub node_id: NodeId,
    pub reputation: u64,
    pub access_level: AccessLevel,
    pub citizenship_verified: bool,
    pub created_at: u64,
    pub last_active: u64,
    pub dao_voting_power: u64,
    pub dao_member_id: String,
}

/// Device-scoped view of an owner identity.
///
/// Devices operating on behalf of a user receive this view. It extends the
/// public view with limited wallet and node graph information required for
/// reward routing and mesh participation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceOwnerView {
    #[serde(flatten)]
    pub core: PublicIdentityView,
    /// The wallet designated for routing/mining rewards.
    pub reward_wallet_id: Option<crate::wallets::WalletId>,
    /// All device node IDs registered to this owner.
    pub device_node_ids: Vec<NodeId>,
}

/// Council investigation-scoped view.
///
/// Council members receive this view when performing fraud investigation or
/// governance oversight. It includes public core data plus governance metadata
/// and summarized graph information, but NEVER private ZK witness material or
/// raw seed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilView {
    #[serde(flatten)]
    pub core: PublicIdentityView,
    pub age: Option<u64>,
    pub jurisdiction: Option<String>,
    /// Number of nodes controlled by this identity.
    pub controlled_node_count: usize,
    /// Number of wallets owned by this identity.
    pub owned_wallet_count: usize,
    /// Credential types held (not the private proof data).
    pub credential_types: Vec<crate::types::CredentialType>,
}

/// Full identity view.
///
/// This is returned only when the principal is the subject identity itself,
/// a verified emergency actor, or an internal system process. It contains
/// the same fields as `ZhtpIdentity` but is a distinct type to preserve the
/// compile-time invariant that only authorized code paths can construct it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullIdentityView {
    #[serde(flatten)]
    pub core: PublicIdentityView,
    pub age: Option<u64>,
    pub jurisdiction: Option<String>,
    pub metadata: std::collections::HashMap<String, String>,
    pub device_node_ids: std::collections::HashMap<String, NodeId>,
    pub owner_identity_id: Option<IdentityId>,
    pub reward_wallet_id: Option<crate::wallets::WalletId>,
    pub credentials: std::collections::HashMap<crate::types::CredentialType, crate::credentials::ZkCredential>,
    pub attestations: Vec<crate::credentials::IdentityAttestation>,
    // NOTE: private_key, zk_identity_secret, wallet_master_seed, encrypted_master_seed,
    // password_hash, master_seed_phrase, and recovery_keys are intentionally EXCLUDED.
    // They must never be serialized into a view.
}

/// Unified identity view enum.
///
/// All identity queries that cross a trust boundary must return this enum.
/// The variant selected is determined by the access policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "view_type", rename_all = "snake_case")]
pub enum IdentityView {
    Public(PublicIdentityView),
    DeviceOwner(DeviceOwnerView),
    Council(CouncilView),
    Full(FullIdentityView),
}
