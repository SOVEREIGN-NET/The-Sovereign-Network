//! Sovereign Asset discovery API (ADR: docs/arch/sovereign-asset.md, SA-2).

use anyhow::Result;
use lib_blockchain::contracts::sovereign_asset::{
    AssetAuthority, AssetIdSource, GovernanceModuleState, GovernanceVerifierState,
    RewardsModuleState, SovereignAsset, SupplyMode,
};
use lib_blockchain::transaction::asset_tx::AssetLaunchPayloadV1;
use lib_blockchain::transaction::{hash_transaction, Transaction};
use lib_blockchain::types::transaction_type::TransactionType;
use lib_blockchain::{Blockchain, BlockchainQuery};
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use serde::Deserialize;
use lib_protocols::zhtp::ZhtpRequestHandler;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::api::handlers::token::u128_as_string;

/// Stable deep-link scheme for sovereign assets (`asset_id` = launch tx hash).
pub fn asset_share_link(asset_id: &[u8; 32]) -> String {
    format!("zhtp://asset/{}", hex::encode(asset_id))
}

fn create_json_response(data: serde_json::Value) -> Result<ZhtpResponse> {
    let json_response = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

fn create_error_response(status: ZhtpStatus, message: String) -> ZhtpResponse {
    ZhtpResponse::error(status, message)
}

/// POST /api/v1/assets/launch — submit a signed `AssetLaunch` tx (M1 CreateDaoTab path).
#[derive(Debug, Deserialize)]
struct LaunchAssetRequest {
    pub signed_tx: String,
    #[serde(default)]
    pub enforce_dao_launch_constraints: bool,
}

#[derive(Debug, Serialize)]
struct AssetListItem {
    asset_id: String,
    id_source: String,
    name: String,
    symbol: String,
    decimals: u8,
    #[serde(serialize_with = "u128_as_string::serialize")]
    total_supply: u128,
    supply_mode: String,
    module_bitmask: u8,
    launched_at_height: Option<u64>,
    manifest_cid: Option<String>,
    manifest_hash: Option<String>,
    share_link: String,
}

#[derive(Debug, Serialize)]
struct AssetDetailResponse {
    asset_id: String,
    id_source: String,
    name: String,
    symbol: String,
    decimals: u8,
    #[serde(serialize_with = "u128_as_string::serialize")]
    total_supply: u128,
    #[serde(serialize_with = "u128_as_string::serialize")]
    max_supply: u128,
    supply_mode: String,
    creator_key_id: String,
    creator_did: Option<String>,
    treasury_key_id: Option<String>,
    launched_at_height: Option<u64>,
    schema_version: u16,
    module_bitmask: u8,
    manifest_cid: Option<String>,
    manifest_hash: Option<String>,
    curve: Option<serde_json::Value>,
    rewards: Option<serde_json::Value>,
    governance: Option<serde_json::Value>,
    interface: serde_json::Value,
    share_link: String,
    manifest_resolved: bool,
    manifest: Option<serde_json::Value>,
    dao_registry: Option<serde_json::Value>,
    governance_status: serde_json::Value,
}

fn id_source_label(s: AssetIdSource) -> &'static str {
    match s {
        AssetIdSource::LaunchTx => "launch_tx",
        AssetIdSource::LegacyTokenId => "legacy_token_id",
    }
}

fn supply_mode_label(s: SupplyMode) -> &'static str {
    match s {
        SupplyMode::Fixed => "fixed",
        SupplyMode::Elastic => "elastic",
    }
}

fn interface_for_asset(asset: &SovereignAsset, manifest: Option<&serde_json::Value>) -> serde_json::Value {
    if let Some(iface) = manifest.and_then(|m| m.get("interface")) {
        return iface.clone();
    }
    asset_interface(asset)
}

fn asset_interface(asset: &SovereignAsset) -> serde_json::Value {
    let mut tx_kinds: Vec<&str> = vec!["TokenTransfer"];
    if asset.module_flags.has_curve() {
        tx_kinds.push("BondingCurveBuy");
        tx_kinds.push("BondingCurveSell");
    }
    if asset.module_flags.has_rewards() {
        tx_kinds.push("RewardsClaim");
    }
    if asset.id_source == AssetIdSource::LaunchTx {
        tx_kinds.push("AssetTransfer");
    }
    json!({
        "version": if asset.id_source == AssetIdSource::LaunchTx { "1.0.0" } else { "0.1.0" },
        "tx_kinds": tx_kinds,
    })
}

fn map_assets_error(err: anyhow::Error) -> ZhtpResponse {
    let msg = err.to_string();
    if msg.contains("Asset not found") {
        create_error_response(ZhtpStatus::NotFound, msg)
    } else if msg.contains("not implemented until SA-3") {
        create_error_response(ZhtpStatus::NotImplemented, msg)
    } else if msg.contains("Invalid") || msg.contains("must be") {
        create_error_response(ZhtpStatus::BadRequest, msg)
    } else if msg.contains("balance lookup failed") {
        create_error_response(ZhtpStatus::InternalServerError, msg)
    } else {
        create_error_response(ZhtpStatus::InternalServerError, msg)
    }
}

fn to_list_item(asset: &SovereignAsset) -> AssetListItem {
    AssetListItem {
        asset_id: hex::encode(asset.asset_id),
        id_source: id_source_label(asset.id_source).to_string(),
        name: asset.name.clone(),
        symbol: asset.symbol.clone(),
        decimals: asset.decimals,
        total_supply: asset.total_supply,
        supply_mode: supply_mode_label(asset.supply_mode).to_string(),
        module_bitmask: asset.module_bitmask(),
        launched_at_height: asset.launched_at_height,
        manifest_cid: asset.manifest_cid.map(hex::encode),
        manifest_hash: asset.manifest_hash.map(hex::encode),
        share_link: asset_share_link(&asset.asset_id),
    }
}

fn dao_registry_linkage(
    bc: &Blockchain,
    asset_id: &[u8; 32],
) -> Option<serde_json::Value> {
    bc.get_dao_registry_entry(asset_id).map(|entry| {
        json!({
            "dao_id": hex::encode(entry.dao_id),
            "class": entry.class,
            "metadata_hash": hex::encode(entry.metadata_hash),
            "created_at": entry.created_at,
        })
    })
}

async fn fetch_manifest_bytes(cid: &[u8; 32]) -> Option<Vec<u8>> {
    if *cid == [0u8; 32] {
        return None;
    }
    let key = hex::encode(cid);
    let client = crate::runtime::shared_dht::get_dht_client().await.ok()?;
    let mut dht = client.write().await;
    dht.fetch_content(&key).await.ok().flatten()
}

fn manifest_hash_matches(bytes: &[u8], expected: &[u8; 32]) -> bool {
    lib_crypto::hash_blake3(bytes) == *expected
}

async fn resolve_asset_manifest(asset: &SovereignAsset) -> (Option<serde_json::Value>, bool) {
    let (Some(cid), Some(expected_hash)) = (asset.manifest_cid, asset.manifest_hash) else {
        return (None, false);
    };
    let Some(bytes) = fetch_manifest_bytes(&cid).await else {
        return (None, false);
    };
    if !manifest_hash_matches(&bytes, &expected_hash) {
        warn!(
            asset_id = %hex::encode(asset.asset_id),
            "manifest bytes do not match on-chain manifest_hash"
        );
        return (None, false);
    }
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(manifest) => (Some(manifest), true),
        Err(e) => {
            warn!(
                asset_id = %hex::encode(asset.asset_id),
                "manifest JSON invalid: {e}"
            );
            (None, false)
        }
    }
}

fn governance_status_detail(
    asset: &SovereignAsset,
    gov_state: Option<&GovernanceModuleState>,
    rewards_state: Option<&RewardsModuleState>,
    tip_height: u64,
) -> serde_json::Value {
    let authority = match &asset.authority {
        AssetAuthority::Creator { key_id } => json!({
            "kind": "creator",
            "key_id": hex::encode(key_id),
        }),
        AssetAuthority::Governance { module_ref } => json!({
            "kind": "governance",
            "module_ref": hex::encode(module_ref),
        }),
    };

    let verifier = gov_state.and_then(|g| g.verifier.as_ref()).map(|v| match v {
        GovernanceVerifierState::Single { signer_key_id } => json!({
            "kind": "single",
            "signers": [hex::encode(signer_key_id)],
            "threshold": 1,
        }),
        GovernanceVerifierState::Multisig { signers, threshold } => json!({
            "kind": "multisig",
            "signers": signers.iter().map(hex::encode).collect::<Vec<_>>(),
            "threshold": threshold,
        }),
    });

    let pending_authority_transfer = gov_state
        .and_then(|g| g.pending_transfer.as_ref())
        .map(|p| {
            let blocks_remaining = p.effective_height.saturating_sub(tip_height);
            json!({
                "new_verifier": match &p.new_verifier {
                    GovernanceVerifierState::Single { signer_key_id } => json!({
                        "kind": "single",
                        "signers": [hex::encode(signer_key_id)],
                        "threshold": 1,
                    }),
                    GovernanceVerifierState::Multisig { signers, threshold } => json!({
                        "kind": "multisig",
                        "signers": signers.iter().map(hex::encode).collect::<Vec<_>>(),
                        "threshold": threshold,
                    }),
                },
                "effective_height": p.effective_height,
                "blocks_remaining": blocks_remaining,
            })
        });

    let pending_rewards_policy = rewards_state
        .and_then(|r| r.pending_policy.as_ref())
        .map(|p| {
            let blocks_remaining = p.effective_height.saturating_sub(tip_height);
            json!({
                "policy_cid": hex::encode(p.policy_cid),
                "policy_hash": hex::encode(p.policy_hash),
                "effective_height": p.effective_height,
                "blocks_remaining": blocks_remaining,
            })
        });

    json!({
        "authority": authority,
        "verifier": verifier,
        "pending_authority_transfer": pending_authority_transfer,
        "pending_rewards_policy": pending_rewards_policy,
        "chain_tip_height": tip_height,
    })
}

fn rewards_detail(
    asset: &SovereignAsset,
    state: Option<&RewardsModuleState>,
) -> Option<serde_json::Value> {
    if !asset.module_flags.has_rewards() {
        return None;
    }
    let header = asset.rewards.as_ref();
    Some(json!({
        "spend_delegate_key_id": state
            .map(|s| hex::encode(s.spend_delegate_key_id))
            .or_else(|| header.and_then(|h| h.spend_delegate_key_id.map(hex::encode))),
        "policy_cid": state.map(|s| hex::encode(s.policy_cid)),
        "policy_hash": state.map(|s| hex::encode(s.policy_hash)),
        "nonce": state.map(|s| s.nonce),
    }))
}

fn to_detail(
    asset: &SovereignAsset,
    rewards_state: Option<&RewardsModuleState>,
    gov_state: Option<&GovernanceModuleState>,
    tip_height: u64,
    manifest: Option<&serde_json::Value>,
    manifest_resolved: bool,
    dao_registry: Option<serde_json::Value>,
) -> AssetDetailResponse {
    AssetDetailResponse {
        asset_id: hex::encode(asset.asset_id),
        id_source: id_source_label(asset.id_source).to_string(),
        name: asset.name.clone(),
        symbol: asset.symbol.clone(),
        decimals: asset.decimals,
        total_supply: asset.total_supply,
        max_supply: asset.max_supply,
        supply_mode: supply_mode_label(asset.supply_mode).to_string(),
        creator_key_id: hex::encode(asset.creator_key_id),
        creator_did: asset.creator_did.clone(),
        treasury_key_id: asset.treasury_key_id.map(hex::encode),
        launched_at_height: asset.launched_at_height,
        schema_version: asset.schema_version,
        module_bitmask: asset.module_bitmask(),
        manifest_cid: asset.manifest_cid.map(hex::encode),
        manifest_hash: asset.manifest_hash.map(hex::encode),
        curve: asset.curve.as_ref().map(|c| {
            json!({
                "phase": c.phase,
                "sell_enabled": c.sell_enabled,
            })
        }),
        rewards: rewards_detail(asset, rewards_state),
        governance: asset.governance.as_ref().map(|g| {
            json!({
                "verifier": match g.verifier {
                    lib_blockchain::contracts::sovereign_asset::GovernanceVerifierKind::Single => "single",
                    lib_blockchain::contracts::sovereign_asset::GovernanceVerifierKind::Multisig => "multisig",
                },
                "signers": g.signers,
                "threshold": g.threshold,
            })
        }),
        interface: interface_for_asset(asset, manifest),
        share_link: asset_share_link(&asset.asset_id),
        manifest_resolved,
        manifest: manifest.cloned(),
        dao_registry,
        governance_status: governance_status_detail(
            asset,
            gov_state,
            rewards_state,
            tip_height,
        ),
    }
}

pub struct AssetsHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl AssetsHandler {
    pub fn new() -> Self {
        let blockchain = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .expect("Global blockchain must be initialized")
            })
        });
        Self { blockchain }
    }

    async fn handle_launch(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let launch_req: LaunchAssetRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let tx = decode_signed_tx_raw(&launch_req.signed_tx).map_err(|e| {
            tracing::error!("[assets/launch] decode_signed_tx FAILED: {}", e);
            e
        })?;

        if tx.transaction_type != TransactionType::AssetLaunch {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!(
                    "Invalid transaction type for assets/launch: expected AssetLaunch, got {:?}",
                    tx.transaction_type
                ),
            ));
        }

        let payload = match AssetLaunchPayloadV1::decode_memo(&tx.memo) {
            Ok(p) => p,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid asset launch payload: {e}"),
                ));
            }
        };

        if launch_req.enforce_dao_launch_constraints {
            if let Err(e) = payload.validate_dao_launch_ui_constraints() {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("DAO launch validation failed: {e}"),
                ));
            }
        }

        {
            let bc = self.blockchain.read().await;
            if bc
                .iter_sovereign_assets()
                .iter()
                .any(|a| a.symbol.eq_ignore_ascii_case(&payload.symbol))
            {
                return Ok(create_error_response(
                    ZhtpStatus::Conflict,
                    format!(
                        "Asset with symbol '{}' already exists",
                        payload.symbol
                    ),
                ));
            }
        }

        let asset_id = hash_transaction(&tx).as_array();
        if let Err(e) = self.submit_to_mempool(tx).await {
            tracing::error!("[assets/launch] submit_to_mempool FAILED: {}", e);
            return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
        }

        let (creator_alloc, treasury_alloc) = payload.split_initial_supply();
        info!(
            "AssetLaunch submitted: {} ({}) asset_id={}",
            payload.name,
            payload.symbol,
            hex::encode(asset_id)
        );
        create_json_response(json!({
            "success": true,
            "asset_id": hex::encode(asset_id),
            "share_link": asset_share_link(&asset_id),
            "name": payload.name,
            "symbol": payload.symbol,
            "creator_allocation": creator_alloc.to_string(),
            "treasury_allocation": treasury_alloc.to_string(),
            "tx_status": "submitted_to_mempool",
        }))
    }

    async fn handle_list(&self) -> Result<ZhtpResponse> {
        let bc = self.blockchain.read().await;
        let mut assets: Vec<AssetListItem> =
            bc.iter_sovereign_assets().iter().map(to_list_item).collect();
        assets.sort_by(|a, b| {
            b.launched_at_height
                .cmp(&a.launched_at_height)
                .then_with(|| a.symbol.cmp(&b.symbol))
        });
        let count = assets.len();
        info!("Served sovereign asset catalog: count={}", count);
        create_json_response(json!({
            "assets": assets,
            "count": count,
            "share_link_scheme": "zhtp://asset/{asset_id}",
        }))
    }

    async fn handle_get(&self, asset_id_hex: &str) -> Result<ZhtpResponse> {
        let asset_id = parse_asset_id(asset_id_hex)?;
        let bc = self.blockchain.read().await;
        let asset = bc
            .get_sovereign_asset(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not found"))?;
        let rewards_state = bc.get_rewards_module_state(&asset_id);
        if asset.module_flags.has_rewards() && rewards_state.is_none() {
            anyhow::bail!("rewards module state unavailable for asset {}", asset_id_hex);
        }
        let gov_state = bc.get_governance_module_state(&asset_id);
        let tip_height = bc.height;
        let (manifest, manifest_resolved) = resolve_asset_manifest(&asset).await;
        let dao_registry = dao_registry_linkage(&bc, &asset_id);
        create_json_response(serde_json::to_value(to_detail(
            &asset,
            rewards_state.as_ref(),
            gov_state.as_ref(),
            tip_height,
            manifest.as_ref(),
            manifest_resolved,
            dao_registry,
        ))?)
    }

    async fn handle_interface(&self, asset_id_hex: &str) -> Result<ZhtpResponse> {
        let asset_id = parse_asset_id(asset_id_hex)?;
        let bc = self.blockchain.read().await;
        let asset = bc
            .get_sovereign_asset(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not found"))?;
        let (manifest, manifest_resolved) = resolve_asset_manifest(&asset).await;
        create_json_response(json!({
            "asset_id": hex::encode(asset.asset_id),
            "symbol": asset.symbol,
            "share_link": asset_share_link(&asset.asset_id),
            "manifest_resolved": manifest_resolved,
            "interface": interface_for_asset(&asset, manifest.as_ref()),
        }))
    }

    async fn handle_balance(&self, asset_id_hex: &str, address: &str) -> Result<ZhtpResponse> {
        let asset_id = parse_asset_id(asset_id_hex)?;
        let bc = self.blockchain.read().await;

        let asset = bc
            .get_sovereign_asset(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not found"))?;

        let key_id =
            crate::api::handlers::balance_key::resolve_custom_token_balance_key(&bc, address)?;
        let balance = bc
            .token_balance(&asset_id, &key_id)
            .map_err(|e| anyhow::anyhow!("balance lookup failed: {}", e))?;

        create_json_response(json!({
            "asset_id": hex::encode(asset_id),
            "address": address,
            "balance": balance.to_string(),
            "symbol": asset.symbol,
        }))
    }

    fn parse_path_segments(uri: &str) -> Vec<&str> {
        uri.trim_start_matches("/api/v1/assets/")
            .trim_end_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect()
    }

    async fn submit_to_mempool(&self, tx: Transaction) -> Result<()> {
        let tx_type = tx.transaction_type;
        let mut blockchain = self.blockchain.write().await;
        blockchain
            .add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit transaction to mempool: {}", e))?;
        tracing::debug!("assets submit_to_mempool: type={:?} accepted", tx_type);
        Ok(())
    }
}

fn decode_signed_tx_raw(signed_tx: &str) -> Result<Transaction> {
    let tx_bytes = hex::decode(signed_tx).map_err(|_| anyhow::anyhow!("Invalid signed_tx hex"))?;
    lib_blockchain::transaction::decode_client_transaction(&tx_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid signed_tx payload: {}", e))
}

fn parse_asset_id(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|_| anyhow::anyhow!("Invalid asset_id hex"))?;
    if bytes.len() != 32 {
        anyhow::bail!("asset_id must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for AssetsHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        if crate::session_manager::is_request_password_session(&request).await {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Asset launch requires key authentication (mobile app or seed phrase recovery)"
                    .to_string(),
            ));
        }

        let result = match (request.method.clone(), request.uri.as_str()) {
            (ZhtpMethod::Post, "/api/v1/assets/launch") => self.handle_launch(request).await,
            (ZhtpMethod::Get, "/api/v1/assets" | "/api/v1/assets/") => self.handle_list().await,
            (ZhtpMethod::Get, uri) if uri.starts_with("/api/v1/assets/") => {
                let segments = Self::parse_path_segments(uri);
                match segments.as_slice() {
                    [id] => self.handle_get(id).await,
                    [id, "interface"] => self.handle_interface(id).await,
                    [id, "balances", address] => self.handle_balance(id, address).await,
                    _ => {
                        return Ok(create_error_response(
                            ZhtpStatus::NotFound,
                            "Unknown assets route".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    "Not found".to_string(),
                ));
            }
        };
        match result {
            Ok(response) => Ok(response),
            Err(err) => Ok(map_assets_error(err)),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/assets")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::contracts::sovereign_asset::{AssetIdSource, AssetModuleFlags, SupplyMode};

    fn sample_asset() -> SovereignAsset {
        SovereignAsset {
            asset_id: [0xAB; 32],
            id_source: AssetIdSource::LaunchTx,
            name: "Bubble".to_string(),
            symbol: "BUBL".to_string(),
            decimals: 18,
            creator_key_id: [0x01; 32],
            creator_did: None,
            treasury_key_id: Some([0x02; 32]),
            launched_at_height: Some(10),
            supply_mode: SupplyMode::Fixed,
            max_supply: 1_000,
            total_supply: 1_000,
            manifest_cid: Some([0x11; 32]),
            manifest_hash: Some([0x22; 32]),
            schema_version: 1,
            authority: lib_blockchain::contracts::sovereign_asset::AssetAuthority::Creator {
                key_id: [0x01; 32],
            },
            module_flags: AssetModuleFlags(AssetModuleFlags::REWARDS),
            curve: None,
            rewards: None,
            governance: None,
        }
    }

    #[test]
    fn asset_share_link_is_stable_zhtp_scheme() {
        assert_eq!(
            asset_share_link(&[0xAB; 32]),
            format!("zhtp://asset/{}", hex::encode([0xAB; 32]))
        );
    }

    #[test]
    fn interface_prefers_manifest_wallet_shortcut() {
        let asset = sample_asset();
        let manifest = json!({
            "schema": "zhtp/asset-manifest/v1",
            "interface": {
                "version": "2.0.0",
                "tx_kinds": ["RewardsClaim", "AssetTransfer"],
                "wallet_tab": "rewards"
            }
        });
        let iface = interface_for_asset(&asset, Some(&manifest));
        assert_eq!(iface["version"], "2.0.0");
        assert_eq!(iface["wallet_tab"], "rewards");
    }

    #[test]
    fn manifest_hash_matches_raw_blake3_bytes() {
        let bytes = br#"{"schema":"zhtp/asset-manifest/v1"}"#;
        let hash = lib_crypto::hash_blake3(bytes);
        assert!(manifest_hash_matches(bytes, &hash));
        assert!(!manifest_hash_matches(b"other", &hash));
    }
}