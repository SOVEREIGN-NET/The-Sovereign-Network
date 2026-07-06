//! Sovereign Asset discovery API (ADR: docs/arch/sovereign-asset.md, SA-2).

use anyhow::Result;
use lib_blockchain::contracts::sovereign_asset::{AssetIdSource, SovereignAsset, SupplyMode};
use lib_blockchain::{Blockchain, BlockchainQuery};
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::api::handlers::token::u128_as_string;

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
    }
}

fn to_detail(asset: &SovereignAsset) -> AssetDetailResponse {
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
        rewards: asset.rewards.as_ref().map(|r| {
            json!({
                "spend_delegate_key_id": r.spend_delegate_key_id.map(hex::encode),
            })
        }),
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
        interface: asset_interface(asset),
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

    async fn handle_list(&self) -> Result<ZhtpResponse> {
        let bc = self.blockchain.read().await;
        let assets: Vec<AssetListItem> = bc.iter_sovereign_assets().iter().map(to_list_item).collect();
        let count = assets.len();
        info!("Served sovereign asset catalog: count={}", count);
        create_json_response(json!({ "assets": assets, "count": count }))
    }

    async fn handle_get(&self, asset_id_hex: &str) -> Result<ZhtpResponse> {
        let asset_id = parse_asset_id(asset_id_hex)?;
        let bc = self.blockchain.read().await;
        let asset = bc
            .get_sovereign_asset(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not found"))?;
        create_json_response(serde_json::to_value(to_detail(&asset))?)
    }

    async fn handle_interface(&self, asset_id_hex: &str) -> Result<ZhtpResponse> {
        let asset_id = parse_asset_id(asset_id_hex)?;
        let bc = self.blockchain.read().await;
        let asset = bc
            .get_sovereign_asset(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not found"))?;
        create_json_response(json!({
            "asset_id": hex::encode(asset.asset_id),
            "symbol": asset.symbol,
            "interface": asset_interface(&asset),
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
        let result = match (request.method.clone(), request.uri.as_str()) {
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