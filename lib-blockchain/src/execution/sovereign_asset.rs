//! Sovereign Asset executor apply helpers (SA-3..SA-7).

use crate::contracts::sovereign_asset::{
    project_from_token_contract, validate_governance_verifier, AssetAuthority, AssetIdSource,
    AssetModuleFlags, CurveModuleHeader, GovernanceModuleHeader, GovernanceModuleState,
    GovernanceVerifierKind, GovernanceVerifierState, PendingAuthorityTransfer,
    PendingRewardsPolicyUpdate, RewardsModuleHeader, RewardsModuleState, SovereignAsset,
    SupplyMode, AUTHORITY_TRANSFER_TIMELOCK_BLOCKS, REWARDS_POLICY_DECREASE_TIMELOCK_BLOCKS,
};
use crate::execution::tx_apply::{apply_token_mint, StateMutator};
use crate::execution::{TxApplyError, TxApplyResult};
use crate::storage::{Address, TokenId};
use crate::transaction::asset_tx::{
    AssetAuthorityProof, AssetAuthorityTransferPayloadV1, AssetLaunchPayloadV1,
    AssetManifestUpdatePayloadV1, AssetModuleUpgradePayloadV1,
    AssetRewardsDelegateRotatePayloadV1, AssetRewardsPolicyUpdatePayloadV1, AssetUpgradeModule,
    GovernanceLaunchConfig, RewardsLaunchConfig,
};
use crate::types::Hash;

#[derive(Debug)]
pub struct AssetLaunchOutcome {
    pub asset_id: [u8; 32],
    pub creator_allocation: u128,
    pub treasury_allocation: u128,
    pub module_bitmask: u8,
}

pub fn apply_asset_launch(
    mutator: &StateMutator<'_>,
    tx_hash: &Hash,
    creator_key_id: [u8; 32],
    payload: &AssetLaunchPayloadV1,
    block_height: u64,
    block_time: u64,
) -> TxApplyResult<AssetLaunchOutcome> {
    let asset_id = tx_hash.as_array();

    if mutator.get_sovereign_asset(&asset_id)?.is_some() {
        return Err(TxApplyError::InvalidType(
            "AssetLaunch for existing asset_id is not allowed".to_string(),
        ));
    }
    if mutator.asset_symbol_exists(&payload.symbol)? {
        return Err(TxApplyError::InvalidType(format!(
            "AssetLaunch: symbol '{}' conflicts with an existing asset",
            payload.symbol
        )));
    }
    if payload.treasury_key_id == creator_key_id {
        return Err(TxApplyError::InvalidType(
            "AssetLaunch treasury_key_id must differ from creator".to_string(),
        ));
    }

    let (creator_allocation, treasury_allocation) = payload.split_initial_supply();
    let mut module_flags = AssetModuleFlags(0);
    let mut curve_header = None;
    let mut rewards_header = None;
    let mut governance_header = None;
    let mut authority = AssetAuthority::Creator { key_id: creator_key_id };

    if let Some(curve_cfg) = &payload.curve {
        module_flags.0 |= AssetModuleFlags::CURVE;
        curve_header = Some(CurveModuleHeader {
            phase: "curve".to_string(),
            sell_enabled: curve_cfg.sell_enabled,
        });
        if let Some(state) = payload.initial_curve_state() {
            mutator.put_curve_module_state(&asset_id, &state)?;
        }
    }

    if let Some(rewards_cfg) = &payload.rewards {
        module_flags.0 |= AssetModuleFlags::REWARDS;
        rewards_header = Some(RewardsModuleHeader {
            spend_delegate_key_id: Some(rewards_cfg.spend_delegate_key_id),
        });
        mutator.put_rewards_module_state(
            &asset_id,
            &RewardsModuleState {
                spend_delegate_key_id: rewards_cfg.spend_delegate_key_id,
                policy_cid: rewards_cfg.policy_cid,
                policy_hash: rewards_cfg.policy_hash,
                nonce: 0,
                pending_policy: None,
            },
        )?;
        if let Some(doc) = &rewards_cfg.policy_document {
            mutator.put_rewards_policy_document(&rewards_cfg.policy_hash, doc)?;
        }
    }

    if let Some(gov_cfg) = &payload.governance {
        let verifier = gov_cfg.resolved_verifier();
        module_flags.0 |= AssetModuleFlags::GOVERNANCE;
        governance_header = Some(governance_header_from_verifier(&verifier));
        let mut gov_state = GovernanceModuleState::default();
        gov_state.verifier = Some(verifier);
        if payload.transfer_authority {
            authority = AssetAuthority::Governance {
                module_ref: asset_id,
            };
        } else {
            gov_state.pending_transfer = None;
        }
        mutator.put_governance_module_state(&asset_id, &gov_state)?;
    }

    let asset = SovereignAsset {
        asset_id,
        id_source: AssetIdSource::LaunchTx,
        name: payload.name.clone(),
        symbol: payload.symbol.clone(),
        decimals: if payload.decimals == 0 { 8 } else { payload.decimals },
        creator_key_id,
        creator_did: None,
        treasury_key_id: Some(payload.treasury_key_id),
        launched_at_height: Some(block_height),
        supply_mode: payload.supply_mode,
        max_supply: payload.initial_supply,
        total_supply: payload.initial_supply,
        manifest_cid: Some(payload.manifest_cid),
        manifest_hash: Some(payload.manifest_hash),
        schema_version: 1,
        authority,
        module_flags,
        curve: curve_header,
        rewards: rewards_header,
        governance: governance_header,
    };

    mutator.put_sovereign_asset(&asset)?;
    mutator.put_asset_symbol_index(&payload.symbol, &asset_id)?;

    let token_id = TokenId::new(asset_id);
    let creator_addr = Address::new(creator_key_id);
    let treasury_addr = Address::new(payload.treasury_key_id);
    apply_token_mint(mutator, &token_id, &creator_addr, creator_allocation)?;
    apply_token_mint(mutator, &token_id, &treasury_addr, treasury_allocation)?;

    Ok(AssetLaunchOutcome {
        asset_id,
        creator_allocation,
        treasury_allocation,
        module_bitmask: module_flags.0,
    })
}

/// Resolve a sovereign asset for upgrade: sled record first, else legacy token projection.
fn resolve_sovereign_asset_for_upgrade(
    mutator: &StateMutator<'_>,
    asset_id: &[u8; 32],
) -> TxApplyResult<SovereignAsset> {
    if let Some(asset) = mutator.get_sovereign_asset(asset_id)? {
        return Ok(asset);
    }
    let token_id = TokenId::new(*asset_id);
    let contract = mutator
        .get_token_contract(&token_id)?
        .ok_or_else(|| TxApplyError::InvalidType("asset not found".to_string()))?;
    project_from_token_contract(&contract, None).ok_or_else(|| {
        TxApplyError::InvalidType("legacy asset cannot be upgraded".to_string())
    })
}

pub fn apply_asset_module_upgrade(
    mutator: &StateMutator<'_>,
    signer_key_id: [u8; 32],
    payload: &AssetModuleUpgradePayloadV1,
    block_height: u64,
) -> TxApplyResult<()> {
    let mut asset = resolve_sovereign_asset_for_upgrade(mutator, &payload.asset_id)?;

    ensure_creator_or_governance(mutator, &asset, signer_key_id)?;

    match &payload.module {
        AssetUpgradeModule::Curve(cfg) => {
            if asset.module_flags.has_curve() {
                return Err(TxApplyError::InvalidType("curve module already enabled".into()));
            }
            asset.supply_mode = SupplyMode::Elastic;
            asset.module_flags.0 |= AssetModuleFlags::CURVE;
            asset.curve = Some(CurveModuleHeader {
                phase: "curve".to_string(),
                sell_enabled: cfg.sell_enabled,
            });
            let launch = AssetLaunchPayloadV1 {
                name: asset.name.clone(),
                symbol: asset.symbol.clone(),
                decimals: asset.decimals,
                initial_supply: asset.total_supply,
                treasury_key_id: asset.treasury_key_id.unwrap_or([0u8; 32]),
                treasury_bps: 2_000,
                supply_mode: SupplyMode::Elastic,
                manifest_cid: asset.manifest_cid.unwrap_or([0u8; 32]),
                manifest_hash: asset.manifest_hash.unwrap_or([0u8; 32]),
                curve: Some(cfg.clone()),
                rewards: None,
                governance: None,
                transfer_authority: false,
            };
            if let Some(state) = launch.initial_curve_state() {
                mutator.put_curve_module_state(&payload.asset_id, &state)?;
            }
        }
        AssetUpgradeModule::Rewards(cfg) => {
            enable_rewards(mutator, &mut asset, cfg)?;
        }
        AssetUpgradeModule::Governance(gov) => {
            enable_governance(
                mutator,
                &mut asset,
                gov,
                payload.transfer_authority,
                block_height,
            )?;
        }
    }

    mutator.put_sovereign_asset(&asset)?;
    Ok(())
}

pub fn apply_asset_manifest_update(
    mutator: &StateMutator<'_>,
    signer_key_id: [u8; 32],
    payload: &AssetManifestUpdatePayloadV1,
) -> TxApplyResult<()> {
    let mut asset = mutator
        .get_sovereign_asset(&payload.asset_id)?
        .ok_or_else(|| TxApplyError::InvalidType("asset not found".to_string()))?;

    verify_authority_proof(mutator, &asset, signer_key_id, &payload.authority_proof)?;

    if payload.manifest_cid == [0u8; 32] || payload.manifest_hash == [0u8; 32] {
        return Err(TxApplyError::InvalidType("manifest fields required".into()));
    }

    asset.manifest_cid = Some(payload.manifest_cid);
    asset.manifest_hash = Some(payload.manifest_hash);
    mutator.put_sovereign_asset(&asset)?;
    Ok(())
}

pub fn apply_asset_rewards_policy_update(
    mutator: &StateMutator<'_>,
    signer_key_id: [u8; 32],
    payload: &AssetRewardsPolicyUpdatePayloadV1,
    block_height: u64,
) -> TxApplyResult<()> {
    let asset = mutator
        .get_sovereign_asset(&payload.asset_id)?
        .ok_or_else(|| TxApplyError::InvalidType("asset not found".to_string()))?;

    if !asset.module_flags.has_rewards() {
        return Err(TxApplyError::InvalidType("rewards module not enabled".into()));
    }
    verify_authority_proof(mutator, &asset, signer_key_id, &payload.authority_proof)?;

    let doc = payload
        .policy
        .policy_document
        .as_ref()
        .ok_or_else(|| TxApplyError::InvalidType("policy_document required".into()))?;
    let new_policy = crate::rewards_policy::validate_rewards_policy(doc)
        .map_err(|e| TxApplyError::InvalidType(format!("invalid rewards policy: {e}")))?;
    let expected_asset_id = hex::encode(payload.asset_id);
    if new_policy.asset_id != expected_asset_id {
        return Err(TxApplyError::InvalidType(
            "policy asset_id does not match payload asset_id".into(),
        ));
    }

    let mut state = mutator
        .get_rewards_module_state(&payload.asset_id)?
        .ok_or_else(|| TxApplyError::InvalidType("rewards state missing".into()))?;

    if payload.policy.policy_hash == state.policy_hash {
        return Err(TxApplyError::InvalidType(
            "rewards policy hash unchanged".into(),
        ));
    }

    let current_policy = mutator
        .get_rewards_policy_document(&state.policy_hash)?
        .ok_or_else(|| TxApplyError::InvalidType("current policy document missing".into()))?;
    let current_policy = crate::rewards_policy::validate_rewards_policy(&current_policy)
        .map_err(|e| TxApplyError::InvalidType(format!("invalid current policy: {e}")))?;

    let is_decrease =
        crate::rewards_policy::is_rewards_policy_decrease(&current_policy, &new_policy);
    if is_decrease {
        if state.pending_policy.is_some() {
            return Err(TxApplyError::InvalidType(
                "rewards policy decrease already pending".into(),
            ));
        }
        state.pending_policy = Some(PendingRewardsPolicyUpdate {
            policy_cid: payload.policy.policy_cid,
            policy_hash: payload.policy.policy_hash,
            effective_height: block_height.saturating_add(REWARDS_POLICY_DECREASE_TIMELOCK_BLOCKS),
        });
        mutator.put_rewards_policy_document(&payload.policy.policy_hash, doc)?;
        mutator.put_rewards_module_state(&payload.asset_id, &state)?;
        return Ok(());
    }

    apply_rewards_policy_now(mutator, &payload.asset_id, &mut state, &payload.policy, doc)?;
    Ok(())
}

/// Activate queued decrease-only policy updates whose timelock has expired.
pub fn activate_pending_rewards_policies(
    mutator: &StateMutator<'_>,
    block_height: u64,
) -> TxApplyResult<()> {
    let asset_ids = mutator.list_rewards_module_asset_ids()?;
    for asset_id in asset_ids {
        let Some(mut state) = mutator.get_rewards_module_state(&asset_id)? else {
            continue;
        };
        let Some(pending) = state.pending_policy.clone() else {
            continue;
        };
        if pending.effective_height > block_height {
            continue;
        }
        let doc = mutator
            .get_rewards_policy_document(&pending.policy_hash)?
            .ok_or_else(|| {
                TxApplyError::InvalidType(format!(
                    "pending rewards policy document missing for {}",
                    hex::encode(asset_id)
                ))
            })?;
        state.policy_cid = pending.policy_cid;
        state.policy_hash = pending.policy_hash;
        state.pending_policy = None;
        state.nonce = state.nonce.saturating_add(1);
        mutator.put_rewards_module_state(&asset_id, &state)?;
        let _ = doc;
    }
    Ok(())
}

fn apply_rewards_policy_now(
    mutator: &StateMutator<'_>,
    asset_id: &[u8; 32],
    state: &mut RewardsModuleState,
    policy_cfg: &crate::transaction::asset_tx::RewardsPolicyUpdateConfig,
    doc: &[u8],
) -> TxApplyResult<()> {
    state.policy_cid = policy_cfg.policy_cid;
    state.policy_hash = policy_cfg.policy_hash;
    state.pending_policy = None;
    state.nonce = state.nonce.saturating_add(1);
    mutator.put_rewards_policy_document(&policy_cfg.policy_hash, doc)?;
    mutator.put_rewards_module_state(asset_id, state)?;
    Ok(())
}

pub fn apply_asset_rewards_delegate_rotate(
    mutator: &StateMutator<'_>,
    signer_key_id: [u8; 32],
    payload: &AssetRewardsDelegateRotatePayloadV1,
) -> TxApplyResult<()> {
    let asset = mutator
        .get_sovereign_asset(&payload.asset_id)?
        .ok_or_else(|| TxApplyError::InvalidType("asset not found".to_string()))?;

    if !asset.module_flags.has_rewards() {
        return Err(TxApplyError::InvalidType("rewards module not enabled".into()));
    }
    verify_authority_proof(mutator, &asset, signer_key_id, &payload.authority_proof)?;

    if payload.new_delegate_key_id == [0u8; 32] {
        return Err(TxApplyError::InvalidType("new delegate must be non-zero".into()));
    }

    let mut state = mutator
        .get_rewards_module_state(&payload.asset_id)?
        .ok_or_else(|| TxApplyError::InvalidType("rewards state missing".into()))?;
    state.spend_delegate_key_id = payload.new_delegate_key_id;
    state.nonce = state.nonce.saturating_add(1);
    mutator.put_rewards_module_state(&payload.asset_id, &state)?;

    let mut asset = asset;
    if let Some(ref mut rh) = asset.rewards {
        rh.spend_delegate_key_id = Some(payload.new_delegate_key_id);
    }
    mutator.put_sovereign_asset(&asset)?;
    Ok(())
}

fn enable_rewards(
    mutator: &StateMutator<'_>,
    asset: &mut SovereignAsset,
    cfg: &RewardsLaunchConfig,
) -> TxApplyResult<()> {
    if mutator.get_rewards_module_state(&asset.asset_id)?.is_some() {
        return Err(TxApplyError::InvalidType("rewards module already enabled".into()));
    }
    asset.module_flags.0 |= AssetModuleFlags::REWARDS;
    asset.rewards = Some(RewardsModuleHeader {
        spend_delegate_key_id: Some(cfg.spend_delegate_key_id),
    });
    mutator.put_rewards_module_state(
        &asset.asset_id,
        &RewardsModuleState {
            spend_delegate_key_id: cfg.spend_delegate_key_id,
            policy_cid: cfg.policy_cid,
            policy_hash: cfg.policy_hash,
            nonce: 0,
            pending_policy: None,
        },
    )?;
    if let Some(doc) = &cfg.policy_document {
        mutator.put_rewards_policy_document(&cfg.policy_hash, doc)?;
    }
    Ok(())
}

fn enable_governance(
    mutator: &StateMutator<'_>,
    asset: &mut SovereignAsset,
    gov: &GovernanceLaunchConfig,
    transfer_authority: bool,
    block_height: u64,
) -> TxApplyResult<()> {
    if asset.module_flags.has_governance() {
        return Err(TxApplyError::InvalidType("governance module already enabled".into()));
    }
    let verifier = gov.resolved_verifier();
    asset.module_flags.0 |= AssetModuleFlags::GOVERNANCE;
    asset.governance = Some(governance_header_from_verifier(&verifier));

    let mut gov_state = GovernanceModuleState::default();
    gov_state.verifier = Some(verifier.clone());

    if transfer_authority {
        asset.authority = AssetAuthority::Governance {
            module_ref: asset.asset_id,
        };
    } else {
        gov_state.pending_transfer = Some(PendingAuthorityTransfer {
            new_verifier: verifier,
            effective_height: block_height.saturating_add(AUTHORITY_TRANSFER_TIMELOCK_BLOCKS),
        });
    }
    mutator.put_governance_module_state(&asset.asset_id, &gov_state)?;
    Ok(())
}

fn governance_header_from_verifier(v: &GovernanceVerifierState) -> GovernanceModuleHeader {
    GovernanceModuleHeader {
        verifier: v.kind(),
        signers: v.signer_count(),
        threshold: v.threshold(),
    }
}

fn ensure_creator_or_governance(
    mutator: &StateMutator<'_>,
    asset: &SovereignAsset,
    signer_key_id: [u8; 32],
) -> TxApplyResult<()> {
    match &asset.authority {
        AssetAuthority::Creator { key_id } if *key_id == signer_key_id => Ok(()),
        AssetAuthority::Governance { module_ref } => {
            let gov = mutator
                .get_governance_module_state(module_ref)?
                .ok_or_else(|| TxApplyError::InvalidType("governance state missing".into()))?;
            if let Some(v) = gov.verifier {
                if verifier_contains(&v, signer_key_id) {
                    return Ok(());
                }
            }
            Err(TxApplyError::InvalidType("unauthorized for asset upgrade".into()))
        }
        _ => Err(TxApplyError::InvalidType("unauthorized for asset upgrade".into())),
    }
}

pub fn apply_asset_authority_transfer(
    mutator: &StateMutator<'_>,
    signer_key_id: [u8; 32],
    payload: &AssetAuthorityTransferPayloadV1,
    block_height: u64,
) -> TxApplyResult<()> {
    let mut asset = mutator
        .get_sovereign_asset(&payload.asset_id)?
        .ok_or_else(|| TxApplyError::InvalidType("asset not found".to_string()))?;

    verify_authority_proof(mutator, &asset, signer_key_id, &payload.authority_proof)?;
    validate_governance_verifier(&payload.new_verifier)
        .map_err(|e| TxApplyError::InvalidType(e))?;

    let mut gov_state = mutator
        .get_governance_module_state(&payload.asset_id)?
        .unwrap_or_default();

    match &asset.authority {
        AssetAuthority::Creator { .. } => {
            if let Some(effective) = payload.effective_height {
                if effective <= block_height {
                    return Err(TxApplyError::InvalidType(
                        "authority transfer effective_height must be in the future".into(),
                    ));
                }
                gov_state.pending_transfer = Some(PendingAuthorityTransfer {
                    new_verifier: payload.new_verifier.clone(),
                    effective_height: effective,
                });
            } else {
                asset.authority = AssetAuthority::Governance {
                    module_ref: asset.asset_id,
                };
                gov_state.verifier = Some(payload.new_verifier.clone());
                gov_state.pending_transfer = None;
                asset.governance = Some(governance_header_from_verifier(&payload.new_verifier));
                asset.module_flags.0 |= AssetModuleFlags::GOVERNANCE;
            }
        }
        AssetAuthority::Governance { .. } => {
            gov_state.verifier = Some(payload.new_verifier.clone());
            gov_state.pending_transfer = None;
            asset.governance = Some(governance_header_from_verifier(&payload.new_verifier));
        }
    }

    mutator.put_governance_module_state(&payload.asset_id, &gov_state)?;
    mutator.put_sovereign_asset(&asset)?;
    Ok(())
}

fn verify_authority_proof(
    mutator: &StateMutator<'_>,
    asset: &SovereignAsset,
    signer_key_id: [u8; 32],
    proof: &AssetAuthorityProof,
) -> TxApplyResult<()> {
    match (&asset.authority, proof) {
        (AssetAuthority::Creator { key_id }, AssetAuthorityProof::CreatorSig) if *key_id == signer_key_id => {
            Ok(())
        }
        (AssetAuthority::Creator { .. }, AssetAuthorityProof::CreatorSig) => {
            Err(TxApplyError::InvalidType("creator signature mismatch".into()))
        }
        (AssetAuthority::Governance { module_ref }, AssetAuthorityProof::Governance(_)) => {
            let gov = mutator
                .get_governance_module_state(module_ref)?
                .ok_or_else(|| TxApplyError::InvalidType("governance state missing".into()))?;
            let verifier = gov
                .verifier
                .as_ref()
                .ok_or_else(|| TxApplyError::InvalidType("governance verifier missing".into()))?;
            if verifier_contains(verifier, signer_key_id) {
                Ok(())
            } else {
                Err(TxApplyError::InvalidType(
                    "governance signer not authorized".into(),
                ))
            }
        }
        _ => Err(TxApplyError::InvalidType("invalid authority proof".into())),
    }
}

fn verifier_contains(verifier: &GovernanceVerifierState, key_id: [u8; 32]) -> bool {
    match verifier {
        GovernanceVerifierState::Single { signer_key_id } => *signer_key_id == key_id,
        GovernanceVerifierState::Multisig { signers, .. } => signers.iter().any(|s| *s == key_id),
    }
}