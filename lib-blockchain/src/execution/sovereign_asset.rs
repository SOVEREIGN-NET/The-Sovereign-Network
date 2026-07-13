//! Sovereign Asset executor apply helpers (SA-3..SA-7).

use crate::contracts::sovereign_asset::{
    project_from_token_contract, validate_governance_verifier, AssetAuthority, AssetIdSource,
    AssetModuleFlags, CurveModuleHeader, GovernanceModuleHeader, GovernanceModuleState,
    GovernanceVerifierKind, GovernanceVerifierState, PendingAuthorityTransfer,
    PendingBurnBpsUpdate, PendingRewardsPolicyUpdate, RewardsModuleHeader, RewardsModuleState,
    SovereignAsset, SupplyMode, AUTHORITY_TRANSFER_TIMELOCK_BLOCKS,
    GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT, MAX_TRANSFER_BURN_BPS,
    REWARDS_POLICY_DECREASE_TIMELOCK_BLOCKS,
};
use crate::execution::mint_and_allocate::mint_and_allocate;
use crate::execution::tx_apply::StateMutator;
use crate::execution::{TxApplyError, TxApplyResult};
use crate::storage::{Address, AddressExt, TokenId};
use crate::transaction::asset_tx::{
    AssetAuthorityProof, AssetAuthorityTransferPayloadV1, AssetLaunchPayloadV1,
    AssetManifestUpdatePayloadV1, AssetModuleUpgradePayloadV1,
    AssetBurnBpsUpdatePayloadV1, AssetRewardsDelegateRotatePayloadV1,
    AssetRewardsPolicyUpdatePayloadV1, AssetUpgradeModule, GovernanceLaunchConfig,
    RewardsLaunchConfig,
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
    let creator_recipient = if creator_allocation > 0 {
        creator_key_id
    } else {
        payload.treasury_key_id
    };
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
        dao_class: payload.dao_class,
        burn_bps: payload.burn_bps,
        pending_burn_bps: None,
        max_supply: payload.initial_supply,
        total_supply: 0,
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

    let mut live_asset = mutator
        .get_sovereign_asset(&asset_id)?
        .expect("asset just written");
    mint_and_allocate(
        mutator,
        &mut live_asset,
        creator_recipient,
        payload.initial_supply,
    )?;

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
                treasury_bps: asset.dao_class.treasury_bps(),
                supply_mode: SupplyMode::Elastic,
                manifest_cid: asset.manifest_cid.unwrap_or([0u8; 32]),
                manifest_hash: asset.manifest_hash.unwrap_or([0u8; 32]),
                curve: Some(cfg.clone()),
                rewards: None,
                governance: None,
                transfer_authority: false,
                dao_class: asset.dao_class,
                burn_bps: asset.burn_bps,
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

/// Activate queued authority transfers whose timelock has expired.
///
/// Creator → Governance handoffs and governance verifier rotations both queue
/// `pending_transfer`; activation applies `new_verifier` and clears the queue.
pub fn activate_pending_authority_transfers(
    mutator: &StateMutator<'_>,
    block_height: u64,
) -> TxApplyResult<()> {
    if block_height < GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT {
        return Ok(());
    }

    let asset_ids = mutator.list_governance_module_asset_ids()?;
    for asset_id in asset_ids {
        let Some(mut gov_state) = mutator.get_governance_module_state(&asset_id)? else {
            continue;
        };
        let Some(pending) = gov_state.pending_transfer.clone() else {
            continue;
        };
        if pending.effective_height > block_height {
            continue;
        }

        let Some(mut asset) = mutator.get_sovereign_asset(&asset_id)? else {
            tracing::warn!(
                asset_id = %hex::encode(asset_id),
                block_height,
                "sovereign asset missing for pending authority transfer; skipping"
            );
            continue;
        };

        gov_state.verifier = Some(pending.new_verifier.clone());
        gov_state.pending_transfer = None;
        asset.governance = Some(governance_header_from_verifier(&pending.new_verifier));

        match &asset.authority {
            AssetAuthority::Creator { .. } => {
                asset.authority = AssetAuthority::Governance {
                    module_ref: asset_id,
                };
            }
            AssetAuthority::Governance { .. } => {}
        }

        mutator.put_governance_module_state(&asset_id, &gov_state)?;
        mutator.put_sovereign_asset(&asset)?;
    }
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
        let Some(doc) = mutator.get_rewards_policy_document(&pending.policy_hash)? else {
            tracing::warn!(
                asset_id = %hex::encode(asset_id),
                block_height,
                policy_hash = %hex::encode(pending.policy_hash),
                "pending rewards policy document missing; skipping activation"
            );
            continue;
        };
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

/// Returns true when `signer_key_id` is an on-chain governance verifier for the asset.
pub fn is_governance_verifier_signer(
    mutator: &StateMutator<'_>,
    asset_id: &[u8; 32],
    signer_key_id: [u8; 32],
) -> TxApplyResult<bool> {
    let Some(gov) = mutator.get_governance_module_state(asset_id)? else {
        return Ok(false);
    };
    let Some(verifier) = gov.verifier.as_ref() else {
        return Ok(false);
    };
    Ok(verifier_contains(verifier, signer_key_id))
}

/// Post-launch elastic mints require a configured governance verifier signer.
pub fn require_governance_mint_signer(
    mutator: &StateMutator<'_>,
    asset: &SovereignAsset,
    signer_key_id: [u8; 32],
) -> TxApplyResult<()> {
    if !is_governance_verifier_signer(mutator, &asset.asset_id, signer_key_id)? {
        return Err(TxApplyError::Unauthorized(
            "elastic sovereign mint requires governance verifier signer".to_string(),
        ));
    }
    Ok(())
}

/// Treasury balance moves require a governance verifier signer (epic Q2).
pub fn require_treasury_spend_signer(
    mutator: &StateMutator<'_>,
    asset: &SovereignAsset,
    from_key_id: [u8; 32],
    signer_key_id: [u8; 32],
) -> TxApplyResult<()> {
    let Some(treasury_key_id) = asset.treasury_key_id else {
        return Ok(());
    };
    if from_key_id != treasury_key_id {
        return Ok(());
    }
    if !is_governance_verifier_signer(mutator, &asset.asset_id, signer_key_id)? {
        return Err(TxApplyError::Unauthorized(
            "treasury spend requires governance verifier authorization".to_string(),
        ));
    }
    Ok(())
}

pub fn apply_asset_burn_bps_update(
    mutator: &StateMutator<'_>,
    signer_key_id: [u8; 32],
    payload: &AssetBurnBpsUpdatePayloadV1,
    block_height: u64,
) -> TxApplyResult<()> {
    let mut asset = mutator
        .get_sovereign_asset(&payload.asset_id)?
        .ok_or_else(|| TxApplyError::InvalidType("asset not found".to_string()))?;

    verify_authority_proof(mutator, &asset, signer_key_id, &payload.authority_proof)?;

    asset.pending_burn_bps = Some(PendingBurnBpsUpdate {
        new_burn_bps: payload.new_burn_bps,
        effective_height: block_height.saturating_add(AUTHORITY_TRANSFER_TIMELOCK_BLOCKS),
    });
    mutator.put_sovereign_asset(&asset)?;
    Ok(())
}

/// Activate queued `burn_bps` updates whose timelock has expired (epic Q8).
pub fn activate_pending_burn_bps(mutator: &StateMutator<'_>, block_height: u64) -> TxApplyResult<()> {
    if block_height < GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT {
        return Ok(());
    }

    for (asset_id, mut asset) in mutator.iter_sovereign_assets()? {
        let Some(pending) = asset.pending_burn_bps.clone() else {
            continue;
        };
        if pending.effective_height > block_height {
            continue;
        }
        if pending.new_burn_bps > MAX_TRANSFER_BURN_BPS {
            tracing::warn!(
                asset_id = %hex::encode(asset_id),
                burn_bps = pending.new_burn_bps,
                "pending burn_bps exceeds cap; skipping activation"
            );
            asset.pending_burn_bps = None;
            mutator.put_sovereign_asset(&asset)?;
            continue;
        }
        asset.burn_bps = pending.new_burn_bps;
        asset.pending_burn_bps = None;
        mutator.put_sovereign_asset(&asset)?;
    }
    Ok(())
}

/// Apply a sovereign-asset transfer with optional burn (epic Q8).
pub fn apply_sovereign_token_transfer(
    mutator: &StateMutator<'_>,
    asset: &mut SovereignAsset,
    token: &TokenId,
    from: &Address,
    to: &Address,
    amount: u128,
    fee_bps: u16,
    fee_destination: &Address,
) -> TxApplyResult<u128> {
    let burn = if asset.burn_bps > 0 {
        (amount * asset.burn_bps as u128) / 10_000u128
    } else {
        0
    };
    let after_burn = amount.saturating_sub(burn);
    let fee_amount = if fee_bps > 0 && *fee_destination != Address::ZERO {
        (after_burn * fee_bps as u128) / 10_000u128
    } else {
        0
    };
    let net_to_recipient = after_burn.saturating_sub(fee_amount);

    mutator.debit_token(token, from, amount)?;
    if net_to_recipient > 0 {
        mutator.credit_token(token, to, net_to_recipient)?;
    }
    if fee_amount > 0 {
        mutator.credit_token(token, fee_destination, fee_amount)?;
    }
    if burn > 0 {
        asset.total_supply = asset.total_supply.saturating_sub(burn);
        mutator.put_sovereign_asset(asset)?;
    }
    Ok(fee_amount)
}

#[cfg(test)]
mod activate_pending_tests {
    use super::*;
    use crate::contracts::sovereign_asset::{
        AssetIdSource, GovernanceVerifierKind, PendingRewardsPolicyUpdate,
    };
    use crate::rewards_policy::policy_hash;
    use crate::storage::{BlockchainStore, SledStore};
    use std::sync::Arc;

    fn fresh_store() -> Arc<dyn BlockchainStore> {
        Arc::new(SledStore::open_temporary().unwrap())
    }

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn single_verifier(seed: u8) -> GovernanceVerifierState {
        GovernanceVerifierState::Single {
            signer_key_id: key(seed),
        }
    }

    fn sample_creator_asset(asset_id: [u8; 32], creator: [u8; 32]) -> SovereignAsset {
        SovereignAsset {
            asset_id,
            id_source: AssetIdSource::LaunchTx,
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            creator_key_id: creator,
            creator_did: None,
            treasury_key_id: Some(key(0xEE)),
            launched_at_height: Some(1),
            supply_mode: SupplyMode::Fixed,
            dao_class: crate::contracts::sovereign_asset::DaoClass::Fp,
            burn_bps: 0,
            pending_burn_bps: None,
            max_supply: 1_000,
            total_supply: 1_000,
            manifest_cid: Some([0x11; 32]),
            manifest_hash: Some([0x22; 32]),
            schema_version: 1,
            authority: AssetAuthority::Creator { key_id: creator },
            module_flags: AssetModuleFlags(AssetModuleFlags::GOVERNANCE),
            curve: None,
            rewards: None,
            governance: Some(GovernanceModuleHeader {
                verifier: GovernanceVerifierKind::Single,
                signers: 1,
                threshold: 1,
            }),
        }
    }

    struct BlockSession<'a> {
        store: &'a dyn BlockchainStore,
        next_height: u64,
    }

    impl<'a> BlockSession<'a> {
        fn new(store: &'a dyn BlockchainStore) -> Self {
            Self {
                store,
                next_height: 0,
            }
        }

        fn apply<F>(&mut self, f: F)
        where
            F: FnOnce(&StateMutator<'_>, u64),
        {
            self.store.begin_block(self.next_height).unwrap();
            f(&StateMutator::new(self.store), self.next_height);
            self.store.commit_block().unwrap();
            self.next_height += 1;
        }
    }

    fn seed_pending_creator_transfer(
        session: &mut BlockSession<'_>,
        asset_id: [u8; 32],
        creator: [u8; 32],
        new_verifier: GovernanceVerifierState,
        effective_height: u64,
    ) {
        session.apply(|mutator, _| {
            mutator.put_sovereign_asset(&sample_creator_asset(asset_id, creator)).unwrap();
            mutator
                .put_governance_module_state(
                    &asset_id,
                    &GovernanceModuleState {
                        verifier: Some(single_verifier(0xAA)),
                        pending_transfer: Some(PendingAuthorityTransfer {
                            new_verifier,
                            effective_height,
                        }),
                    },
                )
                .unwrap();
        });
    }

    #[test]
    fn authority_activation_fires_at_effective_height_not_before() {
        assert_eq!(GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT, 0, "unit tests expect gate at 0");
        let store = fresh_store();
        let mut session = BlockSession::new(store.as_ref());
        let asset_id = key(0x01);
        let new_verifier = single_verifier(0xBB);
        seed_pending_creator_transfer(
            &mut session,
            asset_id,
            key(0xCC),
            new_verifier.clone(),
            2,
        );

        session.apply(|mutator, height| {
            activate_pending_authority_transfers(mutator, height).unwrap();
        });
        let mutator = StateMutator::new(store.as_ref());
        let asset = mutator.get_sovereign_asset(&asset_id).unwrap().unwrap();
        assert!(matches!(asset.authority, AssetAuthority::Creator { .. }));
        let gov = mutator.get_governance_module_state(&asset_id).unwrap().unwrap();
        assert!(gov.pending_transfer.is_some());

        session.apply(|mutator, height| {
            activate_pending_authority_transfers(mutator, height).unwrap();
        });
        let mutator = StateMutator::new(store.as_ref());
        let asset = mutator.get_sovereign_asset(&asset_id).unwrap().unwrap();
        assert!(matches!(
            asset.authority,
            AssetAuthority::Governance { module_ref } if module_ref == asset_id
        ));
        assert_eq!(
            asset.governance,
            Some(GovernanceModuleHeader {
                verifier: GovernanceVerifierKind::Single,
                signers: 1,
                threshold: 1,
            })
        );
        let gov = mutator.get_governance_module_state(&asset_id).unwrap().unwrap();
        assert_eq!(gov.verifier, Some(new_verifier));
        assert!(gov.pending_transfer.is_none());
    }

    #[test]
    fn authority_activation_is_idempotent_on_next_block() {
        let store = fresh_store();
        let mut session = BlockSession::new(store.as_ref());
        let asset_id = key(0x02);
        let new_verifier = single_verifier(0xBB);
        seed_pending_creator_transfer(&mut session, asset_id, key(0xCC), new_verifier.clone(), 1);

        session.apply(|mutator, height| {
            activate_pending_authority_transfers(mutator, height).unwrap();
        });
        session.apply(|mutator, height| {
            activate_pending_authority_transfers(mutator, height).unwrap();
        });

        let mutator = StateMutator::new(store.as_ref());
        let asset = mutator.get_sovereign_asset(&asset_id).unwrap().unwrap();
        assert!(matches!(
            asset.authority,
            AssetAuthority::Governance { module_ref } if module_ref == asset_id
        ));
        let gov = mutator.get_governance_module_state(&asset_id).unwrap().unwrap();
        assert_eq!(gov.verifier, Some(new_verifier));
        assert!(gov.pending_transfer.is_none());
    }

    #[test]
    fn authority_activation_skips_assets_without_pending_transfer() {
        let store = fresh_store();
        let mut session = BlockSession::new(store.as_ref());
        let asset_id = key(0x03);
        let asset = sample_creator_asset(asset_id, key(0xCC));
        session.apply(|mutator, _| {
            mutator.put_sovereign_asset(&asset).unwrap();
            mutator
                .put_governance_module_state(
                    &asset_id,
                    &GovernanceModuleState {
                        verifier: Some(single_verifier(0xAA)),
                        pending_transfer: None,
                    },
                )
                .unwrap();
        });

        session.apply(|mutator, height| {
            activate_pending_authority_transfers(mutator, height).unwrap();
        });

        let mutator = StateMutator::new(store.as_ref());
        let live = mutator.get_sovereign_asset(&asset_id).unwrap().unwrap();
        assert_eq!(live.authority, asset.authority);
        let gov = mutator.get_governance_module_state(&asset_id).unwrap().unwrap();
        assert!(gov.pending_transfer.is_none());
        assert_eq!(gov.verifier, Some(single_verifier(0xAA)));
    }

    #[test]
    fn governance_authority_applies_pending_verifier_rotation() {
        let store = fresh_store();
        let mut session = BlockSession::new(store.as_ref());
        let asset_id = key(0x04);
        let new_verifier = single_verifier(0xDD);
        session.apply(|mutator, _| {
            let mut asset = sample_creator_asset(asset_id, key(0xCC));
            asset.authority = AssetAuthority::Governance { module_ref: asset_id };
            mutator.put_sovereign_asset(&asset).unwrap();
            mutator
                .put_governance_module_state(
                    &asset_id,
                    &GovernanceModuleState {
                        verifier: Some(single_verifier(0xAA)),
                        pending_transfer: Some(PendingAuthorityTransfer {
                            new_verifier: new_verifier.clone(),
                            effective_height: 1,
                        }),
                    },
                )
                .unwrap();
        });

        session.apply(|mutator, height| {
            activate_pending_authority_transfers(mutator, height).unwrap();
        });

        let mutator = StateMutator::new(store.as_ref());
        let gov = mutator.get_governance_module_state(&asset_id).unwrap().unwrap();
        assert_eq!(gov.verifier, Some(new_verifier));
        assert!(gov.pending_transfer.is_none());
        let live = mutator.get_sovereign_asset(&asset_id).unwrap().unwrap();
        assert!(matches!(live.authority, AssetAuthority::Governance { .. }));
        assert_eq!(
            live.governance,
            Some(GovernanceModuleHeader {
                verifier: GovernanceVerifierKind::Single,
                signers: 1,
                threshold: 1,
            })
        );
    }

    #[test]
    fn missing_sovereign_asset_does_not_halt_activation() {
        let store = fresh_store();
        let mut session = BlockSession::new(store.as_ref());
        let asset_id = key(0x05);
        session.apply(|mutator, _| {
            mutator
                .put_governance_module_state(
                    &asset_id,
                    &GovernanceModuleState {
                        verifier: Some(single_verifier(0xAA)),
                        pending_transfer: Some(PendingAuthorityTransfer {
                            new_verifier: single_verifier(0xBB),
                            effective_height: 1,
                        }),
                    },
                )
                .unwrap();
        });

        session.apply(|mutator, height| {
            activate_pending_authority_transfers(mutator, height).unwrap();
        });
        let mutator = StateMutator::new(store.as_ref());
        assert!(mutator.get_sovereign_asset(&asset_id).unwrap().is_none());
        let gov = mutator.get_governance_module_state(&asset_id).unwrap().unwrap();
        assert!(gov.pending_transfer.is_some(), "unchanged when asset missing");
    }

    #[test]
    fn rewards_activation_boundary_matches_authority_transfers() {
        let store = fresh_store();
        let mut session = BlockSession::new(store.as_ref());
        let asset_id = key(0x06);
        let policy_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../schemas/zhtp/rewards-policy/examples/bubl-v1.json"
        );
        let policy_bytes = std::fs::read(policy_path).expect("read bubl example");
        let policy_hash = policy_hash(
            &crate::rewards_policy::validate_rewards_policy(&policy_bytes).expect("valid policy"),
        )
        .expect("policy hash")
        .as_array();

        session.apply(|mutator, _| {
            mutator.put_rewards_policy_document(&policy_hash, &policy_bytes).unwrap();
            mutator
                .put_rewards_module_state(
                    &asset_id,
                    &RewardsModuleState {
                        spend_delegate_key_id: key(0x77),
                        policy_cid: [0x33; 32],
                        policy_hash,
                        nonce: 0,
                        pending_policy: Some(PendingRewardsPolicyUpdate {
                            policy_cid: [0x44; 32],
                            policy_hash,
                            effective_height: 2,
                        }),
                    },
                )
                .unwrap();
        });

        session.apply(|mutator, height| {
            activate_pending_rewards_policies(mutator, height).unwrap();
        });
        let mutator = StateMutator::new(store.as_ref());
        let state = mutator.get_rewards_module_state(&asset_id).unwrap().unwrap();
        assert_eq!(state.policy_cid, [0x33; 32]);
        assert!(state.pending_policy.is_some());

        session.apply(|mutator, height| {
            activate_pending_rewards_policies(mutator, height).unwrap();
        });
        let mutator = StateMutator::new(store.as_ref());
        let state = mutator.get_rewards_module_state(&asset_id).unwrap().unwrap();
        assert_eq!(state.policy_cid, [0x44; 32]);
        assert_eq!(state.policy_hash, policy_hash);
        assert!(state.pending_policy.is_none());
        assert_eq!(state.nonce, 1);
    }
}