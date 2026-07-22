//! On-chain reward claim application (policy-driven eligibility + token transfer).

use tracing::warn;

use crate::contracts::utils::generate_custom_token_id;
use crate::execution::errors::{TxApplyError, TxApplyResult};
use crate::execution::executor::TokenTransferOutcome;
use crate::execution::tx_apply::{self, StateMutator};
use crate::rewards_policy::{
    expected_amount_for_trigger, legacy_bubl_policy, policy_hash, validate_rewards_policy,
    weekly_partner_cap, RewardsPolicyV1,
};
use crate::storage::{Address, TokenId};
use crate::transaction::reward_claim::{
    daily_claim_key, iso_week_from_ts, key_id_from_did, partner_claim_key, partner_count_key,
    reward_event_to_policy_event, streak_key, utc_date_from_ts, utc_day_ordinal_from_ts,
    welcome_claim_key, RewardClaimData, RewardEventKind,
};

fn is_legacy_bubl_token(token_id: [u8; 32]) -> bool {
    token_id == generate_custom_token_id("Bubble", "BUBL")
}

fn resolve_rewards_policy(
    mutator: &StateMutator<'_>,
    token_id: [u8; 32],
) -> TxApplyResult<RewardsPolicyV1> {
    if let Some(state) = mutator.get_rewards_module_state(&token_id)? {
        if let Some(doc) = mutator.get_rewards_policy_document(&state.policy_hash)? {
            let policy = validate_rewards_policy(&doc).map_err(|e| {
                TxApplyError::RewardClaimDropped(format!("invalid stored rewards policy: {e}"))
            })?;
            let hash = policy_hash(&policy).map_err(|e| {
                TxApplyError::RewardClaimDropped(format!("rewards policy hash failed: {e}"))
            })?;
            if hash.as_array() != state.policy_hash {
                return Err(TxApplyError::RewardClaimDropped(
                    "stored rewards policy hash mismatch".to_string(),
                ));
            }
            return Ok(policy);
        }
        warn!(
            "RewardClaim: rewards module present but policy document missing for token {}",
            hex::encode(token_id)
        );
        return Err(TxApplyError::RewardClaimDropped(
            "rewards module present but policy document missing".to_string(),
        ));
    }
    if is_legacy_bubl_token(token_id) {
        return Ok(legacy_bubl_policy());
    }
    Err(TxApplyError::RewardClaimDropped(
        "rewards module state required for reward claims".to_string(),
    ))
}
fn reject_claim(msg: impl Into<String>) -> TxApplyResult<Option<TokenTransferOutcome>> {
    // Soft-drop at block apply (executor maps this to skip-tx, not halt).
    Err(TxApplyError::RewardClaimDropped(msg.into()))
}

/// Apply a `RewardClaim` inside the executor block window.
///
/// Ineligible claims return `Err` so the tx is rejected outright (never a silent
/// no-op block entry). Returns `Ok(Some(outcome))` on success.
pub fn apply_reward_claim(
    mutator: &StateMutator<'_>,
    data: &RewardClaimData,
    block_height: u64,
    block_timestamp: u64,
    fee_sink: &Address,
) -> TxApplyResult<Option<TokenTransferOutcome>> {
    if data.amount == 0 {
        warn!("RewardClaim rejected at height {}: zero amount", block_height);
        return reject_claim("RewardClaim amount must be greater than 0");
    }

    if key_id_from_did(&data.owner_did) != Some(data.recipient_key_id) {
        warn!(
            "RewardClaim rejected at height {}: recipient_key_id does not match owner_did",
            block_height
        );
        return reject_claim("recipient_key_id does not match owner_did");
    }

    let did_hash = crate::storage::did_to_hash(&data.owner_did);
    if mutator.get_identity(&did_hash)?.is_none() {
        warn!(
            "RewardClaim rejected at height {}: DID {} not registered",
            block_height,
            &data.owner_did[..20.min(data.owner_did.len())]
        );
        return reject_claim("owner DID not registered");
    }

    let token = TokenId::new(data.token_id);

    // Authorization:
    // - Rewards-module assets (pure AssetLaunch): require spend-delegate match.
    //   These have no `token_contracts` row; balances live in sled alone and
    //   `apply_token_transfer` does not need a contract object.
    // - Legacy TokenContract path: require token_contracts row + creator signer.
    if let Some(rewards_state) = mutator.get_rewards_module_state(&data.token_id)? {
        if data.from != rewards_state.spend_delegate_key_id {
            warn!(
                "RewardClaim rejected at height {}: signer {} is not spend delegate {} for token {}",
                block_height,
                hex::encode(data.from),
                hex::encode(rewards_state.spend_delegate_key_id),
                hex::encode(data.token_id)
            );
            return reject_claim("signer is not on-chain spend delegate");
        }
    } else {
        let contract = match mutator.get_token_contract(&token)? {
            Some(c) => c,
            None => {
                warn!(
                    "RewardClaim rejected at height {}: token contract not found",
                    block_height
                );
                return reject_claim("token contract not found");
            }
        };
        if contract.creator.key_id != data.from {
            warn!(
                "RewardClaim rejected at height {}: signer is not token creator (legacy path)",
                block_height
            );
            return reject_claim("signer is not authorized token creator");
        }
    }

    // Day/week bucketing rejects chrono-unrepresentable timestamps. On the apply
    // path this is defence-in-depth only: `block_validate::validate_timestamp`
    // already bounds `block_timestamp` to `now + max_future_timestamp` (default
    // 2h) and enforces monotonicity, so a validated block cannot reach the
    // ~8.2e12 chrono ceiling. Safety is therefore coupled to that config staying
    // far below chrono's range — not to these helpers being infallible.
    let date = utc_date_from_ts(block_timestamp).map_err(TxApplyError::RewardClaimDropped)?;
    let week = iso_week_from_ts(block_timestamp).map_err(TxApplyError::RewardClaimDropped)?;
    let today_ord =
        utc_day_ordinal_from_ts(block_timestamp).map_err(TxApplyError::RewardClaimDropped)?;
    let token_id = &data.token_id;

    let mut streak_day = 1u32;
    if data.event == RewardEventKind::DailyCheckin {
        let streak_storage_key = streak_key(token_id, &data.owner_did);
        let streak = mutator
            .get_bubl_reward_streak(&streak_storage_key)?
            .unwrap_or_default();
        streak_day = if streak.last_day == today_ord - 1 {
            streak.current_streak.saturating_add(1)
        } else {
            1
        };
    }

    let policy = resolve_rewards_policy(mutator, data.token_id)?;
    let policy_event = reward_event_to_policy_event(data.event);
    let expected = expected_amount_for_trigger(&policy, policy_event, streak_day);
    let expected = match expected {
        Some(v) => v,
        None => {
            warn!(
                "RewardClaim rejected at height {}: no enabled trigger for {:?}",
                block_height, data.event
            );
            return reject_claim(format!("no enabled policy trigger for {:?}", data.event));
        }
    };
    if data.amount != expected {
        warn!(
            "RewardClaim rejected at height {}: amount {} != expected {} for {:?}",
            block_height, data.amount, expected, data.event
        );
        return reject_claim(format!(
            "amount {} does not match policy expected {} for {:?}",
            data.amount, expected, data.event
        ));
    }
    let partner_cap = weekly_partner_cap(&policy);

    match data.event {
        RewardEventKind::Welcome => {
            let welcome_key = welcome_claim_key(token_id, &data.owner_did);
            if mutator.get_bubl_reward_welcome(&welcome_key)?.is_some() {
                warn!(
                    "RewardClaim rejected at height {}: welcome already claimed for {}",
                    block_height,
                    &data.owner_did[..20.min(data.owner_did.len())]
                );
                return reject_claim("welcome already claimed");
            }
        }
        RewardEventKind::DailyCheckin | RewardEventKind::ActiveSession => {
            let key = daily_claim_key(token_id, &date, &data.owner_did, data.event);
            if mutator.get_bubl_reward_daily(&key)?.is_some() {
                warn!(
                    "RewardClaim rejected at height {}: daily claim already recorded ({})",
                    block_height, key
                );
                return reject_claim(format!("{:?} already claimed for {}", data.event, date));
            }
        }
        RewardEventKind::NewPartner => {
            let peer = match data.peer_did.as_deref() {
                Some(p) if !p.is_empty() && p != data.owner_did => p,
                _ => {
                    warn!(
                        "RewardClaim rejected at height {}: invalid peer_did",
                        block_height
                    );
                    return reject_claim("invalid peer_did");
                }
            };
            if key_id_from_did(peer).is_none() {
                warn!(
                    "RewardClaim rejected at height {}: peer_did format invalid",
                    block_height
                );
                return reject_claim("peer_did format invalid");
            }
            let slot_key = partner_claim_key(token_id, &week, &data.owner_did, peer);
            if mutator.get_bubl_reward_partner(&slot_key)?.is_some() {
                warn!(
                    "RewardClaim rejected at height {}: partner already counted ({})",
                    block_height, slot_key
                );
                return reject_claim("partner already counted this week");
            }
            let count_key = partner_count_key(token_id, &week, &data.owner_did);
            let count = mutator.get_bubl_reward_partner_count(&count_key)?.unwrap_or(0);
            if partner_cap == 0 || count >= partner_cap {
                warn!(
                    "RewardClaim rejected at height {}: weekly partner cap reached",
                    block_height
                );
                return reject_claim("weekly partner cap reached");
            }
        }
    }

    let from = Address::new(data.from);
    let to = Address::new(data.recipient_key_id);
    let expected_nonce = mutator.get_token_nonce(&token, &from)?;
    if data.nonce < expected_nonce {
        warn!(
            "RewardClaim dropped at height {}: nonce replay (expected {})",
            block_height, expected_nonce
        );
        return Err(TxApplyError::ReplayDropped {
            expected: expected_nonce,
            actual: data.nonce,
        });
    }
    if data.nonce > expected_nonce {
        return reject_claim(format!(
            "RewardClaim nonce gap: expected {}, got {}",
            expected_nonce, data.nonce
        ));
    }

    let cbe_token_id_arr = crate::Blockchain::derive_cbe_token_id_pub();
    let fee_bps = if data.token_id == cbe_token_id_arr {
        0u16
    } else {
        crate::contracts::tokens::constants::SOV_FEE_RATE_BPS
    };

    if crate::contracts::sovereign_asset::economic_rules_active(block_height) {
        if let Err(TxApplyError::InsufficientBalance { have, need, .. }) =
            tx_apply::apply_token_transfer(
                mutator,
                &token,
                &from,
                &to,
                data.amount,
                fee_bps,
                fee_sink,
            )
        {
            return reject_claim(format!(
                "insufficient reward liquidity: have {have}, need {need}"
            ));
        }
    } else {
        tx_apply::apply_token_transfer(
            mutator,
            &token,
            &from,
            &to,
            data.amount,
            fee_bps,
            fee_sink,
        )?;
    }
    mutator.increment_token_nonce(&token, &from)?;

    match data.event {
        RewardEventKind::Welcome => {
            let welcome_key = welcome_claim_key(token_id, &data.owner_did);
            mutator.put_bubl_reward_welcome(&welcome_key, block_height)?;
        }
        RewardEventKind::DailyCheckin => {
            let key = daily_claim_key(token_id, &date, &data.owner_did, data.event);
            mutator.put_bubl_reward_daily(&key, block_height)?;
            let streak_storage_key = streak_key(token_id, &data.owner_did);
            let mut streak = mutator
                .get_bubl_reward_streak(&streak_storage_key)?
                .unwrap_or_default();
            streak.last_day = today_ord;
            streak.current_streak = streak_day;
            if streak_day > streak.longest_streak {
                streak.longest_streak = streak_day;
            }
            mutator.put_bubl_reward_streak(&streak_storage_key, &streak)?;
        }
        RewardEventKind::ActiveSession => {
            let key = daily_claim_key(token_id, &date, &data.owner_did, data.event);
            mutator.put_bubl_reward_daily(&key, block_height)?;
        }
        RewardEventKind::NewPartner => {
            let peer = data.peer_did.as_deref().expect("validated above");
            let slot_key = partner_claim_key(token_id, &week, &data.owner_did, peer);
            mutator.put_bubl_reward_partner(&slot_key, block_height)?;
            let count_key = partner_count_key(token_id, &week, &data.owner_did);
            let count = mutator.get_bubl_reward_partner_count(&count_key)?.unwrap_or(0);
            mutator.put_bubl_reward_partner_count(&count_key, count.saturating_add(1))?;
        }
    }

    Ok(Some(TokenTransferOutcome {
        token,
        from,
        to,
        amount: data.amount,
    }))
}