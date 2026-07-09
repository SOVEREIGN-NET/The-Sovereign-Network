//! On-chain BUBL reward claim application (eligibility + token transfer).

use tracing::warn;

use crate::execution::errors::{TxApplyError, TxApplyResult};
use crate::execution::executor::TokenTransferOutcome;
use crate::execution::tx_apply::{self, StateMutator};
use crate::storage::{Address, TokenId};
use crate::transaction::reward_claim::{
    daily_claim_key, expected_amount_for_event, iso_week_from_ts, key_id_from_did,
    partner_claim_key, partner_count_key, utc_date_from_ts, utc_day_ordinal_from_ts,
    RewardClaimData, RewardEventKind, WEEKLY_PARTNER_CAP,
};
/// Apply a `RewardClaim` inside the executor block window.
///
/// Returns `Ok(None)` when the claim is ineligible (tx is a no-op, block continues).
/// Returns `Ok(Some(outcome))` on success.
pub fn apply_reward_claim(
    mutator: &StateMutator<'_>,
    data: &RewardClaimData,
    block_height: u64,
    block_timestamp: u64,
    fee_sink: &Address,
) -> TxApplyResult<Option<TokenTransferOutcome>> {
    if data.amount == 0 {
        warn!("RewardClaim rejected at height {}: zero amount", block_height);
        return Ok(None);
    }

    if key_id_from_did(&data.owner_did) != Some(data.recipient_key_id) {
        warn!(
            "RewardClaim rejected at height {}: recipient_key_id does not match owner_did",
            block_height
        );
        return Ok(None);
    }

    let did_hash = crate::types::hash::blake3_hash(data.owner_did.as_bytes());
    let did_hash_arr = did_hash.as_array();
    if mutator.get_identity(&did_hash_arr)?.is_none() {
        warn!(
            "RewardClaim rejected at height {}: DID {} not registered",
            block_height,
            &data.owner_did[..20.min(data.owner_did.len())]
        );
        return Ok(None);
    }

    let token = TokenId::new(data.token_id);

    let contract = match mutator.get_token_contract(&token)? {
        Some(c) => c,
        None => {
            warn!(
                "RewardClaim rejected at height {}: token contract not found",
                block_height
            );
            return Ok(None);
        }
    };

    if contract.creator.key_id != data.from {
        warn!(
            "RewardClaim rejected at height {}: signer is not token creator",
            block_height
        );
        return Ok(None);
    }

    let date = utc_date_from_ts(block_timestamp);
    let week = iso_week_from_ts(block_timestamp);
    let today_ord = utc_day_ordinal_from_ts(block_timestamp);

    let mut streak_day = 1u32;
    if data.event == RewardEventKind::DailyCheckin {
        let streak = mutator
            .get_bubl_reward_streak(&data.owner_did)?
            .unwrap_or_default();
        streak_day = if streak.last_day == today_ord - 1 {
            streak.current_streak.saturating_add(1)
        } else {
            1
        };
    }

    let expected = expected_amount_for_event(data.event, streak_day);
    if data.amount != expected {
        warn!(
            "RewardClaim rejected at height {}: amount {} != expected {} for {:?}",
            block_height, data.amount, expected, data.event
        );
        return Ok(None);
    }

    match data.event {
        RewardEventKind::Welcome => {
            if mutator.get_bubl_reward_welcome(&data.owner_did)?.is_some() {
                warn!(
                    "RewardClaim rejected at height {}: welcome already claimed for {}",
                    block_height,
                    &data.owner_did[..20.min(data.owner_did.len())]
                );
                return Ok(None);
            }
        }
        RewardEventKind::DailyCheckin | RewardEventKind::ActiveSession => {
            let key = daily_claim_key(&date, &data.owner_did, data.event);
            if mutator.get_bubl_reward_daily(&key)?.is_some() {
                warn!(
                    "RewardClaim rejected at height {}: daily claim already recorded ({})",
                    block_height, key
                );
                return Ok(None);
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
                    return Ok(None);
                }
            };
            if key_id_from_did(peer).is_none() {
                warn!(
                    "RewardClaim rejected at height {}: peer_did format invalid",
                    block_height
                );
                return Ok(None);
            }
            let slot_key = partner_claim_key(&week, &data.owner_did, peer);
            if mutator.get_bubl_reward_partner(&slot_key)?.is_some() {
                warn!(
                    "RewardClaim rejected at height {}: partner already counted ({})",
                    block_height, slot_key
                );
                return Ok(None);
            }
            let count_key = partner_count_key(&week, &data.owner_did);
            let count = mutator.get_bubl_reward_partner_count(&count_key)?.unwrap_or(0);
            if count >= WEEKLY_PARTNER_CAP {
                warn!(
                    "RewardClaim rejected at height {}: weekly partner cap reached",
                    block_height
                );
                return Ok(None);
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
        return Ok(None);
    }
    if data.nonce > expected_nonce {
        return Err(TxApplyError::InvalidType(format!(
            "RewardClaim nonce gap: expected {}, got {}",
            expected_nonce, data.nonce
        )));
    }

    let cbe_token_id_arr = crate::Blockchain::derive_cbe_token_id_pub();
    let fee_bps = if data.token_id == cbe_token_id_arr {
        0u16
    } else {
        crate::contracts::tokens::constants::SOV_FEE_RATE_BPS
    };

    tx_apply::apply_token_transfer(
        mutator,
        &token,
        &from,
        &to,
        data.amount,
        fee_bps,
        fee_sink,
    )?;
    mutator.increment_token_nonce(&token, &from)?;

    match data.event {
        RewardEventKind::Welcome => {
            mutator.put_bubl_reward_welcome(&data.owner_did, block_height)?;
        }
        RewardEventKind::DailyCheckin => {
            let key = daily_claim_key(&date, &data.owner_did, data.event);
            mutator.put_bubl_reward_daily(&key, block_height)?;
            let mut streak = mutator
                .get_bubl_reward_streak(&data.owner_did)?
                .unwrap_or_default();
            streak.last_day = today_ord;
            streak.current_streak = streak_day;
            if streak_day > streak.longest_streak {
                streak.longest_streak = streak_day;
            }
            mutator.put_bubl_reward_streak(&data.owner_did, &streak)?;
        }
        RewardEventKind::ActiveSession => {
            let key = daily_claim_key(&date, &data.owner_did, data.event);
            mutator.put_bubl_reward_daily(&key, block_height)?;
        }
        RewardEventKind::NewPartner => {
            let peer = data.peer_did.as_deref().expect("validated above");
            let slot_key = partner_claim_key(&week, &data.owner_did, peer);
            mutator.put_bubl_reward_partner(&slot_key, block_height)?;
            let count_key = partner_count_key(&week, &data.owner_did);
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