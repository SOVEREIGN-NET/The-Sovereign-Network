//! N2 hybrid settlement (Path C): node attests eligibility and submits
//! `RewardClaim` txs signed by the spend delegate (Q4 spend-delegate model).

use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::RwLock;

use lib_blockchain::transaction::reward_claim::{RewardClaimData, RewardEventKind, REWARD_CLAIM_MEMO};
use lib_blockchain::transaction::Transaction;
use lib_blockchain::Blockchain;

use lib_crypto::Signature;

use super::TreasuryConfig;

/// Planned claim after a single chain snapshot read (eligibility + policy amount).
pub struct RewardClaimPlan {
    pub amount: u128,
    pub streak_day: Option<u32>,
}

/// Read eligibility and policy-derived amount from consensus state.
pub fn plan_reward_claim(
    bc: &Blockchain,
    token_id: &[u8; 32],
    did: &str,
    event: RewardEventKind,
    peer_did: Option<&str>,
) -> Result<RewardClaimPlan, String> {
    let date = lib_blockchain::transaction::reward_claim::utc_date_from_ts(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let week = lib_blockchain::transaction::reward_claim::iso_week_from_ts(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let today_ord = lib_blockchain::transaction::reward_claim::utc_day_ordinal_from_ts(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    match event {
        RewardEventKind::Welcome => {
            if bc.reward_welcome_claimed(token_id, did) {
                return Err("welcome_already_claimed".into());
            }
        }
        RewardEventKind::DailyCheckin => {
            if bc.reward_daily_claimed(token_id, &date, did, event) {
                return Err("checkin_already_claimed_today".into());
            }
        }
        RewardEventKind::ActiveSession => {
            if bc.reward_daily_claimed(token_id, &date, did, event) {
                return Err("session_already_claimed_today".into());
            }
        }
        RewardEventKind::NewPartner => {
            let peer = peer_did.filter(|p| !p.is_empty() && *p != did).ok_or_else(|| {
                "invalid peer_did".to_string()
            })?;
            if bc.reward_partner_claimed(token_id, &week, did, peer) {
                return Err("partner_already_counted_this_week".into());
            }
            let cap = bc.reward_weekly_partner_cap(token_id);
            let count = bc.reward_partners_this_week(token_id, &week, did);
            if cap > 0 && count >= cap {
                return Err("weekly_partner_cap_reached".into());
            }
        }
    }

    let streak_day = if event == RewardEventKind::DailyCheckin {
        let streak = bc.reward_streak(token_id, did);
        let day = if streak.last_day == today_ord - 1 {
            streak.current_streak.saturating_add(1)
        } else {
            1
        };
        Some(day)
    } else {
        None
    };

    let amount = bc
        .reward_expected_amount(token_id, event, streak_day.unwrap_or(1))
        .ok_or_else(|| "rewards policy unavailable for this asset".to_string())?;

    Ok(RewardClaimPlan { amount, streak_day })
}

/// Build, sign, and enqueue a `RewardClaim` for mempool (not `TokenTransfer`).
pub async fn submit_reward_claim(
    blockchain: &Arc<RwLock<Blockchain>>,
    treasury: &TreasuryConfig,
    did: &str,
    recipient_key_id: [u8; 32],
    event: RewardEventKind,
    amount: u128,
    peer_did: Option<String>,
) -> Result<String> {
    let nonce = {
        let bc = blockchain.read().await;
        bc.token_nonce(&treasury.rewards_asset_id, &treasury.signer_key_id)
            .map_err(|e| anyhow!("nonce lookup failed: {e}"))?
    };

    let data = RewardClaimData {
        event,
        owner_did: did.to_string(),
        recipient_key_id,
        token_id: treasury.rewards_asset_id,
        from: treasury.signer_key_id,
        amount,
        nonce,
        peer_did,
    };

    let mut tx = Transaction::new_reward_claim_with_chain_id(
        super::chain_id_from_env(),
        data,
        Signature::default(),
        REWARD_CLAIM_MEMO.to_vec(),
    );
    let sig = treasury
        .keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| anyhow!("rewards sign failed: {e}"))?;
    tx.signature = sig;

    let tx_hash = hex::encode(tx.hash().as_bytes());
    let mut bc = blockchain.write().await;
    bc.add_pending_transaction(tx)
        .map_err(|e| anyhow!("Failed to submit reward claim: {e}"))?;
    Ok(tx_hash)
}