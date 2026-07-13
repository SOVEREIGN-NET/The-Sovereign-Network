//! N2 hybrid settlement (Path C): node attests eligibility and submits
//! `RewardClaim` txs signed by the spend delegate (Q4 spend-delegate model).

use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::RwLock;

use lib_blockchain::transaction::reward_claim::{
    iso_week_from_ts, utc_date_from_ts, utc_day_ordinal_from_ts, RewardClaimData, RewardEventKind,
    REWARD_CLAIM_MEMO,
};
use lib_blockchain::transaction::Transaction;
use lib_blockchain::Blockchain;

use lib_crypto::Signature;

use super::TreasuryConfig;

const WEEKLY_PARTNER_CAP_FALLBACK: u32 = 5;

fn claim_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Planned claim after a single chain snapshot read (eligibility + policy amount).
pub struct RewardClaimPlan {
    pub amount: u128,
    pub streak_day: Option<u32>,
    pub partners_this_week: Option<u32>,
    pub weekly_cap: Option<u32>,
}

pub struct ClaimSpec {
    pub event: RewardEventKind,
    pub event_label: &'static str,
    pub peer_did: Option<String>,
    pub soft_fail_reasons: &'static [&'static str],
}

impl ClaimSpec {
    pub fn welcome() -> Self {
        Self {
            event: RewardEventKind::Welcome,
            event_label: "welcome",
            peer_did: None,
            soft_fail_reasons: &["welcome_already_claimed"],
        }
    }

    pub fn daily_checkin() -> Self {
        Self {
            event: RewardEventKind::DailyCheckin,
            event_label: "daily_checkin",
            peer_did: None,
            soft_fail_reasons: &["checkin_already_claimed_today"],
        }
    }

    pub fn active_session() -> Self {
        Self {
            event: RewardEventKind::ActiveSession,
            event_label: "active_session",
            peer_did: None,
            soft_fail_reasons: &["session_already_claimed_today"],
        }
    }

    pub fn new_partner(peer_did: String) -> Self {
        Self {
            event: RewardEventKind::NewPartner,
            event_label: "new_partner",
            peer_did: Some(peer_did),
            soft_fail_reasons: &[
                "partner_already_counted_this_week",
                "weekly_partner_cap_reached",
            ],
        }
    }
}

pub struct SubmittedClaim {
    pub tx_hash: String,
    pub plan: RewardClaimPlan,
}

pub enum ClaimFlowError {
    Ineligible { reason: String },
    Unavailable(String),
    SubmitFailed(String),
}

/// Read eligibility and policy-derived amount from consensus state.
pub fn plan_reward_claim(
    bc: &Blockchain,
    token_id: &[u8; 32],
    did: &str,
    spec: &ClaimSpec,
) -> Result<RewardClaimPlan, String> {
    match bc.owner_identity_registered_in_store(did) {
        Ok(true) => {}
        Ok(false) => return Err("owner_did_not_registered".into()),
        Err(_) => return Err("owner_did_not_registered".into()),
    }
    let ts = claim_unix_ts();
    let date = utc_date_from_ts(ts);
    let week = iso_week_from_ts(ts);
    let today_ord = utc_day_ordinal_from_ts(ts);

    match spec.event {
        RewardEventKind::Welcome => {
            if bc.reward_welcome_claimed(token_id, did) {
                return Err("welcome_already_claimed".into());
            }
        }
        RewardEventKind::DailyCheckin | RewardEventKind::ActiveSession => {
            if bc.reward_daily_claimed(token_id, &date, did, spec.event) {
                return Err(if spec.event == RewardEventKind::DailyCheckin {
                    "checkin_already_claimed_today"
                } else {
                    "session_already_claimed_today"
                }
                .into());
            }
        }
        RewardEventKind::NewPartner => {
            let peer = spec
                .peer_did
                .as_deref()
                .filter(|p| !p.is_empty() && *p != did)
                .ok_or_else(|| "invalid peer_did".to_string())?;
            if bc.reward_partner_claimed(token_id, &week, did, peer) {
                return Err("partner_already_counted_this_week".into());
            }
            let policy_cap = bc.reward_weekly_partner_cap(token_id);
            let weekly_cap = if policy_cap > 0 {
                policy_cap
            } else {
                WEEKLY_PARTNER_CAP_FALLBACK
            };
            let partners_this_week = bc.reward_partners_this_week(token_id, &week, did);
            if weekly_cap > 0 && partners_this_week >= weekly_cap {
                return Err("weekly_partner_cap_reached".into());
            }
            let amount = bc
                .reward_expected_amount(token_id, spec.event, 1)
                .ok_or_else(|| "rewards policy unavailable for this asset".to_string())?;
            return Ok(RewardClaimPlan {
                amount,
                streak_day: None,
                partners_this_week: Some(partners_this_week),
                weekly_cap: Some(weekly_cap),
            });
        }
    }

    let streak_day = if spec.event == RewardEventKind::DailyCheckin {
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
        .reward_expected_amount(token_id, spec.event, streak_day.unwrap_or(1))
        .ok_or_else(|| "rewards policy unavailable for this asset".to_string())?;

    Ok(RewardClaimPlan {
        amount,
        streak_day,
        partners_this_week: None,
        weekly_cap: None,
    })
}

/// Plan, sign, and enqueue a `RewardClaim` (single entry point for all event types).
pub async fn run_claim_flow(
    blockchain: &Arc<RwLock<Blockchain>>,
    treasury: &TreasuryConfig,
    did: &str,
    recipient_key_id: [u8; 32],
    spec: &ClaimSpec,
) -> Result<SubmittedClaim, ClaimFlowError> {
    let token_id = treasury.rewards_asset_id;
    let plan = {
        let bc = blockchain.read().await;
        plan_reward_claim(&bc, &token_id, did, spec).map_err(|reason| {
            if spec.soft_fail_reasons.contains(&reason.as_str()) {
                ClaimFlowError::Ineligible { reason }
            } else {
                ClaimFlowError::Unavailable(reason)
            }
        })?
    };

    let tx_hash = submit_reward_claim(
        blockchain,
        treasury,
        did,
        recipient_key_id,
        spec.event,
        plan.amount,
        spec.peer_did.clone(),
    )
    .await
    .map_err(|e| ClaimFlowError::SubmitFailed(e.to_string()))?;

    Ok(SubmittedClaim { tx_hash, plan })
}

async fn submit_reward_claim(
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