//! Reward eligibility facades — sled/consensus tree reads (authoritative).

use serde::{Deserialize, Serialize};

use crate::rewards_policy::{
    expected_amount_for_trigger, legacy_bubl_policy, policy_hash, validate_rewards_policy,
    weekly_partner_cap, RewardsPolicyV1,
};
use crate::transaction::reward_claim::{
    daily_claim_key, partner_claim_key, partner_count_key, reward_event_to_policy_event,
    streak_key, welcome_claim_key, RewardEventKind, RewardStreakRecord,
};
use crate::types::TransactionType;

/// Lifetime reward counters derived from on-chain eligibility trees (N4).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RewardLifetimeStats {
    pub total_earned: u128,
    pub welcome_claimed: bool,
    pub checkin_count: u64,
    pub session_count: u64,
    pub partner_count: u64,
    pub current_streak: u32,
    pub longest_streak: u32,
}

/// One committed `RewardClaim` for API history (newest-first pages).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardHistoryEntry {
    pub at: u64,
    /// Monotonic tiebreaker: `height * 10_000 + tx_index`.
    pub seq: u64,
    pub event: String,
    pub amount: u128,
    pub tx_hash: String,
    pub meta_streak_day: Option<u32>,
    pub meta_peer_did: Option<String>,
}

impl crate::blockchain::Blockchain {
    /// Resolve the rewards policy document for `token_id` (on-chain module or legacy BUBL).
    pub fn rewards_policy_for_token(&self, token_id: &[u8; 32]) -> Option<RewardsPolicyV1> {
        if let Some(store) = self.get_store() {
            if let Ok(Some(state)) = store.get_rewards_module_state(token_id) {
                if let Ok(Some(doc)) = store.get_rewards_policy_document(&state.policy_hash) {
                    if let Ok(policy) = validate_rewards_policy(&doc) {
                        if let Ok(hash) = policy_hash(&policy) {
                            if hash.as_array() == state.policy_hash {
                                return Some(policy);
                            }
                        }
                    }
                }
            }
        }
        if crate::contracts::utils::generate_custom_token_id("Bubble", "BUBL") == *token_id {
            return Some(legacy_bubl_policy());
        }
        None
    }

    pub fn reward_welcome_claimed(&self, token_id: &[u8; 32], did: &str) -> bool {
        let key = welcome_claim_key(token_id, did);
        self.reward_tree_has_height(|store| store.get_bubl_reward_welcome(&key))
    }

    pub fn reward_daily_claimed(
        &self,
        token_id: &[u8; 32],
        date: &str,
        did: &str,
        event: RewardEventKind,
    ) -> bool {
        let key = daily_claim_key(token_id, date, did, event);
        self.reward_tree_has_height(|store| store.get_bubl_reward_daily(&key))
    }

    pub fn reward_partner_claimed(
        &self,
        token_id: &[u8; 32],
        week: &str,
        did: &str,
        peer_did: &str,
    ) -> bool {
        let key = partner_claim_key(token_id, week, did, peer_did);
        self.reward_tree_has_height(|store| store.get_bubl_reward_partner(&key))
    }

    pub fn reward_partners_this_week(&self, token_id: &[u8; 32], week: &str, did: &str) -> u32 {
        let key = partner_count_key(token_id, week, did);
        if let Some(store) = self.get_store() {
            match store.get_bubl_reward_partner_count(&key) {
                Ok(Some(c)) => return c,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "reward_partners_this_week: sled read failed");
                }
            }
        }
        0
    }

    pub fn reward_streak(&self, token_id: &[u8; 32], did: &str) -> RewardStreakRecord {
        let key = streak_key(token_id, did);
        if let Some(store) = self.get_store() {
            match store.get_bubl_reward_streak(&key) {
                Ok(Some(s)) => return s,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "reward_streak: sled read failed");
                }
            }
        }
        RewardStreakRecord::default()
    }

    pub fn reward_weekly_partner_cap(&self, token_id: &[u8; 32]) -> u32 {
        self.rewards_policy_for_token(token_id)
            .map(|p| weekly_partner_cap(&p))
            .unwrap_or(0)
    }

    pub fn reward_expected_amount(
        &self,
        token_id: &[u8; 32],
        event: RewardEventKind,
        streak_day: u32,
    ) -> Option<u128> {
        let policy = self.rewards_policy_for_token(token_id)?;
        let policy_event = reward_event_to_policy_event(event);
        expected_amount_for_trigger(&policy, policy_event, streak_day)
    }

    pub fn reward_checkin_amount_for_streak(
        &self,
        token_id: &[u8; 32],
        streak_day: u32,
    ) -> Option<u128> {
        self.reward_expected_amount(token_id, RewardEventKind::DailyCheckin, streak_day)
    }

    /// Aggregate per-DID reward counters from consensus trees (no node-local sled).
    pub fn reward_lifetime_stats(&self, token_id: &[u8; 32], did: &str) -> RewardLifetimeStats {
        let welcome_claimed = self.reward_welcome_claimed(token_id, did);
        let streak = self.reward_streak(token_id, did);
        let checkin_count = self.count_reward_daily_events(token_id, did, RewardEventKind::DailyCheckin);
        let session_count =
            self.count_reward_daily_events(token_id, did, RewardEventKind::ActiveSession);
        let partner_count = self.count_reward_partner_slots(token_id, did);

        let mut total_earned = 0u128;
        if welcome_claimed {
            if let Some(amount) = self.reward_expected_amount(token_id, RewardEventKind::Welcome, 1)
            {
                total_earned = total_earned.saturating_add(amount);
            }
        }
        if let Some(checkin_amount) =
            self.reward_expected_amount(token_id, RewardEventKind::DailyCheckin, 1)
        {
            total_earned =
                total_earned.saturating_add(checkin_amount.saturating_mul(checkin_count as u128));
        }
        if let Some(session_amount) =
            self.reward_expected_amount(token_id, RewardEventKind::ActiveSession, 1)
        {
            total_earned =
                total_earned.saturating_add(session_amount.saturating_mul(session_count as u128));
        }
        if let Some(partner_amount) =
            self.reward_expected_amount(token_id, RewardEventKind::NewPartner, 1)
        {
            total_earned =
                total_earned.saturating_add(partner_amount.saturating_mul(partner_count as u128));
        }

        RewardLifetimeStats {
            total_earned,
            welcome_claimed,
            checkin_count,
            session_count,
            partner_count,
            current_streak: streak.current_streak,
            longest_streak: streak.longest_streak,
        }
    }

    /// Scan committed blocks for `RewardClaim` txs credited to `did` (newest first).
    pub fn reward_claim_history(
        &self,
        token_id: &[u8; 32],
        did: &str,
        limit: usize,
        cursor_seq: Option<u64>,
    ) -> (Vec<RewardHistoryEntry>, bool) {
        let mut page = Vec::with_capacity(limit.min(64));
        let mut has_more = false;
        let max_seq = cursor_seq.unwrap_or(u64::MAX);

        'blocks: for height in (0..self.block_count()).rev() {
            let Some(block) = self.get_block(height) else {
                continue;
            };
            let at = block.header.timestamp;
            for (tx_index, tx) in block.transactions.iter().enumerate().rev() {
                if tx.transaction_type != TransactionType::RewardClaim {
                    continue;
                }
                let Some(data) = tx.reward_claim_data() else {
                    continue;
                };
                if data.token_id != *token_id || data.owner_did != did {
                    continue;
                }
                let seq = height.saturating_mul(10_000).saturating_add(tx_index as u64);
                if seq >= max_seq {
                    continue;
                }
                if page.len() == limit {
                    has_more = true;
                    break 'blocks;
                }
                page.push(RewardHistoryEntry {
                    at,
                    seq,
                    event: data.event.as_str().to_string(),
                    amount: data.amount,
                    tx_hash: hex::encode(tx.hash().as_bytes()),
                    meta_streak_day: None,
                    meta_peer_did: data.peer_did.clone(),
                });
            }
        }

        (page, has_more)
    }

    fn count_reward_daily_events(
        &self,
        token_id: &[u8; 32],
        did: &str,
        event: RewardEventKind,
    ) -> u64 {
        let Some(store) = self.get_store() else {
            return 0;
        };
        let event_label = event.as_str();
        let Ok(rows) = store.iter_bubl_reward_daily() else {
            return 0;
        };
        let prefix = format!("{}|", hex::encode(token_id));
        rows.into_iter()
            .filter(|(key, _)| {
                key.starts_with(&prefix)
                    && key
                        .split('|')
                        .nth(2)
                        .is_some_and(|owner| owner == did)
                    && key
                        .split('|')
                        .nth(3)
                        .is_some_and(|ev| ev == event_label)
            })
            .count() as u64
    }

    fn count_reward_partner_slots(&self, token_id: &[u8; 32], did: &str) -> u64 {
        let Some(store) = self.get_store() else {
            return 0;
        };
        let Ok(rows) = store.iter_bubl_reward_partner() else {
            return 0;
        };
        let prefix = format!("{}|", hex::encode(token_id));
        rows.into_iter()
            .filter(|(key, _)| {
                key.starts_with(&prefix)
                    && key
                        .split('|')
                        .nth(2)
                        .is_some_and(|owner| owner == did)
            })
            .count() as u64
    }

    fn reward_tree_has_height<F>(&self, read: F) -> bool
    where
        F: FnOnce(
            &dyn crate::storage::BlockchainStore,
        ) -> crate::storage::StorageResult<Option<u64>>,
    {
        if let Some(store) = self.get_store() {
            match read(store.as_ref()) {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "reward eligibility read failed; failing closed");
                    return true;
                }
            }
        }
        false
    }
}

