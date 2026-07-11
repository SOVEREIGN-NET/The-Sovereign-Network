//! Reward eligibility facades — sled/consensus tree reads (authoritative).

use crate::rewards_policy::{
    expected_amount_for_trigger, legacy_bubl_policy, policy_hash, validate_rewards_policy,
    weekly_partner_cap, RewardsPolicyV1,
};
use crate::transaction::reward_claim::{
    daily_claim_key, partner_claim_key, partner_count_key, reward_event_to_policy_event,
    streak_key, welcome_claim_key, RewardEventKind, RewardStreakRecord,
};

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

