//! BUBL reward eligibility facades (sled-first reads).

use crate::transaction::reward_claim::{
    daily_claim_key, partner_claim_key, partner_count_key, RewardEventKind, RewardStreakRecord,
};

impl crate::blockchain::Blockchain {
    /// Whether this DID has already claimed the one-shot welcome reward on-chain.
    pub fn bubl_reward_welcome_claimed(&self, did: &str) -> bool {
        if let Some(store) = self.get_store() {
            match store.get_bubl_reward_welcome(did) {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "bubl_reward_welcome_claimed: sled read failed; failing closed"
                    );
                    return true;
                }
            }
        }
        false
    }

    /// Whether a daily reward event was already claimed for `did` on `date` (UTC).
    pub fn bubl_reward_daily_claimed(
        &self,
        date: &str,
        did: &str,
        event: RewardEventKind,
    ) -> bool {
        let key = daily_claim_key(date, did, event);
        if let Some(store) = self.get_store() {
            match store.get_bubl_reward_daily(&key) {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "bubl_reward_daily_claimed: sled read failed; failing closed"
                    );
                    return true;
                }
            }
        }
        false
    }

    pub fn bubl_reward_partner_claimed(&self, week: &str, did: &str, peer_did: &str) -> bool {
        let key = partner_claim_key(week, did, peer_did);
        if let Some(store) = self.get_store() {
            match store.get_bubl_reward_partner(&key) {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "bubl_reward_partner_claimed: sled read failed; failing closed"
                    );
                    return true;
                }
            }
        }
        false
    }

    pub fn bubl_reward_partners_this_week(&self, week: &str, did: &str) -> u32 {
        let key = partner_count_key(week, did);
        if let Some(store) = self.get_store() {
            match store.get_bubl_reward_partner_count(&key) {
                Ok(Some(c)) => return c,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "bubl_reward_partners_this_week: sled read failed"
                    );
                }
            }
        }
        0
    }

    pub fn bubl_reward_streak(&self, did: &str) -> RewardStreakRecord {
        if let Some(store) = self.get_store() {
            match store.get_bubl_reward_streak(did) {
                Ok(Some(s)) => return s,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "bubl_reward_streak: sled read failed");
                }
            }
        }
        RewardStreakRecord::default()
    }
}