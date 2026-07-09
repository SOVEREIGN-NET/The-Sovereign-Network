//! On-chain BUBL reward claim application (policy-backed eligibility + token transfer).

use crate::execution::errors::{TxApplyError, TxApplyResult};
use crate::execution::executor::TokenTransferOutcome;
use crate::execution::tx_apply::{self, StateMutator};
use crate::rewards_policy::{expected_amount_for_trigger, legacy_bubl_policy, weekly_partner_cap};
use crate::storage::{Address, TokenId};
use crate::transaction::reward_claim::{
    bubl_token_id, canonical_owner_did, daily_claim_key, iso_week_from_ts, key_id_from_did,
    partner_claim_key, partner_count_key, reward_event_to_policy_event, utc_date_from_ts,
    utc_day_ordinal_from_ts, RewardClaimData, RewardEventKind,
};

fn reject_claim(reason: impl Into<String>) -> TxApplyResult<Option<TokenTransferOutcome>> {
    Err(TxApplyError::InvalidType(reason.into()))
}

/// Apply a `RewardClaim` inside the executor block window.
///
/// Ineligible or invalid claims return `Err` so the tx is not committed as a
/// silent no-op (review #2832 P1).
pub fn apply_reward_claim(
    mutator: &StateMutator<'_>,
    data: &RewardClaimData,
    block_height: u64,
    block_timestamp: u64,
    fee_sink: &Address,
) -> TxApplyResult<Option<TokenTransferOutcome>> {
    if data.token_id != bubl_token_id() {
        return reject_claim("RewardClaim is only valid for the canonical BUBL token_id");
    }

    if data.amount == 0 {
        return reject_claim("RewardClaim amount must be greater than 0");
    }

    let owner_did = canonical_owner_did(&data.owner_did)
        .ok_or_else(|| TxApplyError::InvalidType("invalid owner_did".into()))?;

    if key_id_from_did(&owner_did) != Some(data.recipient_key_id) {
        return reject_claim("recipient_key_id does not match owner_did");
    }

    let did_hash = crate::types::hash::blake3_hash(owner_did.as_bytes());
    let did_hash_arr = did_hash.as_array();
    if mutator.get_identity(&did_hash_arr)?.is_none() {
        return reject_claim(format!(
            "DID {} not registered",
            &owner_did[..20.min(owner_did.len())]
        ));
    }

    let token = TokenId::new(data.token_id);

    let contract = match mutator.get_token_contract(&token)? {
        Some(c) => c,
        None => return reject_claim("token contract not found"),
    };

    if contract.creator.key_id != data.from {
        return reject_claim("signer is not token creator");
    }

    let policy = legacy_bubl_policy();
    let date = utc_date_from_ts(block_timestamp);
    let week = iso_week_from_ts(block_timestamp);
    let today_ord = utc_day_ordinal_from_ts(block_timestamp);

    let mut streak_day = 1u32;
    if data.event == RewardEventKind::DailyCheckin {
        let streak = mutator
            .get_bubl_reward_streak(&owner_did)?
            .unwrap_or_default();
        streak_day = if streak.last_day == today_ord - 1 {
            streak.current_streak.saturating_add(1)
        } else {
            1
        };
    }

    let policy_event = reward_event_to_policy_event(data.event);
    let expected = expected_amount_for_trigger(&policy, policy_event, streak_day)
        .ok_or_else(|| TxApplyError::InvalidType("no enabled policy trigger for event".into()))?;
    if data.amount != expected {
        return reject_claim(format!(
            "amount {} != expected {} for {:?}",
            data.amount, expected, data.event
        ));
    }

    let partner_cap = weekly_partner_cap(&policy);

    match data.event {
        RewardEventKind::Welcome => {
            if mutator.get_bubl_reward_welcome(&owner_did)?.is_some() {
                return reject_claim("welcome already claimed");
            }
        }
        RewardEventKind::DailyCheckin | RewardEventKind::ActiveSession => {
            let key = daily_claim_key(&date, &owner_did, data.event);
            if mutator.get_bubl_reward_daily(&key)?.is_some() {
                return reject_claim(format!("daily claim already recorded ({key})"));
            }
        }
        RewardEventKind::NewPartner => {
            let peer = match data.peer_did.as_deref().and_then(canonical_owner_did) {
                Some(p) if p != owner_did => p,
                _ => return reject_claim("invalid peer_did"),
            };
            let slot_key = partner_claim_key(&week, &owner_did, &peer);
            if mutator.get_bubl_reward_partner(&slot_key)?.is_some() {
                return reject_claim(format!("partner already counted ({slot_key})"));
            }
            let count_key = partner_count_key(&week, &owner_did);
            let count = mutator.get_bubl_reward_partner_count(&count_key)?.unwrap_or(0);
            if partner_cap == 0 || count >= partner_cap {
                return reject_claim("weekly partner cap reached");
            }
        }
    }

    let from = Address::new(data.from);
    let to = Address::new(data.recipient_key_id);
    let expected_nonce = mutator.get_token_nonce(&token, &from)?;
    if data.nonce < expected_nonce {
        return reject_claim(format!("nonce replay (expected {expected_nonce})"));
    }
    if data.nonce > expected_nonce {
        return reject_claim(format!(
            "nonce gap: expected {expected_nonce}, got {}",
            data.nonce
        ));
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
            mutator.put_bubl_reward_welcome(&owner_did, block_height)?;
        }
        RewardEventKind::DailyCheckin => {
            let key = daily_claim_key(&date, &owner_did, data.event);
            mutator.put_bubl_reward_daily(&key, block_height)?;
            let mut streak = mutator
                .get_bubl_reward_streak(&owner_did)?
                .unwrap_or_default();
            streak.last_day = today_ord;
            streak.current_streak = streak_day;
            if streak_day > streak.longest_streak {
                streak.longest_streak = streak_day;
            }
            mutator.put_bubl_reward_streak(&owner_did, &streak)?;
        }
        RewardEventKind::ActiveSession => {
            let key = daily_claim_key(&date, &owner_did, data.event);
            mutator.put_bubl_reward_daily(&key, block_height)?;
        }
        RewardEventKind::NewPartner => {
            let peer = data
                .peer_did
                .as_deref()
                .and_then(canonical_owner_did)
                .expect("validated above");
            let slot_key = partner_claim_key(&week, &owner_did, &peer);
            mutator.put_bubl_reward_partner(&slot_key, block_height)?;
            let count_key = partner_count_key(&week, &owner_did);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::errors::TxApplyError;
    use crate::execution::tx_apply::StateMutator;
    use crate::integration::crypto_integration::PublicKey;
    use crate::storage::{
        Address, AddressExt, BlockchainStore, IdentityConsensus, SledStore, TokenId,
    };
    use crate::transaction::reward_claim::{REWARD_WELCOME_ATOMS, bubl_token_id};
    use std::sync::Arc;

    fn fresh_store() -> Arc<SledStore> {
        Arc::new(SledStore::open_temporary().unwrap())
    }

    fn test_public_key(key_id: [u8; 32]) -> PublicKey {
        PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id,
        }
    }

    fn seed_reward_claim_prereqs(store: &SledStore, creator: [u8; 32], owner_did: &str) {
        let token_id = TokenId::new(bubl_token_id());
        store
            .force_set_token_balances(&[(
                token_id,
                Address::new(creator),
                REWARD_WELCOME_ATOMS.saturating_mul(2),
            )])
            .unwrap();

        store.begin_block(0).unwrap();
        let mutator = StateMutator::new(store);
        let did_hash = crate::types::hash::blake3_hash(owner_did.as_bytes()).as_array();
        store
            .put_identity(
                &did_hash,
                &IdentityConsensus {
                    did_hash,
                    ..Default::default()
                },
            )
            .unwrap();
        let token = crate::contracts::TokenContract::new_custom(
            "Bubble".to_string(),
            "BUBL".to_string(),
            0,
            test_public_key(creator),
        );
        mutator.put_token_contract(&token).unwrap();
        store
            .set_token_nonce(&token_id, &Address::new(creator), 0)
            .unwrap();
        store.commit_block().unwrap();
    }

    fn welcome_claim_data(creator: [u8; 32], owner_did: &str) -> RewardClaimData {
        RewardClaimData {
            event: RewardEventKind::Welcome,
            owner_did: owner_did.to_string(),
            recipient_key_id: creator,
            token_id: bubl_token_id(),
            from: creator,
            amount: REWARD_WELCOME_ATOMS,
            nonce: 0,
            peer_did: None,
        }
    }

    #[test]
    fn rejects_non_bubl_token_id() {
        let store = fresh_store();
        let creator = [0xAAu8; 32];
        let owner_did = format!("did:zhtp:{}", hex::encode(creator));
        seed_reward_claim_prereqs(store.as_ref(), creator, &owner_did);

        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let mut data = welcome_claim_data(creator, &owner_did);
        data.token_id = [0xFF; 32];

        let err = apply_reward_claim(
            &mutator,
            &data,
            1,
            1_700_000_000,
            &Address::ZERO,
        )
        .unwrap_err();
        assert!(matches!(err, TxApplyError::InvalidType(_)));
        store.rollback_block().unwrap();
    }

    #[test]
    fn rejects_welcome_when_already_claimed() {
        let store = fresh_store();
        let creator = [0xBBu8; 32];
        let owner_did = format!("did:zhtp:{}", hex::encode(creator));
        seed_reward_claim_prereqs(store.as_ref(), creator, &owner_did);

        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        mutator.put_bubl_reward_welcome(&owner_did, 1).unwrap();

        let data = welcome_claim_data(creator, &owner_did);
        let err = apply_reward_claim(
            &mutator,
            &data,
            1,
            1_700_000_000,
            &Address::ZERO,
        )
        .unwrap_err();
        assert!(matches!(err, TxApplyError::InvalidType(msg) if msg.contains("welcome already claimed")));
        store.rollback_block().unwrap();
    }

    #[test]
    fn rejects_unregistered_did() {
        let store = fresh_store();
        let creator = [0xCCu8; 32];
        let owner_did = format!("did:zhtp:{}", hex::encode(creator));

        store.begin_block(0).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let token = crate::contracts::TokenContract::new_custom(
            "Bubble".to_string(),
            "BUBL".to_string(),
            0,
            test_public_key(creator),
        );
        mutator.put_token_contract(&token).unwrap();

        let data = welcome_claim_data(creator, &owner_did);
        let err = apply_reward_claim(
            &mutator,
            &data,
            1,
            1_700_000_000,
            &Address::ZERO,
        )
        .unwrap_err();
        assert!(matches!(err, TxApplyError::InvalidType(msg) if msg.contains("not registered")));
        store.rollback_block().unwrap();
    }
}