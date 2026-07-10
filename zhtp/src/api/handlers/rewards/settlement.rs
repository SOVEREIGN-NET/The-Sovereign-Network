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