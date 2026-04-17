//! Single minting path for all reward types.
//!
//! All reward processors call RewardMinter::mint() — no other code path
//! creates reward transactions.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use super::budget_tracker::RewardSource;

/// Single call site for creating reward transactions.
///
/// Creates a TokenMint system transaction via `blockchain.mint_sov_for_pouw`.
/// The transaction goes through consensus and is executed by all nodes.
pub struct RewardMinter {
    blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
}

impl RewardMinter {
    pub fn new(blockchain: Arc<RwLock<lib_blockchain::Blockchain>>) -> Self {
        Self { blockchain }
    }

    /// Mint SOV to a recipient via a TokenMint system transaction.
    ///
    /// Returns the transaction hash on success.
    pub async fn mint(
        &self,
        recipient_key_id: [u8; 32],
        amount: u128,
        source: RewardSource,
        epoch: u64,
    ) -> Result<lib_blockchain::Hash> {
        let tx_hash = {
            let mut bc = self.blockchain.write().await;
            bc.mint_sov_for_pouw(recipient_key_id, amount)?
        };

        info!(
            recipient = hex::encode(&recipient_key_id[..8]),
            amount,
            source = ?source,
            epoch,
            tx_hash = hex::encode(tx_hash.as_bytes()),
            "Reward minted via TokenMint system transaction"
        );

        Ok(tx_hash)
    }
}
