//! Single minting path for all reward types.
//!
//! All reward processors call RewardMinter::mint() — no other code path
//! creates reward transactions.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::transaction::{TokenMintData, Transaction};

use super::budget_tracker::RewardSource;

/// Single call site for creating reward transactions.
///
/// Builds a TokenMint system transaction outside the blockchain lock,
/// then acquires the write lock only for mempool insertion.
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
        // Build the transaction entirely outside the lock
        let mint_data = TokenMintData {
            token_id: lib_blockchain::contracts::utils::generate_lib_token_id(),
            to: recipient_key_id,
            amount,
        };

        let signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let memo = format!("pouw:mint:{}:{}", hex::encode(recipient_key_id), amount).into_bytes();
        let mint_tx = Transaction::new_token_mint(mint_data, signature, memo);
        let tx_hash = mint_tx.hash();

        // Write lock only for mempool insertion
        {
            let mut bc = self.blockchain.write().await;
            bc.add_system_transaction(mint_tx)?;
        }

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
