/// CBE Transaction Scanner
///
/// Opens the sled store directly and extracts all CBE-related transactions
/// (TokenTransfer, TokenMint, TokenCreation, InitCbeToken, CreateEmploymentContract,
/// ProcessPayroll) to enable testnet replay after a reset.

use anyhow::Result;
use lib_blockchain::storage::{BlockchainStore, SledStore};
use lib_blockchain::types::transaction_type::TransactionType;
use std::path::PathBuf;
use std::sync::Arc;

fn get_cbe_token_id() -> [u8; 32] {
    lib_blockchain::Blockchain::derive_cbe_token_id_pub()
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/data/testnet/sled".to_string());

    eprintln!("Opening sled at: {}", path);
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(PathBuf::from(&path))?);

    let latest_height = match store.latest_height() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("No committed blocks in sled ({})", e);
            return Ok(());
        }
    };

    let cbe_token_id = get_cbe_token_id();
    let cbe_hex = hex::encode(cbe_token_id);
    eprintln!("CBE token ID: {}", cbe_hex);
    eprintln!("Scanning {} blocks...\n", latest_height + 1);

    // JSON array output
    println!("[");
    let mut first = true;

    for height in 0..=latest_height {
        let block = match store.get_block_by_height(height)? {
            Some(b) => b,
            None => continue,
        };

        for tx in &block.transactions {
            let is_cbe = match tx.transaction_type {
                TransactionType::TokenTransfer => {
                    tx.token_transfer_data()
                        .map(|d| d.token_id == cbe_token_id)
                        .unwrap_or(false)
                }
                TransactionType::TokenMint => {
                    tx.token_mint_data()
                        .map(|d| d.token_id == cbe_token_id)
                        .unwrap_or(false)
                }
                TransactionType::TokenCreation => {
                    // Check memo for CBE references
                    let memo_str = String::from_utf8_lossy(&tx.memo);
                    memo_str.contains("CBE") || memo_str.contains("cbe")
                }
                TransactionType::InitCbeToken
                | TransactionType::CreateEmploymentContract
                | TransactionType::ProcessPayroll => true,
                _ => {
                    // Check memo for cbe references
                    let memo_str = String::from_utf8_lossy(&tx.memo);
                    memo_str.contains("cbe:") || memo_str.contains("CBE")
                }
            };

            if !is_cbe {
                continue;
            }

            let tx_hash = hex::encode(tx.hash().as_bytes());
            let tx_type = format!("{:?}", tx.transaction_type);
            let signer_key_id = hex::encode(tx.signature.public_key.key_id);

            // Extract details based on type
            let (from, to, amount, token_id_hex) = match tx.transaction_type {
                TransactionType::TokenTransfer => {
                    if let Some(d) = tx.token_transfer_data() {
                        (
                            hex::encode(d.from),
                            hex::encode(d.to),
                            d.amount.to_string(),
                            hex::encode(d.token_id),
                        )
                    } else {
                        (String::new(), String::new(), "0".into(), String::new())
                    }
                }
                TransactionType::TokenMint => {
                    if let Some(d) = tx.token_mint_data() {
                        (
                            String::new(),
                            hex::encode(d.to),
                            d.amount.to_string(),
                            hex::encode(d.token_id),
                        )
                    } else {
                        (String::new(), String::new(), "0".into(), String::new())
                    }
                }
                _ => (String::new(), String::new(), "0".into(), cbe_hex.clone()),
            };

            let memo_preview: String = String::from_utf8_lossy(&tx.memo)
                .chars()
                .take(120)
                .collect();

            if !first {
                println!(",");
            }
            first = false;

            println!(
                "  {{\n    \"height\": {},\n    \"tx_hash\": \"{}\",\n    \"type\": \"{}\",\n    \"signer\": \"{}\",\n    \"token_id\": \"{}\",\n    \"from\": \"{}\",\n    \"to\": \"{}\",\n    \"amount\": \"{}\",\n    \"memo\": \"{}\",\n    \"timestamp\": {}\n  }}",
                height,
                tx_hash,
                tx_type,
                signer_key_id,
                token_id_hex,
                from,
                to,
                amount,
                memo_preview.replace('\"', "\\\"").replace('\n', "\\n"),
                tx.signature.timestamp,
            );
        }
    }

    println!("\n]");

    Ok(())
}
