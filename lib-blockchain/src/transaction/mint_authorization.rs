//! Token mint authorization validation (audit security fixes).
//!
//! Enforces treasury-kernel governance for SOV mints and closes memo-based
//! authorization bypasses for UBI and migration flows at validation time.

use crate::blockchain::Blockchain;
use crate::integration::crypto_integration::PublicKey;
use crate::transaction::core::Transaction;
use crate::transaction::validation::ValidationError;

/// Returns true when `token_id` is the canonical native SOV identifier.
pub fn is_canonical_sov_token_id(token_id: &[u8; 32]) -> bool {
    *token_id == [0u8; 32] || *token_id == crate::contracts::utils::generate_lib_token_id()
}

/// Returns true when `signer` is the treasury kernel governance authority or kernel address.
pub fn is_treasury_authorized_signer(blockchain: &Blockchain, signer: &PublicKey) -> bool {
    let Some(kernel) = blockchain.treasury_kernel.as_ref() else {
        return false;
    };
    signer == kernel.governance_authority() || signer == kernel.kernel_address()
}

fn is_genesis_unsigned_mint_exception(blockchain: &Blockchain, transaction: &Transaction) -> bool {
    blockchain.height == 0
        && blockchain.latest_block().is_none()
        && transaction.signature.signature.is_empty()
}

fn validate_ubi_distribution_memo(
    blockchain: &Blockchain,
    memo: &str,
) -> Result<(), ValidationError> {
    let rest = memo
        .strip_prefix("UBI_DISTRIBUTION_V1:")
        .ok_or(ValidationError::InvalidMemo)?;
    let mut parts = rest.split(':');
    let identity_id = parts.next().filter(|s| !s.is_empty()).ok_or(ValidationError::InvalidMemo)?;
    let wallet_id = parts.next().filter(|s| !s.is_empty()).ok_or(ValidationError::InvalidMemo)?;

    let entry = blockchain
        .ubi_registry
        .get(identity_id)
        .ok_or(ValidationError::InvalidTransaction)?;
    if entry.ubi_wallet_id != wallet_id {
        return Err(ValidationError::InvalidTransaction);
    }

    Ok(())
}

fn validate_token_migrate_memo(memo: &str) -> Result<(), ValidationError> {
    let rest = memo
        .strip_prefix("TOKEN_MIGRATE_V1:")
        .ok_or(ValidationError::InvalidMemo)?;
    if rest.is_empty() {
        return Err(ValidationError::InvalidMemo);
    }
    hex::decode(rest).map_err(|_| ValidationError::InvalidMemo)?;
    Ok(())
}

/// Stateful mint authorization parity with execution path.
pub fn validate_token_mint_authorization(
    blockchain: &Blockchain,
    transaction: &Transaction,
) -> Result<(), ValidationError> {
    let mint_data = transaction
        .token_mint_data()
        .ok_or(ValidationError::MissingRequiredData)?;
    let signer = &transaction.signature.public_key;

    let memo_str = std::str::from_utf8(&transaction.memo).ok();
    let is_ubi_mint = memo_str
        .map(|memo| memo.starts_with("UBI_DISTRIBUTION_V1:"))
        .unwrap_or(false);
    let is_migration = memo_str
        .map(|memo| memo.starts_with("TOKEN_MIGRATE_V1:"))
        .unwrap_or(false);

    if is_ubi_mint {
        let memo = memo_str.ok_or(ValidationError::InvalidMemo)?;
        validate_ubi_distribution_memo(blockchain, memo)?;

        if is_canonical_sov_token_id(&mint_data.token_id)
            && !is_treasury_authorized_signer(blockchain, signer)
        {
            return Err(ValidationError::Unauthorized);
        }

        if !is_canonical_sov_token_id(&mint_data.token_id) {
            let token = blockchain
                .token_contracts
                .get(&mint_data.token_id)
                .ok_or(ValidationError::InvalidTransaction)?;
            token
                .check_mint_authorization(signer)
                .map_err(|_| ValidationError::Unauthorized)?;
        }

        return Ok(());
    }

    if is_migration {
        validate_token_migrate_memo(memo_str.ok_or(ValidationError::InvalidMemo)?)?;
        if !is_treasury_authorized_signer(blockchain, signer) {
            return Err(ValidationError::Unauthorized);
        }
        return Ok(());
    }

    if is_canonical_sov_token_id(&mint_data.token_id) {
        if is_genesis_unsigned_mint_exception(blockchain, transaction) {
            return Ok(());
        }
        if is_treasury_authorized_signer(blockchain, signer) {
            return Ok(());
        }
        return Err(ValidationError::Unauthorized);
    }

    let token = blockchain
        .token_contracts
        .get(&mint_data.token_id)
        .ok_or(ValidationError::InvalidTransaction)?;
    token
        .check_mint_authorization(signer)
        .map_err(|_| ValidationError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::{Signature, SignatureAlgorithm};
    use crate::transaction::TokenMintData;
    use crate::transaction::TransactionPayload;
    use crate::types::transaction_type::TransactionType;
    use std::collections::HashMap;

    fn test_public_key(id: u8) -> PublicKey {
        let mut key_bytes = [id; 2592];
        key_bytes[0] = id;
        key_bytes[1] = id.wrapping_add(1);
        key_bytes[2] = id.wrapping_add(2);
        PublicKey::new(key_bytes)
    }

    fn mint_tx(signer: &PublicKey, token_id: [u8; 32], memo: &str, empty_sig: bool) -> Transaction {
        Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenMint,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: Signature {
                signature: if empty_sig { vec![] } else { vec![1u8; 64] },
                public_key: signer.clone(),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: memo.as_bytes().to_vec(),
            payload: TransactionPayload::TokenMint(TokenMintData {
                token_id,
                to: [0xAA; 32],
                amount: 100,
            }),
        }
    }

    fn blockchain_with_treasury(authority: PublicKey) -> Blockchain {
        let mut blockchain = Blockchain::default();
        blockchain.initialize_treasury_kernel(authority);
        blockchain
    }

    #[test]
    fn canonical_sov_token_id_matches_legacy_and_generated_ids() {
        assert!(is_canonical_sov_token_id(&[0u8; 32]));
        assert!(is_canonical_sov_token_id(
            &crate::contracts::utils::generate_lib_token_id()
        ));
        assert!(!is_canonical_sov_token_id(&[0xAB; 32]));
    }

    #[test]
    fn treasury_signer_matches_governance_and_kernel_address() {
        let authority = test_public_key(1);
        let blockchain = blockchain_with_treasury(authority.clone());
        assert!(is_treasury_authorized_signer(&blockchain, &authority));
        assert!(!is_treasury_authorized_signer(&blockchain, &test_public_key(2)));
    }

    #[test]
    fn sov_mint_requires_treasury_signer() {
        let authority = test_public_key(10);
        let attacker = test_public_key(11);
        let blockchain = blockchain_with_treasury(authority);
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        let result = validate_token_mint_authorization(&blockchain, &mint_tx(&attacker, sov_id, "", false));
        assert!(matches!(result, Err(ValidationError::Unauthorized)));
    }

    #[test]
    fn sov_mint_allows_treasury_signer() {
        let authority = test_public_key(20);
        let blockchain = blockchain_with_treasury(authority.clone());
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        let result = validate_token_mint_authorization(&blockchain, &mint_tx(&authority, sov_id, "", false));
        assert!(result.is_ok());
    }

    #[test]
    fn sov_mint_allows_genesis_unsigned_exception() {
        let mut blockchain = Blockchain::default();
        blockchain.blocks.clear();
        blockchain.height = 0;
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let signer = test_public_key(30);

        let result = validate_token_mint_authorization(&blockchain, &mint_tx(&signer, sov_id, "", true));
        assert!(result.is_ok());
    }

    #[test]
    fn ubi_mint_requires_registry_entry_and_treasury_for_sov() {
        let authority = test_public_key(40);
        let mut blockchain = blockchain_with_treasury(authority.clone());
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let memo = "UBI_DISTRIBUTION_V1:identity-1:wallet-1";

        let missing_registry =
            validate_token_mint_authorization(&blockchain, &mint_tx(&authority, sov_id, memo, false));
        assert!(matches!(missing_registry, Err(ValidationError::InvalidTransaction)));

        blockchain.ubi_registry.insert(
            "identity-1".to_string(),
            crate::blockchain::UbiRegistryEntry {
                identity_id: "identity-1".to_string(),
                ubi_wallet_id: "wallet-1".to_string(),
                daily_amount: 33,
                monthly_amount: 1_000,
                registered_at_block: 1,
                last_payout_block: None,
                total_received: 0,
                remainder_balance: 0,
                is_active: true,
            },
        );

        let unauthorized = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&test_public_key(41), sov_id, memo, false),
        );
        assert!(matches!(unauthorized, Err(ValidationError::Unauthorized)));

        let authorized = validate_token_mint_authorization(&blockchain, &mint_tx(&authority, sov_id, memo, false));
        assert!(authorized.is_ok());
    }

    #[test]
    fn ubi_mint_rejects_malformed_memo() {
        let authority = test_public_key(50);
        let blockchain = blockchain_with_treasury(authority.clone());
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        let result = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&authority, sov_id, "UBI_DISTRIBUTION_V1:only-identity", false),
        );
        assert!(matches!(result, Err(ValidationError::InvalidMemo)));
    }

    #[test]
    fn token_migrate_requires_treasury_signer() {
        let authority = test_public_key(60);
        let blockchain = blockchain_with_treasury(authority.clone());
        let custom_id = [0xCD; 32];
        let memo = format!("TOKEN_MIGRATE_V1:{}", hex::encode([0x11; 2592]));

        let unauthorized = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&test_public_key(61), custom_id, &memo, false),
        );
        assert!(matches!(unauthorized, Err(ValidationError::Unauthorized)));

        let authorized = validate_token_mint_authorization(&blockchain, &mint_tx(&authority, custom_id, &memo, false));
        assert!(authorized.is_ok());
    }

    #[test]
    fn custom_token_rejects_memo_bypass_without_creator() {
        let creator = test_public_key(70);
        let attacker = test_public_key(71);
        let mut blockchain = Blockchain::default();

        let token = crate::contracts::TokenContract::new_custom(
            "BypassToken".to_string(),
            "BPS".to_string(),
            1_000,
            creator.clone(),
        );
        let token_id = token.token_id;
        blockchain.token_contracts.insert(token_id, token);

        let ubi_memo = "UBI_DISTRIBUTION_V1:id:wid";
        let result = validate_token_mint_authorization(&blockchain, &mint_tx(&attacker, token_id, ubi_memo, false));
        assert!(matches!(result, Err(ValidationError::InvalidTransaction)));

        blockchain.ubi_registry = HashMap::from([(
            "id".to_string(),
            crate::blockchain::UbiRegistryEntry {
                identity_id: "id".to_string(),
                ubi_wallet_id: "wid".to_string(),
                daily_amount: 1,
                monthly_amount: 1,
                registered_at_block: 1,
                last_payout_block: None,
                total_received: 0,
                remainder_balance: 0,
                is_active: true,
            },
        )]);

        let still_unauthorized =
            validate_token_mint_authorization(&blockchain, &mint_tx(&attacker, token_id, ubi_memo, false));
        assert!(matches!(still_unauthorized, Err(ValidationError::Unauthorized)));

        let creator_ok =
            validate_token_mint_authorization(&blockchain, &mint_tx(&creator, token_id, ubi_memo, false));
        assert!(creator_ok.is_ok());
    }
}