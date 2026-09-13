//! Token mint authorization validation (audit security fixes).
//!
//! Enforces treasury-kernel governance for SOV mints and closes memo-based
//! authorization bypasses for UBI and migration flows at validation time.
//!
//! Treasury authorization accepts either `governance_authority` (policy signer)
//! or `kernel_address` (execution signer) — two roles, not two interchangeable hot keys.

use crate::blockchain::Blockchain;
use crate::integration::crypto_integration::PublicKey;
use crate::transaction::core::Transaction;
use crate::transaction::threshold_approval::{
    compute_approval_preimage, ApprovalDomain, ThresholdApprovalSet,
};
use crate::transaction::validation::ValidationError;

/// Dilithium5 public key byte length used by migration memos.
const DILITHIUM_PUBKEY_LEN: usize = 2592;

/// `TransactionType` discriminant for `TokenMint`.
const TOKEN_MINT_TYPE_BYTE: u8 = 24;

/// Returns true when `token_id` is the canonical native SOV identifier.
pub fn is_canonical_sov_token_id(token_id: &[u8; 32]) -> bool {
    *token_id == [0u8; 32] || *token_id == crate::contracts::utils::generate_lib_token_id()
}

/// Compute the canonical signable preimage for a `TokenMint` governance approval.
///
/// Each council signer signs `compute_approval_preimage(24, BootstrapCouncil, bincode({token_id, to, amount}))`.
pub fn token_mint_approval_preimage(token_id: &[u8; 32], to: &[u8; 32], amount: u128) -> [u8; 32] {
    #[derive(serde::Serialize)]
    struct CanonicalPayload<'a> {
        token_id: &'a [u8; 32],
        to: &'a [u8; 32],
        amount: u128,
    }
    let payload = CanonicalPayload {
        token_id,
        to,
        amount,
    };
    let payload_bytes = bincode::serialize(&payload).unwrap_or_default();
    compute_approval_preimage(
        TOKEN_MINT_TYPE_BYTE,
        &ApprovalDomain::BootstrapCouncil,
        &payload_bytes,
    )
}

/// Returns true when `signer` is the treasury kernel governance authority or kernel address.
///
/// Deprecated as the sole SOV mint gate — user-submitted mints must now carry a
/// council `ThresholdApprovalSet` (see `validate_token_mint_authorization`).
pub fn is_treasury_authorized_signer(blockchain: &Blockchain, signer: &PublicKey) -> bool {
    let Some(kernel) = blockchain.treasury_kernel.as_ref() else {
        return false;
    };
    signer == kernel.governance_authority() || signer == kernel.kernel_address()
}

/// Returns true when `approvals` meet the Bootstrap-council M-of-N threshold for `preimage`.
fn council_threshold_met(
    blockchain: &Blockchain,
    approvals: &ThresholdApprovalSet,
    preimage: &[u8; 32],
) -> bool {
    if approvals.domain != ApprovalDomain::BootstrapCouncil {
        return false;
    }
    crate::transaction::threshold_approval::validate_threshold_approvals(
        approvals,
        preimage,
        |pk_bytes| {
            blockchain
                .did_by_public_key(pk_bytes)
                .map(|did| blockchain.is_council_member(&did))
                .unwrap_or(false)
        },
        blockchain.council_threshold as usize,
    )
    .is_ok()
}

fn is_genesis_unsigned_mint_exception(blockchain: &Blockchain, transaction: &Transaction) -> bool {
    blockchain.is_applying_genesis_state() && transaction.signature.signature.is_empty()
}

fn validate_ubi_distribution_memo(
    blockchain: &Blockchain,
    memo: &str,
) -> Result<(), ValidationError> {
    let rest = memo
        .strip_prefix("UBI_DISTRIBUTION_V1:")
        .ok_or(ValidationError::InvalidMemo)?;
    let mut parts = rest.split(':');
    let identity_id = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(ValidationError::InvalidMemo)?;
    let wallet_id = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(ValidationError::InvalidMemo)?;

    let entry = blockchain
        .ubi_registry
        .get(identity_id)
        .ok_or(ValidationError::InvalidTransaction)?;
    if entry.ubi_wallet_id != wallet_id {
        return Err(ValidationError::InvalidTransaction);
    }

    Ok(())
}

fn validate_ubi_sov_recipient_match(
    mint_to: &[u8; 32],
    memo_wallet_id: &str,
) -> Result<(), ValidationError> {
    if hex::encode(mint_to) != memo_wallet_id {
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
    let decoded = hex::decode(rest).map_err(|_| ValidationError::InvalidMemo)?;
    if decoded.len() != DILITHIUM_PUBKEY_LEN {
        return Err(ValidationError::InvalidMemo);
    }
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

        if is_canonical_sov_token_id(&mint_data.token_id) {
            let wallet_id = memo
                .strip_prefix("UBI_DISTRIBUTION_V1:")
                .and_then(|rest| rest.split(':').nth(1))
                .ok_or(ValidationError::InvalidMemo)?;
            validate_ubi_sov_recipient_match(&mint_data.to, wallet_id)?;
            let preimage =
                token_mint_approval_preimage(&mint_data.token_id, &mint_data.to, mint_data.amount);
            if !council_threshold_met(blockchain, &mint_data.approvals, &preimage) {
                return Err(ValidationError::Unauthorized);
            }
        } else if let Some(token) = blockchain.get_token_contract(&mint_data.token_id) {
            token
                .check_mint_authorization(signer)
                .map_err(|_| ValidationError::Unauthorized)?;
        } else {
            return Err(ValidationError::InvalidTransaction);
        }

        return Ok(());
    }

    if is_migration {
        validate_token_migrate_memo(memo_str.ok_or(ValidationError::InvalidMemo)?)?;
        let preimage =
            token_mint_approval_preimage(&mint_data.token_id, &mint_data.to, mint_data.amount);
        if !council_threshold_met(blockchain, &mint_data.approvals, &preimage) {
            return Err(ValidationError::Unauthorized);
        }
        return Ok(());
    }

    if is_canonical_sov_token_id(&mint_data.token_id) {
        if is_genesis_unsigned_mint_exception(blockchain, transaction) {
            return Ok(());
        }
        // No single key may mint SOV: user-submitted mints must carry a
        // Bootstrap-council M-of-N ThresholdApprovalSet over the canonical
        // (token_id, to, amount) preimage.
        let preimage =
            token_mint_approval_preimage(&mint_data.token_id, &mint_data.to, mint_data.amount);
        if council_threshold_met(blockchain, &mint_data.approvals, &preimage) {
            return Ok(());
        }
        return Err(ValidationError::Unauthorized);
    }

    let token = blockchain
        .get_token_contract(&mint_data.token_id)
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
                approvals: Default::default(),
            }),
        }
    }

    fn blockchain_with_treasury(authority: PublicKey) -> Blockchain {
        let mut blockchain = Blockchain::default();
        blockchain.initialize_treasury_kernel(authority);
        blockchain
    }

    fn register_council_member(blockchain: &mut Blockchain, did: &str, signer: &PublicKey) {
        blockchain.identity_registry.insert(
            did.to_string(),
            crate::transaction::IdentityTransactionData::new(
                did.to_string(),
                "Council Member".to_string(),
                signer.dilithium_pk.to_vec(),
                vec![1, 2, 3],
                "human".to_string(),
                crate::types::Hash::from([9u8; 32]),
                0,
                0,
            ),
        );
        blockchain.council_members.push(crate::dao::CouncilMember {
            identity_id: did.to_string(),
            wallet_id: "wallet".to_string(),
            stake_amount: 1,
            joined_at_height: 0,
        });
        blockchain.council_threshold = 1;
    }

    fn council_mint_tx(
        signers: &[lib_crypto::KeyPair],
        token_id: [u8; 32],
        memo: &str,
    ) -> Transaction {
        use crate::transaction::threshold_approval::{Approval, ApprovalDomain};
        let to = [0xAAu8; 32];
        let amount = 100u128;
        let preimage = token_mint_approval_preimage(&token_id, &to, amount);
        let approvals = signers
            .iter()
            .map(|signer| {
                let signature = signer.sign(&preimage).unwrap();
                Approval {
                    public_key: signer.public_key.clone(),
                    algorithm: signature.algorithm,
                    signature: signature.signature,
                }
            })
            .collect();

        Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenMint,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: Signature {
                signature: vec![],
                public_key: signers[0].public_key.clone(),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: memo.as_bytes().to_vec(),
            payload: TransactionPayload::TokenMint(TokenMintData {
                token_id,
                to,
                amount,
                approvals: crate::transaction::threshold_approval::ThresholdApprovalSet {
                    domain: ApprovalDomain::BootstrapCouncil,
                    approvals,
                },
            }),
        }
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
        assert!(!is_treasury_authorized_signer(
            &blockchain,
            &test_public_key(2)
        ));
    }

    #[test]
    fn sov_mint_requires_treasury_signer() {
        let authority = test_public_key(10);
        let attacker = test_public_key(11);
        let blockchain = blockchain_with_treasury(authority);
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        let result =
            validate_token_mint_authorization(&blockchain, &mint_tx(&attacker, sov_id, "", false));
        assert!(matches!(result, Err(ValidationError::Unauthorized)));
    }

    #[test]
    fn sov_mint_rejects_single_treasury_signer() {
        let authority = test_public_key(20);
        let mut blockchain = blockchain_with_treasury(authority.clone());
        register_council_member(&mut blockchain, "did:zhtp:authority", &authority);
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        // A bare single-key signer (no council approval set) must be rejected.
        let result =
            validate_token_mint_authorization(&blockchain, &mint_tx(&authority, sov_id, "", false));
        assert!(matches!(result, Err(ValidationError::Unauthorized)));
    }

    #[test]
    fn sov_mint_requires_council_threshold() {
        let mut blockchain = Blockchain::default();
        let signer = lib_crypto::KeyPair::generate().expect("keygen");
        register_council_member(&mut blockchain, "did:zhtp:council", &signer.public_key);
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        let result =
            validate_token_mint_authorization(&blockchain, &council_mint_tx(&[signer], sov_id, ""));
        assert!(result.is_ok());
    }

    #[test]
    fn sov_mint_allows_genesis_unsigned_exception() {
        let mut blockchain = Blockchain::default();
        blockchain.begin_genesis_apply();
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let signer = test_public_key(30);

        let result =
            validate_token_mint_authorization(&blockchain, &mint_tx(&signer, sov_id, "", true));
        assert!(result.is_ok());
        blockchain.end_genesis_apply();
    }

    #[test]
    fn ubi_mint_requires_registry_entry_and_council_for_sov() {
        let authority = test_public_key(40);
        let mut blockchain = blockchain_with_treasury(authority.clone());
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let wallet_hex = hex::encode([0xAA; 32]);
        let memo = format!("UBI_DISTRIBUTION_V1:identity-1:{wallet_hex}");

        let missing_registry = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&authority, sov_id, &memo, false),
        );
        assert!(matches!(
            missing_registry,
            Err(ValidationError::InvalidTransaction)
        ));

        blockchain.ubi_registry.insert(
            "identity-1".to_string(),
            crate::blockchain::UbiRegistryEntry {
                identity_id: "identity-1".to_string(),
                ubi_wallet_id: wallet_hex.clone(),
                daily_amount: 33,
                monthly_amount: 1_000,
                registered_at_block: 1,
                last_payout_block: None,
                total_received: 0,
                remainder_balance: 0,
                is_active: true,
            },
        );

        // A single treasury key (no council approval set) is rejected.
        let unauthorized = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&test_public_key(41), sov_id, &memo, false),
        );
        assert!(matches!(unauthorized, Err(ValidationError::Unauthorized)));

        // A council M-of-N approval set authorizes.
        let signer = lib_crypto::KeyPair::generate().expect("keygen");
        register_council_member(&mut blockchain, "did:zhtp:council", &signer.public_key);
        let authorized = validate_token_mint_authorization(
            &blockchain,
            &council_mint_tx(&[signer], sov_id, &memo),
        );
        assert!(authorized.is_ok());
    }

    #[test]
    fn ubi_mint_rejects_recipient_wallet_mismatch_for_sov() {
        let authority = test_public_key(42);
        let mut blockchain = blockchain_with_treasury(authority.clone());
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let wallet_hex = hex::encode([0xAA; 32]);
        let wrong_wallet_hex = hex::encode([0xBB; 32]);
        let memo = format!("UBI_DISTRIBUTION_V1:identity-1:{wrong_wallet_hex}");

        blockchain.ubi_registry.insert(
            "identity-1".to_string(),
            crate::blockchain::UbiRegistryEntry {
                identity_id: "identity-1".to_string(),
                ubi_wallet_id: wrong_wallet_hex,
                daily_amount: 33,
                monthly_amount: 1_000,
                registered_at_block: 1,
                last_payout_block: None,
                total_received: 0,
                remainder_balance: 0,
                is_active: true,
            },
        );

        let result = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&authority, sov_id, &memo, false),
        );
        assert!(matches!(result, Err(ValidationError::InvalidTransaction)));
    }

    #[test]
    fn ubi_bypass_rejects_fake_identity_in_memo() {
        let authority = test_public_key(43);
        let blockchain = blockchain_with_treasury(authority.clone());
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let wallet_hex = hex::encode([0xAA; 32]);
        let memo = format!("UBI_DISTRIBUTION_V1:fake-identity:{wallet_hex}");

        let result = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&authority, sov_id, &memo, false),
        );
        assert!(matches!(result, Err(ValidationError::InvalidTransaction)));
    }

    #[test]
    fn genesis_exception_does_not_fire_outside_apply_genesis_state() {
        let blockchain = Blockchain::default();
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let signer = test_public_key(44);

        let result =
            validate_token_mint_authorization(&blockchain, &mint_tx(&signer, sov_id, "", true));
        assert!(matches!(result, Err(ValidationError::Unauthorized)));
    }

    #[test]
    fn token_migrate_rejects_wrong_pubkey_length() {
        let authority = test_public_key(45);
        let blockchain = blockchain_with_treasury(authority.clone());
        let custom_id = [0xCD; 32];
        let memo = format!("TOKEN_MIGRATE_V1:{}", hex::encode([0x11; 32]));

        let result = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&authority, custom_id, &memo, false),
        );
        assert!(matches!(result, Err(ValidationError::InvalidMemo)));
    }

    #[test]
    fn ubi_mint_rejects_malformed_memo() {
        let authority = test_public_key(50);
        let blockchain = blockchain_with_treasury(authority.clone());
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        let result = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(
                &authority,
                sov_id,
                "UBI_DISTRIBUTION_V1:only-identity",
                false,
            ),
        );
        assert!(matches!(result, Err(ValidationError::InvalidMemo)));
    }

    #[test]
    fn token_migrate_requires_council_threshold() {
        let authority = test_public_key(60);
        let mut blockchain = blockchain_with_treasury(authority.clone());
        let custom_id = [0xCD; 32];
        let memo = format!("TOKEN_MIGRATE_V1:{}", hex::encode([0x11; 2592]));

        let unauthorized = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&test_public_key(61), custom_id, &memo, false),
        );
        assert!(matches!(unauthorized, Err(ValidationError::Unauthorized)));

        // Single treasury key (no council approval set) is rejected.
        let single_key = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&authority, custom_id, &memo, false),
        );
        assert!(matches!(single_key, Err(ValidationError::Unauthorized)));

        // Council M-of-N approval set authorizes.
        let signer = lib_crypto::KeyPair::generate().expect("keygen");
        register_council_member(&mut blockchain, "did:zhtp:council", &signer.public_key);
        let authorized = validate_token_mint_authorization(
            &blockchain,
            &council_mint_tx(&[signer], custom_id, &memo),
        );
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
        let result = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&attacker, token_id, ubi_memo, false),
        );
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

        let still_unauthorized = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&attacker, token_id, ubi_memo, false),
        );
        assert!(matches!(
            still_unauthorized,
            Err(ValidationError::Unauthorized)
        ));

        let creator_ok = validate_token_mint_authorization(
            &blockchain,
            &mint_tx(&creator, token_id, ubi_memo, false),
        );
        assert!(creator_ok.is_ok());
    }
}
