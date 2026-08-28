//! System-transaction signature policy (audit follow-up: exhaustive TransactionType map).
//!
//! Every [`TransactionType`] variant must be explicitly classified so new variants
//! cannot silently bypass signature requirements.

use crate::transaction::core::Transaction;
use crate::types::transaction_type::TransactionType;

/// How a system transaction's tx-level signature is treated at validation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemTxSignaturePolicy {
    /// Privileged state mutation — valid Dilithium signature required.
    Required,
    /// Threshold-approval payload is authoritative; tx-level signature optional.
    ThresholdApproval,
    /// Protocol/bootstrap emission (coinbase, system UBI push, audit sessions).
    Bootstrap,
}

/// Explicit policy for every transaction type. Compiler forces updates when variants are added.
pub fn system_tx_signature_policy(ty: TransactionType) -> SystemTxSignaturePolicy {
    match ty {
        TransactionType::Transfer
        | TransactionType::TokenTransfer
        | TransactionType::RewardClaim
        | TransactionType::IdentityRegistration
        | TransactionType::IdentityUpdate
        | TransactionType::IdentityRevocation
        | TransactionType::ContractDeployment
        | TransactionType::ContractExecution
        | TransactionType::ContentUpload
        | TransactionType::WalletRegistration
        | TransactionType::WalletUpdate
        | TransactionType::ValidatorRegistration
        | TransactionType::ValidatorUpdate
        | TransactionType::ValidatorUnregister
        | TransactionType::DaoProposal
        | TransactionType::DaoVote
        | TransactionType::DaoExecution
        | TransactionType::DifficultyUpdate
        | TransactionType::UBIClaim
        | TransactionType::ProfitDeclaration
        | TransactionType::GovernanceConfigUpdate
        | TransactionType::TokenMint
        | TransactionType::TokenCreation
        | TransactionType::AssetLaunch
        | TransactionType::AssetModuleUpgrade
        | TransactionType::AssetManifestUpdate
        | TransactionType::AssetAuthorityTransfer
        | TransactionType::AssetAuthorityTransferCancel
        | TransactionType::AssetRewardsDelegateRotate
        | TransactionType::AssetRewardsPolicyUpdate
        | TransactionType::AssetBurnBpsUpdate
        | TransactionType::TokenSwap
        | TransactionType::CreatePool
        | TransactionType::AddLiquidity
        | TransactionType::RemoveLiquidity
        | TransactionType::BondingCurveDeploy
        | TransactionType::BondingCurveBuy
        | TransactionType::BondingCurveSell
        | TransactionType::BondingCurveGraduate
        | TransactionType::UpdateOracleCommittee
        | TransactionType::UpdateOracleConfig
        | TransactionType::OracleAttestation
        | TransactionType::CancelOracleUpdate
        | TransactionType::InitEntityRegistry
        | TransactionType::InitCbeToken
        | TransactionType::CreateEmploymentContract
        | TransactionType::ProcessPayroll
        | TransactionType::DaoStake
        | TransactionType::DaoUnstake
        | TransactionType::DomainRegistration
        | TransactionType::DomainUpdate
        | TransactionType::GatewayRegistration
        | TransactionType::GatewayUpdate
        | TransactionType::GatewayUnregister
        | TransactionType::NftCreateCollection
        | TransactionType::NftMint
        | TransactionType::NftTransfer
        | TransactionType::NftBurn
        | TransactionType::RegisterObserver
        | TransactionType::UpdateObserverMetadata
        | TransactionType::SuspendObserver
        | TransactionType::RevokeObserver
        | TransactionType::ReauthorizeObserver
        | TransactionType::RegisterCredential
        | TransactionType::UpdateCredentialPassword => SystemTxSignaturePolicy::Required,

        TransactionType::RecordOnRampTrade | TransactionType::TreasuryAllocation => {
            SystemTxSignaturePolicy::ThresholdApproval
        }

        TransactionType::Coinbase
        | TransactionType::UbiDistribution
        | TransactionType::SessionCreation
        | TransactionType::SessionTermination => SystemTxSignaturePolicy::Bootstrap,
    }
}

/// Returns true when a system transaction must carry a valid tx-level signature.
pub fn requires_system_tx_signature(transaction: &Transaction) -> bool {
    system_tx_signature_policy(transaction.transaction_type) == SystemTxSignaturePolicy::Required
}

/// Client / auto-bootstrap system txs that are intentionally unsigned at the
/// Dilithium tx layer. Authentication is carried in the payload:
/// - [`TransactionType::IdentityRegistration`]: Dilithium verify of
///   `ownership_proof` over `ZHTP_REGISTER:{created_at}` (same message the
///   registration API signs), plus DID/pk binding. Consensus must not trust
///   arbitrary proof bytes when skipping tx-level signature verification.
/// - [`TransactionType::WalletRegistration`]: zero-balance auto wallets with
///   wallet_id + pk binding (`SystemOriginator::AutoWalletRegistration`).
///
/// Non-empty signatures still always go through full crypto verify.
pub fn allows_empty_system_signature(transaction: &Transaction) -> bool {
    if !transaction.signature.signature.is_empty() {
        return false;
    }
    match transaction.transaction_type {
        TransactionType::IdentityRegistration => {
            let Some(data) = transaction.identity_data() else {
                return false;
            };
            if data.ownership_proof.is_empty() || data.public_key.len() != 2592 {
                return false;
            }
            let Ok(identity_pk): Result<[u8; 2592], _> = data.public_key.as_slice().try_into()
            else {
                return false;
            };
            if transaction.signature.public_key.dilithium_pk != identity_pk {
                return false;
            }
            // Cryptographic ownership (not just non-empty bytes): client signs
            // "ZHTP_REGISTER:{timestamp}" with the identity private key.
            let ownership_msg = format!("ZHTP_REGISTER:{}", data.created_at);
            if !lib_crypto::verify_signature(
                ownership_msg.as_bytes(),
                &data.ownership_proof,
                &data.public_key,
            )
            .unwrap_or(false)
            {
                return false;
            }
            let key_id = crate::types::hash::blake3_hash(identity_pk.as_slice());
            let expected_did = format!("did:zhtp:{}", hex::encode(key_id.as_bytes()));
            data.did == expected_did
        }
        TransactionType::WalletRegistration => {
            // Zero-balance auto wallets only. Bind wallet_id + tx.signature.pk
            // to the payload public key so an empty signature cannot admit a
            // forged WalletRegistration with arbitrary wallet_id (Copilot #2924).
            let Some(w) = transaction.wallet_data() else {
                return false;
            };
            if w.initial_balance != 0 || w.public_key.len() != 2592 {
                return false;
            }
            let Ok(wallet_pk): Result<[u8; 2592], _> = w.public_key.as_slice().try_into() else {
                return false;
            };
            if transaction.signature.public_key.dilithium_pk != wallet_pk {
                return false;
            }
            // Legacy/validator wallets (zero kyber): wallet_id == blake3(pk).
            let key_id = crate::types::hash::blake3_hash(wallet_pk.as_slice());
            if w.wallet_id.as_bytes() == key_id.as_bytes() {
                return true;
            }
            // Client wallets: wallet_id == blake3(pk || kyber_pk).
            if w.kyber_public_key.is_empty() {
                return false;
            }
            let mut client_input = wallet_pk.to_vec();
            client_input.extend_from_slice(&w.kyber_public_key);
            let client_key_id = crate::types::hash::blake3_hash(&client_input);
            w.wallet_id.as_bytes() == client_key_id.as_bytes()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_always_requires_signature_even_when_empty() {
        let tx = Transaction {
            version: 8,
            chain_id: 0x03,
            transaction_type: TransactionType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: Default::default(),
            memo: vec![],
            payload: crate::transaction::TransactionPayload::None,
        };
        assert!(requires_system_tx_signature(&tx));
    }

    #[test]
    fn threshold_types_do_not_require_tx_signature() {
        for ty in [
            TransactionType::RecordOnRampTrade,
            TransactionType::TreasuryAllocation,
        ] {
            assert_eq!(
                system_tx_signature_policy(ty),
                SystemTxSignaturePolicy::ThresholdApproval
            );
        }
    }

    #[test]
    fn privileged_registration_types_require_signature() {
        for ty in [
            TransactionType::WalletRegistration,
            TransactionType::ValidatorRegistration,
            TransactionType::GatewayRegistration,
            TransactionType::NftMint,
            TransactionType::OracleAttestation,
            TransactionType::DaoStake,
        ] {
            assert_eq!(
                system_tx_signature_policy(ty),
                SystemTxSignaturePolicy::Required
            );
        }
    }

    #[test]
    fn client_identity_registration_allows_empty_sig_when_bound() {
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::core::IdentityTransactionData;
        use crate::types::Hash;

        let keypair = lib_crypto::generate_keypair().expect("keypair");
        let dilithium_pk = keypair.public_key.dilithium_pk;
        let created_at = 1_700_000_000u64;
        let ownership_msg = format!("ZHTP_REGISTER:{}", created_at);
        let ownership_proof = lib_crypto::sign_message(&keypair, ownership_msg.as_bytes())
            .expect("sign ownership")
            .signature;
        let key_id = crate::types::hash::blake3_hash(&dilithium_pk);
        let did = format!("did:zhtp:{}", hex::encode(key_id.as_bytes()));
        let identity_data = IdentityTransactionData {
            did,
            display_name: "test_user".to_string(),
            public_key: dilithium_pk.to_vec(),
            ownership_proof,
            identity_type: "human".to_string(),
            did_document_hash: Hash::default(),
            created_at,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: vec![],
            owned_wallets: vec![],
            kyber_public_key: vec![],
        };
        let tx = Transaction::new_identity_registration(
            identity_data,
            vec![],
            Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(dilithium_pk),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: created_at,
            },
            b"client-identity-register:test".to_vec(),
        );
        assert!(allows_empty_system_signature(&tx));
        assert!(requires_system_tx_signature(&tx));
    }

    #[test]
    fn client_identity_registration_rejects_forged_ownership_proof() {
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::core::IdentityTransactionData;
        use crate::types::Hash;

        let keypair = lib_crypto::generate_keypair().expect("keypair");
        let dilithium_pk = keypair.public_key.dilithium_pk;
        let key_id = crate::types::hash::blake3_hash(&dilithium_pk);
        let did = format!("did:zhtp:{}", hex::encode(key_id.as_bytes()));
        let identity_data = IdentityTransactionData {
            did,
            display_name: "squatter".to_string(),
            public_key: dilithium_pk.to_vec(),
            // Non-empty garbage — previously admitted under empty tx-sig bypass.
            ownership_proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
            identity_type: "human".to_string(),
            did_document_hash: Hash::default(),
            created_at: 1_700_000_000,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: vec![],
            owned_wallets: vec![],
            kyber_public_key: vec![],
        };
        let tx = Transaction::new_identity_registration(
            identity_data,
            vec![],
            Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(dilithium_pk),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 1,
            },
            b"client-identity-register:forged".to_vec(),
        );
        assert!(
            !allows_empty_system_signature(&tx),
            "empty tx-sig must not admit IdentityRegistration with unverified ownership_proof"
        );
    }

    #[test]
    fn wallet_registration_empty_sig_requires_wallet_id_pk_binding() {
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::core::WalletTransactionData;
        use crate::types::Hash;

        let dilithium_pk = [0xCDu8; 2592];
        let key_id = crate::types::hash::blake3_hash(&dilithium_pk);
        let good = WalletTransactionData {
            wallet_id: key_id,
            wallet_type: "Primary".to_string(),
            wallet_name: "p".to_string(),
            alias: None,
            public_key: dilithium_pk.to_vec(),
            kyber_public_key: vec![],
            owner_identity_id: None,
            seed_commitment: Hash::default(),
            created_at: 1,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        };
        let good_tx = Transaction::new_wallet_registration(
            good,
            vec![],
            Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(dilithium_pk),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 1,
            },
            b"wallet-reg".to_vec(),
        );
        assert!(allows_empty_system_signature(&good_tx));

        let mut forged = good_tx.clone();
        if let Some(w) = forged.wallet_data().cloned() {
            let mut bad = w;
            bad.wallet_id = Hash::new([0x11; 32]);
            forged = Transaction::new_wallet_registration(
                bad,
                vec![],
                Signature {
                    signature: Vec::new(),
                    public_key: PublicKey::new(dilithium_pk),
                    algorithm: SignatureAlgorithm::DEFAULT,
                    timestamp: 1,
                },
                b"wallet-reg".to_vec(),
            );
        }
        assert!(
            !allows_empty_system_signature(&forged),
            "empty sig must not allow wallet_id unbound from public_key"
        );
    }

    #[test]
    fn wallet_registration_empty_sig_accepts_client_pk_kyber_binding() {
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::core::WalletTransactionData;
        use crate::types::Hash;

        let dilithium_pk = [0xABu8; 2592];
        let kyber_pk = vec![0x42u8; 1568];
        let mut input = dilithium_pk.to_vec();
        input.extend_from_slice(&kyber_pk);
        let client_key_id = crate::types::hash::blake3_hash(&input);

        let good = WalletTransactionData {
            wallet_id: client_key_id,
            wallet_type: "Primary".to_string(),
            wallet_name: "p".to_string(),
            alias: None,
            public_key: dilithium_pk.to_vec(),
            kyber_public_key: kyber_pk.clone(),
            owner_identity_id: None,
            seed_commitment: Hash::default(),
            created_at: 1,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        };
        let good_tx = Transaction::new_wallet_registration(
            good,
            vec![],
            Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(dilithium_pk),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 1,
            },
            b"wallet-reg".to_vec(),
        );
        assert!(allows_empty_system_signature(&good_tx));
    }

    /// Regression test for #2978 sub-issue 1: wallet IDs for remote-client
    /// registrations must derive from the client's PQC keys (NOT a server-side
    /// HD seed) and must pass the empty-signature wallet binding check.
    #[tokio::test]
    async fn client_pqc_wallet_ids_derive_from_keys_and_pass_empty_sig_binding() {
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::core::WalletTransactionData;
        use crate::types::hash::blake3_hash;
        use crate::types::Hash;

        // Known client Dilithium5 + Kyber1024 keypair.
        let keypair = lib_crypto::generate_keypair().expect("client keypair");
        let dilithium_pk = keypair.public_key.dilithium_pk;
        let kyber_pk = keypair.public_key.kyber_pk.to_vec();

        // Real remote-client registration path (#2979).
        let mut manager = lib_identity::IdentityManager::new();
        let mut economic_model = lib_identity::economics::EconomicModel::new();
        let did = format!("did:zhtp:{}", hex::encode(keypair.public_key.key_id));
        let result = manager
            .register_external_citizen_identity(
                did,
                keypair.public_key.clone(),
                kyber_pk.clone(),
                "test-client-device".to_string(),
                Some("pqc-client".to_string()),
                1_700_000_000u64,
                &mut economic_model,
            )
            .await
            .expect("external citizen registration");

        // primary_wallet_id == blake3(dilithium_pk || kyber_pk)
        let mut primary_input = dilithium_pk.to_vec();
        primary_input.extend_from_slice(&kyber_pk);
        let expected_primary = blake3_hash(&primary_input);
        assert_eq!(result.primary_wallet_id.0, expected_primary.as_array());

        // ubi_wallet_id == blake3(primary_wallet_id || "ubi")
        let mut ubi_input = result.primary_wallet_id.0.to_vec();
        ubi_input.extend_from_slice(b"ubi");
        let expected_ubi = blake3_hash(&ubi_input);
        assert_eq!(result.ubi_wallet_id.0, expected_ubi.as_array());

        // savings_wallet_id == blake3(primary_wallet_id || "savings")
        let mut savings_input = result.primary_wallet_id.0.to_vec();
        savings_input.extend_from_slice(b"savings");
        let expected_savings = blake3_hash(&savings_input);
        assert_eq!(result.savings_wallet_id.0, expected_savings.as_array());

        // Client form: wallet tx carrying kyber, wallet_id == blake3(pk || kyber_pk).
        let client_wallet = WalletTransactionData {
            wallet_id: expected_primary,
            wallet_type: "Primary".to_string(),
            wallet_name: "Primary Wallet".to_string(),
            alias: Some("primary".to_string()),
            public_key: dilithium_pk.to_vec(),
            kyber_public_key: kyber_pk,
            owner_identity_id: None,
            seed_commitment: Hash::default(),
            created_at: 1_700_000_000,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        };
        let client_tx = Transaction::new_wallet_registration(
            client_wallet,
            vec![],
            Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(dilithium_pk),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 1,
            },
            b"wallet-reg:client".to_vec(),
        );
        assert!(
            allows_empty_system_signature(&client_tx),
            "client wallet (pk || kyber binding) must pass empty-sig check"
        );

        // Legacy/validator form: zero kyber, wallet_id == blake3(pk).
        let legacy_wallet_id = blake3_hash(&dilithium_pk);
        let legacy_wallet = WalletTransactionData {
            wallet_id: legacy_wallet_id,
            wallet_type: "Primary".to_string(),
            wallet_name: "Legacy Wallet".to_string(),
            alias: None,
            public_key: dilithium_pk.to_vec(),
            kyber_public_key: vec![],
            owner_identity_id: None,
            seed_commitment: Hash::default(),
            created_at: 1,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        };
        let legacy_tx = Transaction::new_wallet_registration(
            legacy_wallet,
            vec![],
            Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(dilithium_pk),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 1,
            },
            b"wallet-reg:legacy".to_vec(),
        );
        assert!(
            allows_empty_system_signature(&legacy_tx),
            "legacy wallet (blake3(pk) binding) must pass empty-sig check"
        );
    }
}
