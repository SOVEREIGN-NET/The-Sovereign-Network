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
/// Dilithium tx layer. Authentication is elsewhere:
/// - [`TransactionType::IdentityRegistration`]: API verifies `ZHTP_REGISTER`
///   proof; payload carries `ownership_proof` + DID/pk binding (see
///   `SystemOriginator::ClientIdentityRegistration`).
/// - [`TransactionType::WalletRegistration`]: zero-balance auto wallets from
///   the same registration path (`SystemOriginator::AutoWalletRegistration`).
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
            let key_id = crate::types::hash::blake3_hash(identity_pk.as_slice());
            let expected_did = format!("did:zhtp:{}", hex::encode(key_id.as_bytes()));
            data.did == expected_did
        }
        TransactionType::WalletRegistration => transaction
            .wallet_data()
            .map(|w| w.initial_balance == 0)
            .unwrap_or(false),
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

        let dilithium_pk = [0xABu8; 2592];
        let key_id = crate::types::hash::blake3_hash(&dilithium_pk);
        let did = format!("did:zhtp:{}", hex::encode(key_id.as_bytes()));
        let identity_data = IdentityTransactionData {
            did,
            display_name: "test_user".to_string(),
            public_key: dilithium_pk.to_vec(),
            ownership_proof: vec![0x01, 0x02],
            identity_type: "human".to_string(),
            did_document_hash: Hash::default(),
            created_at: 1,
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
            b"client-identity-register:test".to_vec(),
        );
        assert!(allows_empty_system_signature(&tx));
        assert!(requires_system_tx_signature(&tx));
    }
}