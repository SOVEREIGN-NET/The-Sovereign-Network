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
}