//! Build a `lib_types::mempool::AdmitTx` view of a `Transaction` for mempool
//! admission via `lib_mempool::admit`.
//!
//! Mirrors `execution::executor::FeeModelV2::tx_to_fee_input` field-for-field
//! so admission decisions are consistent with the executor's fee calculation.

use lib_fees::model_v2::{SigSchemeExt, TxKindExt};
use lib_fees::{SigScheme, TxKind};
use lib_types::mempool::AdmitTx;
use lib_types::{Address, Amount};

use crate::transaction::Transaction;
use crate::types::TransactionType;

impl Transaction {
    /// Build the admission view of this transaction.
    pub fn to_admit_tx(&self) -> AdmitTx {
        let kind = tx_kind_for(self.transaction_type);
        let sig_scheme = SigScheme::Dilithium5;

        // Witness budget matches FeeModelV2 capped at the TxKind witness cap.
        // The raw signature size for Dilithium5 is ~4.6KB per sig, which
        // exceeds every TxKind cap defined in lib-fees. Both the fee model
        // (via `FeeInputExt::witness_bytes_capped`) and the admission gate
        // operate on the capped value; passing the raw size would always
        // trigger `AdmitErrorKind::WitnessTooLarge`.
        let sig_count = self.inputs.len().max(1) as u8;
        let raw_witness = (sig_count as u32) * sig_scheme.signature_size();
        let witness_bytes = raw_witness.min(kind.witness_cap());

        // Sender = key_id on the tx-level signature. For coinbase / system
        // bypass paths this is whatever the issuer placed there (often zero);
        // admission ignores the value for `add_system_transaction` callers.
        let sender = Address(self.signature.public_key.key_id);

        AdmitTx {
            fee: self.fee as Amount,
            tx_bytes: self.size() as u32,
            witness_bytes,
            input_count: self.inputs.len() as u16,
            output_count: self.outputs.len() as u16,
            sig_count,
            tx_kind: kind,
            sig_scheme,
            sender,
            compute_units: 0,
            state_reads: (self.inputs.len() + self.outputs.len()) as u32,
            state_writes: self.outputs.len() as u32,
            state_write_bytes: (self.outputs.len() * 64) as u32,
        }
    }
}

fn tx_kind_for(t: TransactionType) -> TxKind {
    match t {
        TransactionType::Transfer => TxKind::NativeTransfer,
        TransactionType::TokenTransfer => TxKind::TokenTransfer,
        TransactionType::Coinbase => TxKind::NativeTransfer,
        TransactionType::IdentityRegistration
        | TransactionType::IdentityUpdate
        | TransactionType::IdentityRevocation
        | TransactionType::ValidatorRegistration
        | TransactionType::ValidatorUpdate
        | TransactionType::GatewayRegistration
        | TransactionType::GatewayUpdate
        | TransactionType::GatewayUnregister
        | TransactionType::DaoProposal
        | TransactionType::DaoVote
        | TransactionType::DaoExecution
        | TransactionType::GovernanceConfigUpdate => TxKind::Governance,
        TransactionType::UbiDistribution => TxKind::NativeTransfer,
        TransactionType::ContractDeployment | TransactionType::ContractExecution => {
            TxKind::ContractCall
        }
        TransactionType::ContentUpload => TxKind::DataUpload,
        _ => TxKind::NativeTransfer,
    }
}
