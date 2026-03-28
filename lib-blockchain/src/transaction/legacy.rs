//! Backward-compatible deserialization for V1–V7 Transaction wire format.
//!
//! V1–V7 used a hand-rolled `serialize_tuple` / `deserialize_tuple` serde
//! implementation.  V8 switched to `#[derive(Serialize, Deserialize)]` with a
//! `payload: TransactionPayload` enum in place of the scattered `Option<FooData>`
//! fields.
//!
//! When an old client (e.g. a mobile app built against a pre-V8 lib-client)
//! submits a transaction, the server must be able to decode it.
//!
//! `try_decode_legacy(bytes)` attempts to deserialize using the V1–V7 visitor
//! and, on success, converts the flat optional fields into a V8 `Transaction`
//! with the correct `TransactionPayload` variant.

use crate::integration::crypto_integration::Signature;
use crate::transaction::core::{
    BondingCurveBuyData, BondingCurveDeployData, BondingCurveGraduateData,
    BondingCurveSellData, DaoExecutionData, DaoProposalData, DaoVoteData,
    GovernanceConfigUpdateData, IdentityTransactionData, TokenMintData, TokenTransferData,
    Transaction, TransactionInput, TransactionOutput, TransactionPayload,
    UbiClaimData, ValidatorTransactionData, WalletTransactionData, TX_VERSION_V8,
};
use crate::transaction::oracle_governance::{
    CancelOracleUpdateData, OracleAttestationData, OracleCommitteeUpdateData,
    OracleConfigUpdateData,
};
use crate::transaction::core::InitEntityRegistryData;
use crate::transaction::core::ProfitDeclarationData;
use crate::types::transaction_type::TransactionType;
use serde::{Deserialize, Deserializer};

// V1-V7 field counts — used only for the `deserialize_tuple` call.
const TX_FIELD_COUNT_V7: usize = 28;

/// Flat representation of a V1-V7 Transaction (all payload fields as Option<T>).
#[allow(dead_code)]
struct LegacyTransaction {
    version: u32,
    chain_id: u8,
    transaction_type: TransactionType,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    signature: Signature,
    memo: Vec<u8>,
    identity_data: Option<IdentityTransactionData>,
    wallet_data: Option<WalletTransactionData>,
    validator_data: Option<ValidatorTransactionData>,
    dao_proposal_data: Option<DaoProposalData>,
    dao_vote_data: Option<DaoVoteData>,
    dao_execution_data: Option<DaoExecutionData>,
    ubi_claim_data: Option<UbiClaimData>,
    profit_declaration_data: Option<ProfitDeclarationData>,
    token_transfer_data: Option<TokenTransferData>,
    token_mint_data: Option<TokenMintData>,
    governance_config_data: Option<GovernanceConfigUpdateData>,
    bonding_curve_deploy_data: Option<BondingCurveDeployData>,
    bonding_curve_buy_data: Option<BondingCurveBuyData>,
    bonding_curve_sell_data: Option<BondingCurveSellData>,
    bonding_curve_graduate_data: Option<BondingCurveGraduateData>,
    oracle_committee_update_data: Option<OracleCommitteeUpdateData>,
    oracle_config_update_data: Option<OracleConfigUpdateData>,
    oracle_attestation_data: Option<OracleAttestationData>,
    cancel_oracle_update_data: Option<CancelOracleUpdateData>,
    init_entity_registry_data: Option<InitEntityRegistryData>,
}

const TX_VERSION_V2: u32 = 2;
const TX_VERSION_V3: u32 = 3;
const TX_VERSION_V4: u32 = 4;
const TX_VERSION_V5: u32 = 5;
const TX_VERSION_V6: u32 = 6;
const TX_VERSION_V7: u32 = 7;

impl<'de> Deserialize<'de> for LegacyTransaction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LegacyVisitor;

        impl<'de> serde::de::Visitor<'de> for LegacyVisitor {
            type Value = LegacyTransaction;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("LegacyTransaction (V1-V7 tuple format)")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;

                macro_rules! next {
                    ($name:literal) => {
                        seq.next_element()?
                            .ok_or_else(|| A::Error::missing_field($name))?
                    };
                }

                let version: u32 = next!("version");
                let chain_id: u8 = next!("chain_id");
                let transaction_type: TransactionType = next!("transaction_type");
                let inputs: Vec<TransactionInput> = next!("inputs");
                let outputs: Vec<TransactionOutput> = next!("outputs");
                let fee: u64 = next!("fee");
                let signature: Signature = next!("signature");
                let memo: Vec<u8> = next!("memo");
                let identity_data: Option<IdentityTransactionData> = next!("identity_data");
                let wallet_data: Option<WalletTransactionData> = next!("wallet_data");
                let validator_data: Option<ValidatorTransactionData> = next!("validator_data");
                let dao_proposal_data: Option<DaoProposalData> = next!("dao_proposal_data");
                let dao_vote_data: Option<DaoVoteData> = next!("dao_vote_data");
                let dao_execution_data: Option<DaoExecutionData> = next!("dao_execution_data");
                let ubi_claim_data: Option<UbiClaimData> = next!("ubi_claim_data");
                let profit_declaration_data: Option<ProfitDeclarationData> =
                    next!("profit_declaration_data");
                let token_transfer_data: Option<TokenTransferData> =
                    next!("token_transfer_data");
                let token_mint_data: Option<TokenMintData> = if version >= TX_VERSION_V2 {
                    next!("token_mint_data")
                } else {
                    None
                };
                let governance_config_data: Option<GovernanceConfigUpdateData> =
                    next!("governance_config_data");
                let (
                    bonding_curve_deploy_data,
                    bonding_curve_buy_data,
                    bonding_curve_sell_data,
                    bonding_curve_graduate_data,
                ) = if version >= TX_VERSION_V3 {
                    (
                        next!("bonding_curve_deploy_data"),
                        next!("bonding_curve_buy_data"),
                        next!("bonding_curve_sell_data"),
                        next!("bonding_curve_graduate_data"),
                    )
                } else {
                    (None, None, None, None)
                };
                let (oracle_committee_update_data, oracle_config_update_data) =
                    if version >= TX_VERSION_V4 {
                        (
                            next!("oracle_committee_update_data"),
                            next!("oracle_config_update_data"),
                        )
                    } else {
                        (None, None)
                    };
                let oracle_attestation_data: Option<OracleAttestationData> =
                    if version >= TX_VERSION_V5 {
                        next!("oracle_attestation_data")
                    } else {
                        None
                    };
                let cancel_oracle_update_data: Option<CancelOracleUpdateData> =
                    if version >= TX_VERSION_V6 {
                        next!("cancel_oracle_update_data")
                    } else {
                        None
                    };
                let init_entity_registry_data: Option<InitEntityRegistryData> =
                    if version >= TX_VERSION_V7 {
                        next!("init_entity_registry_data")
                    } else {
                        None
                    };

                Ok(LegacyTransaction {
                    version,
                    chain_id,
                    transaction_type,
                    inputs,
                    outputs,
                    fee,
                    signature,
                    memo,
                    identity_data,
                    wallet_data,
                    validator_data,
                    dao_proposal_data,
                    dao_vote_data,
                    dao_execution_data,
                    ubi_claim_data,
                    profit_declaration_data,
                    token_transfer_data,
                    token_mint_data,
                    governance_config_data,
                    bonding_curve_deploy_data,
                    bonding_curve_buy_data,
                    bonding_curve_sell_data,
                    bonding_curve_graduate_data,
                    oracle_committee_update_data,
                    oracle_config_update_data,
                    oracle_attestation_data,
                    cancel_oracle_update_data,
                    init_entity_registry_data,
                })
            }
        }

        deserializer.deserialize_tuple(TX_FIELD_COUNT_V7, LegacyVisitor)
    }
}

/// Convert a V1-V7 LegacyTransaction into a V8 Transaction by mapping flat
/// `Option<FooData>` fields into the `TransactionPayload` enum.
///
/// Only the first populated data field wins; the old wire format guaranteed
/// at most one was Some per transaction.
impl From<LegacyTransaction> for Transaction {
    fn from(l: LegacyTransaction) -> Self {
        let payload = if let Some(d) = l.token_transfer_data {
            TransactionPayload::TokenTransfer(d)
        } else if let Some(d) = l.token_mint_data {
            TransactionPayload::TokenMint(d)
        } else if let Some(d) = l.identity_data {
            TransactionPayload::Identity(d)
        } else if let Some(d) = l.wallet_data {
            TransactionPayload::Wallet(d)
        } else if let Some(d) = l.validator_data {
            TransactionPayload::Validator(d)
        } else if let Some(d) = l.dao_proposal_data {
            TransactionPayload::DaoProposal(d)
        } else if let Some(d) = l.dao_vote_data {
            TransactionPayload::DaoVote(d)
        } else if let Some(d) = l.dao_execution_data {
            TransactionPayload::DaoExecution(d)
        } else if let Some(d) = l.ubi_claim_data {
            TransactionPayload::UbiClaim(d)
        } else if let Some(d) = l.profit_declaration_data {
            TransactionPayload::ProfitDeclaration(d)
        } else if let Some(d) = l.governance_config_data {
            TransactionPayload::GovernanceConfigUpdate(d)
        } else if let Some(d) = l.bonding_curve_deploy_data {
            TransactionPayload::BondingCurveDeploy(d)
        } else if let Some(d) = l.bonding_curve_buy_data {
            TransactionPayload::BondingCurveBuy(d)
        } else if let Some(d) = l.bonding_curve_sell_data {
            TransactionPayload::BondingCurveSell(d)
        } else if let Some(d) = l.bonding_curve_graduate_data {
            TransactionPayload::BondingCurveGraduate(d)
        } else if let Some(d) = l.oracle_committee_update_data {
            TransactionPayload::OracleCommitteeUpdate(d)
        } else if let Some(d) = l.oracle_config_update_data {
            TransactionPayload::OracleConfigUpdate(d)
        } else if let Some(d) = l.oracle_attestation_data {
            TransactionPayload::OracleAttestation(d)
        } else if let Some(d) = l.cancel_oracle_update_data {
            TransactionPayload::CancelOracleUpdate(d)
        } else if let Some(d) = l.init_entity_registry_data {
            TransactionPayload::InitEntityRegistry(d)
        } else {
            TransactionPayload::None
        };

        Transaction {
            version: TX_VERSION_V8, // upgrade to current version
            chain_id: l.chain_id,
            transaction_type: l.transaction_type,
            inputs: l.inputs,
            outputs: l.outputs,
            fee: l.fee,
            signature: l.signature,
            memo: l.memo,
            payload,
        }
    }
}

/// Try to decode `bytes` as a V1–V7 transaction and convert to V8.
///
/// Returns `None` if the bytes cannot be parsed as legacy format.
/// Logs a warning so operators can track how many old-format clients remain.
pub fn try_decode_legacy(bytes: &[u8]) -> Option<Transaction> {
    match bincode::deserialize::<LegacyTransaction>(bytes) {
        Ok(legacy) => {
            let version = legacy.version;
            let tx = Transaction::from(legacy);
            tracing::warn!(
                tx_version = version,
                tx_type = ?tx.transaction_type,
                "Decoded legacy V{} transaction — client should upgrade to V8 SDK",
                version,
            );
            Some(tx)
        }
        Err(_) => None,
    }
}
