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
    Transaction, TransactionInput, TransactionOutput, TransactionPayload, UbiClaimData,
    ValidatorTransactionData, WalletTransactionData,
};
use crate::transaction::oracle_governance::{
    CancelOracleUpdateData, OracleAttestationData, OracleCommitteeUpdateData,
    OracleConfigUpdateData,
};
use crate::transaction::core::InitEntityRegistryData;
use crate::transaction::core::ProfitDeclarationData;
use crate::types::transaction_type::TransactionType;
use serde::{Deserialize, Deserializer, Serialize};

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

impl LegacyTransaction {
    fn into_transaction(self) -> Option<Transaction> {
        let LegacyTransaction {
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
        } = self;

        let payload = match transaction_type {
            TransactionType::IdentityRegistration
            | TransactionType::IdentityUpdate
            | TransactionType::IdentityRevocation => {
                identity_data.map(TransactionPayload::Identity)?
            }
            TransactionType::WalletRegistration | TransactionType::WalletUpdate => {
                wallet_data.map(TransactionPayload::Wallet)?
            }
            TransactionType::ValidatorRegistration
            | TransactionType::ValidatorUpdate
            | TransactionType::ValidatorUnregister => {
                validator_data.map(TransactionPayload::Validator)?
            }
            TransactionType::DaoProposal => {
                dao_proposal_data.map(TransactionPayload::DaoProposal)?
            }
            TransactionType::DaoVote => dao_vote_data.map(TransactionPayload::DaoVote)?,
            TransactionType::DaoExecution => {
                dao_execution_data.map(TransactionPayload::DaoExecution)?
            }
            TransactionType::UBIClaim => ubi_claim_data.map(TransactionPayload::UbiClaim)?,
            TransactionType::ProfitDeclaration => {
                profit_declaration_data.map(TransactionPayload::ProfitDeclaration)?
            }
            TransactionType::TokenTransfer => {
                token_transfer_data.map(TransactionPayload::TokenTransfer)?
            }
            TransactionType::TokenMint => token_mint_data.map(TransactionPayload::TokenMint)?,
            TransactionType::GovernanceConfigUpdate => {
                governance_config_data.map(TransactionPayload::GovernanceConfigUpdate)?
            }
            TransactionType::BondingCurveDeploy => {
                bonding_curve_deploy_data.map(TransactionPayload::BondingCurveDeploy)?
            }
            TransactionType::BondingCurveBuy => {
                bonding_curve_buy_data.map(TransactionPayload::BondingCurveBuy)?
            }
            TransactionType::BondingCurveSell => {
                bonding_curve_sell_data.map(TransactionPayload::BondingCurveSell)?
            }
            TransactionType::BondingCurveGraduate => {
                bonding_curve_graduate_data.map(TransactionPayload::BondingCurveGraduate)?
            }
            TransactionType::UpdateOracleCommittee => {
                oracle_committee_update_data.map(TransactionPayload::OracleCommitteeUpdate)?
            }
            TransactionType::UpdateOracleConfig => {
                oracle_config_update_data.map(TransactionPayload::OracleConfigUpdate)?
            }
            TransactionType::OracleAttestation => {
                oracle_attestation_data.map(TransactionPayload::OracleAttestation)?
            }
            TransactionType::CancelOracleUpdate => {
                cancel_oracle_update_data.map(TransactionPayload::CancelOracleUpdate)?
            }
            TransactionType::InitEntityRegistry => {
                init_entity_registry_data.map(TransactionPayload::InitEntityRegistry)?
            }
            _ => TransactionPayload::None,
        };

        Some(Transaction {
            version,
            chain_id,
            transaction_type,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload,
        })
    }
}

#[derive(Serialize)]
struct LegacyTransactionWire {
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

fn zero_signature_like(signature: &Signature) -> Signature {
    Signature {
        signature: Vec::new(),
        public_key: crate::integration::crypto_integration::PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id: [0u8; 32],
        },
        algorithm: signature.algorithm.clone(),
        timestamp: 0,
    }
}

fn legacy_wire_from_transaction(
    transaction: &Transaction,
    zero_signature: bool,
) -> Option<LegacyTransactionWire> {
    if !(transaction.version >= 1 && transaction.version <= TX_VERSION_V7) {
        return None;
    }

    let mut identity_data = None;
    let mut wallet_data = None;
    let mut validator_data = None;
    let mut dao_proposal_data = None;
    let mut dao_vote_data = None;
    let mut dao_execution_data = None;
    let mut ubi_claim_data = None;
    let mut profit_declaration_data = None;
    let mut token_transfer_data = None;
    let mut token_mint_data = None;
    let mut governance_config_data = None;
    let mut bonding_curve_deploy_data = None;
    let mut bonding_curve_buy_data = None;
    let mut bonding_curve_sell_data = None;
    let mut bonding_curve_graduate_data = None;
    let mut oracle_committee_update_data = None;
    let mut oracle_config_update_data = None;
    let mut oracle_attestation_data = None;
    let mut cancel_oracle_update_data = None;
    let mut init_entity_registry_data = None;

    match &transaction.payload {
        TransactionPayload::None => {}
        TransactionPayload::Identity(data) => identity_data = Some(data.clone()),
        TransactionPayload::Wallet(data) => wallet_data = Some(data.clone()),
        TransactionPayload::Validator(data) => validator_data = Some(data.clone()),
        TransactionPayload::DaoProposal(data) => dao_proposal_data = Some(data.clone()),
        TransactionPayload::DaoVote(data) => dao_vote_data = Some(data.clone()),
        TransactionPayload::DaoExecution(data) => dao_execution_data = Some(data.clone()),
        TransactionPayload::UbiClaim(data) => ubi_claim_data = Some(data.clone()),
        TransactionPayload::ProfitDeclaration(data) => {
            profit_declaration_data = Some(data.clone())
        }
        TransactionPayload::TokenTransfer(data) => token_transfer_data = Some(data.clone()),
        TransactionPayload::TokenMint(data) => token_mint_data = Some(data.clone()),
        TransactionPayload::GovernanceConfigUpdate(data) => {
            governance_config_data = Some(data.clone())
        }
        TransactionPayload::BondingCurveDeploy(data) => {
            bonding_curve_deploy_data = Some(data.clone())
        }
        TransactionPayload::BondingCurveBuy(data) => bonding_curve_buy_data = Some(data.clone()),
        TransactionPayload::BondingCurveSell(data) => {
            bonding_curve_sell_data = Some(data.clone())
        }
        TransactionPayload::BondingCurveGraduate(data) => {
            bonding_curve_graduate_data = Some(data.clone())
        }
        TransactionPayload::OracleCommitteeUpdate(data) => {
            oracle_committee_update_data = Some(data.clone())
        }
        TransactionPayload::OracleConfigUpdate(data) => {
            oracle_config_update_data = Some(data.clone())
        }
        TransactionPayload::OracleAttestation(data) => oracle_attestation_data = Some(data.clone()),
        TransactionPayload::CancelOracleUpdate(data) => {
            cancel_oracle_update_data = Some(data.clone())
        }
        TransactionPayload::InitEntityRegistry(data) => {
            init_entity_registry_data = Some(data.clone())
        }
        _ => return None,
    }

    Some(LegacyTransactionWire {
        version: transaction.version,
        chain_id: transaction.chain_id,
        transaction_type: transaction.transaction_type,
        inputs: transaction.inputs.clone(),
        outputs: transaction.outputs.clone(),
        fee: transaction.fee,
        signature: if zero_signature {
            zero_signature_like(&transaction.signature)
        } else {
            transaction.signature.clone()
        },
        memo: transaction.memo.clone(),
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

pub fn serialize_legacy_transaction(
    transaction: &Transaction,
    zero_signature: bool,
) -> Option<Vec<u8>> {
    let legacy = legacy_wire_from_transaction(transaction, zero_signature)?;
    bincode::serialize(&legacy).ok()
}

/// Try to decode `bytes` as a V1–V7 transaction and convert to V8.
///
/// Returns `None` if the bytes cannot be parsed as legacy format.
/// Logs a warning so operators can track how many old-format clients remain.
pub fn try_decode_legacy(bytes: &[u8]) -> Option<Transaction> {
    match bincode::deserialize::<LegacyTransaction>(bytes) {
        Ok(legacy) => {
            let version = legacy.version;
            let tx = legacy.into_transaction()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::PublicKey;
    use crate::transaction::core::TX_VERSION_V6;
    use lib_crypto::types::signatures::SignatureAlgorithm;

    fn signature() -> Signature {
        Signature {
            signature: vec![0xAA; 64],
            public_key: PublicKey::new(vec![0x42; 32]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn try_decode_legacy_preserves_version_and_payload() {
        let tx = Transaction {
            version: TX_VERSION_V6,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenTransfer,
            inputs: vec![],
            outputs: vec![],
            fee: 7,
            signature: signature(),
            memo: b"legacy".to_vec(),
            payload: TransactionPayload::TokenTransfer(TokenTransferData {
                token_id: [0x11; 32],
                from: [0x22; 32],
                to: [0x33; 32],
                amount: 55,
                nonce: 3,
            }),
        };

        let bytes = serialize_legacy_transaction(&tx, false).expect("legacy bytes");
        let decoded = try_decode_legacy(&bytes).expect("legacy tx should decode");

        assert_eq!(decoded.version, TX_VERSION_V6);
        assert_eq!(decoded.transaction_type, TransactionType::TokenTransfer);
        match decoded.payload {
            TransactionPayload::TokenTransfer(data) => {
                assert_eq!(data.amount, 55);
                assert_eq!(data.nonce, 3);
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn try_decode_legacy_rejects_missing_expected_payload() {
        let legacy = LegacyTransactionWire {
            version: TX_VERSION_V6,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenTransfer,
            inputs: vec![],
            outputs: vec![],
            fee: 7,
            signature: signature(),
            memo: b"legacy".to_vec(),
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            token_mint_data: None,
            governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
            oracle_committee_update_data: None,
            oracle_config_update_data: None,
            oracle_attestation_data: None,
            cancel_oracle_update_data: None,
            init_entity_registry_data: None,
        };

        let bytes = bincode::serialize(&legacy).expect("legacy bytes");
        assert!(try_decode_legacy(&bytes).is_none());
    }

    #[test]
    fn try_decode_legacy_preserves_token_mint_payload() {
        let tx = Transaction {
            version: TX_VERSION_V6,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenMint,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: signature(),
            memo: b"legacy-mint".to_vec(),
            payload: TransactionPayload::TokenMint(TokenMintData {
                token_id: [0x91; 32],
                to: [0x92; 32],
                amount: 77,
            }),
        };

        let bytes = serialize_legacy_transaction(&tx, false).expect("legacy bytes");
        let decoded = try_decode_legacy(&bytes).expect("legacy token mint should decode");

        assert_eq!(decoded.version, TX_VERSION_V6);
        match decoded.payload {
            TransactionPayload::TokenMint(data) => {
                assert_eq!(data.amount, 77);
                assert_eq!(data.to, [0x92; 32]);
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn try_decode_legacy_rejects_malformed_tuple_bytes() {
        assert!(try_decode_legacy(&[0x01, 0x02, 0x03]).is_none());
    }
}
