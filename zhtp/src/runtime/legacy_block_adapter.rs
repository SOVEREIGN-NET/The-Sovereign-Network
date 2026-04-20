use anyhow::{anyhow, Result};
use lib_blockchain::transaction::{
    BondingCurveBuyData, BondingCurveDeployData, BondingCurveGraduateData, BondingCurveSellData,
    CancelOracleUpdateData, DaoExecutionData, DaoProposalData, DaoVoteData,
    GovernanceConfigUpdateData, IdentityTransactionData, InitEntityRegistryData, TokenMintData,
    TokenTransferData, Transaction, TransactionInput, TransactionOutput, TransactionPayload,
    UbiClaimData, ValidatorTransactionData, WalletTransactionData,
};
use lib_blockchain::types::transaction_type::TransactionType;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
struct LegacyBlock {
    header: lib_blockchain::block::BlockHeader,
    transactions: Vec<LegacyTransaction>,
}

#[derive(Debug, Clone)]
struct LegacyTransaction {
    version: u32,
    chain_id: u8,
    transaction_type: TransactionType,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    signature: lib_blockchain::integration::crypto_integration::Signature,
    memo: Vec<u8>,
    identity_data: Option<IdentityTransactionData>,
    wallet_data: Option<WalletTransactionData>,
    validator_data: Option<ValidatorTransactionData>,
    dao_proposal_data: Option<DaoProposalData>,
    dao_vote_data: Option<DaoVoteData>,
    dao_execution_data: Option<DaoExecutionData>,
    ubi_claim_data: Option<UbiClaimData>,
    profit_declaration_data: Option<lib_blockchain::transaction::ProfitDeclarationData>,
    token_transfer_data: Option<TokenTransferData>,
    token_mint_data: Option<TokenMintData>,
    governance_config_data: Option<GovernanceConfigUpdateData>,
    bonding_curve_deploy_data: Option<BondingCurveDeployData>,
    bonding_curve_buy_data: Option<BondingCurveBuyData>,
    bonding_curve_sell_data: Option<BondingCurveSellData>,
    bonding_curve_graduate_data: Option<BondingCurveGraduateData>,
    oracle_committee_update_data: Option<lib_blockchain::transaction::OracleCommitteeUpdateData>,
    oracle_config_update_data: Option<lib_blockchain::transaction::OracleConfigUpdateData>,
    oracle_attestation_data: Option<lib_blockchain::transaction::OracleAttestationData>,
    cancel_oracle_update_data: Option<CancelOracleUpdateData>,
    init_entity_registry_data: Option<InitEntityRegistryData>,
}

impl<'de> Deserialize<'de> for LegacyTransaction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TxVisitor;

        impl<'de> serde::de::Visitor<'de> for TxVisitor {
            type Value = LegacyTransaction;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("legacy transaction tuple (v1..v7)")
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
                let signature: lib_blockchain::integration::crypto_integration::Signature =
                    next!("signature");
                let memo: Vec<u8> = next!("memo");
                let identity_data: Option<IdentityTransactionData> = next!("identity_data");
                let wallet_data: Option<WalletTransactionData> = next!("wallet_data");
                let validator_data: Option<ValidatorTransactionData> = next!("validator_data");
                let dao_proposal_data: Option<DaoProposalData> = next!("dao_proposal_data");
                let dao_vote_data: Option<DaoVoteData> = next!("dao_vote_data");
                let dao_execution_data: Option<DaoExecutionData> = next!("dao_execution_data");
                let ubi_claim_data: Option<UbiClaimData> = next!("ubi_claim_data");
                let profit_declaration_data: Option<lib_blockchain::transaction::ProfitDeclarationData> =
                    next!("profit_declaration_data");
                let token_transfer_data: Option<TokenTransferData> = next!("token_transfer_data");

                let token_mint_data: Option<TokenMintData> = if version >= 2 {
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
                ) = if version >= 3 {
                    (
                        next!("bonding_curve_deploy_data"),
                        next!("bonding_curve_buy_data"),
                        next!("bonding_curve_sell_data"),
                        next!("bonding_curve_graduate_data"),
                    )
                } else {
                    (None, None, None, None)
                };

                let (oracle_committee_update_data, oracle_config_update_data) = if version >= 4 {
                    (
                        next!("oracle_committee_update_data"),
                        next!("oracle_config_update_data"),
                    )
                } else {
                    (None, None)
                };

                let oracle_attestation_data: Option<lib_blockchain::transaction::OracleAttestationData> =
                    if version >= 5 {
                        next!("oracle_attestation_data")
                    } else {
                        None
                    };

                let cancel_oracle_update_data: Option<CancelOracleUpdateData> =
                    if version >= 6 {
                        next!("cancel_oracle_update_data")
                    } else {
                        None
                    };

                let init_entity_registry_data: Option<InitEntityRegistryData> = if version >= 7 {
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

        deserializer.deserialize_tuple(28, TxVisitor)
    }
}

pub(crate) fn decode_legacy_block_page(body: &[u8]) -> Result<Vec<lib_blockchain::Block>> {
    let legacy_blocks: Vec<LegacyBlock> = bincode::deserialize(body)
        .map_err(|e| anyhow!("LegacyBlockDecodeFailed: {}", e))?;
    let mut converted = Vec::with_capacity(legacy_blocks.len());
    for (block_idx, block) in legacy_blocks.into_iter().enumerate() {
        let block_height = block.header.height;
        let mut txs = Vec::with_capacity(block.transactions.len());
        for (tx_idx, tx) in block.transactions.into_iter().enumerate() {
            let tx_type = tx.transaction_type;
            let tx_current = convert_legacy_transaction(tx).map_err(|e| {
                anyhow!(
                    "IncompatibleLegacyTx: block_height={} block_index={} tx_index={} tx_type={:?}: {}",
                    block_height,
                    block_idx,
                    tx_idx,
                    tx_type,
                    e
                )
            })?;
            txs.push(tx_current);
        }
        converted.push(lib_blockchain::Block::new(block.header, txs));
    }
    Ok(converted)
}

fn convert_legacy_transaction(tx: LegacyTransaction) -> Result<Transaction> {
    let payload = match tx.transaction_type {
        TransactionType::IdentityRegistration
        | TransactionType::IdentityUpdate
        | TransactionType::IdentityRevocation => TransactionPayload::Identity(
            tx.identity_data
                .ok_or_else(|| anyhow!("missing legacy identity_data"))?,
        ),
        TransactionType::WalletRegistration | TransactionType::WalletUpdate => {
            TransactionPayload::Wallet(
                tx.wallet_data
                    .ok_or_else(|| anyhow!("missing legacy wallet_data"))?,
            )
        }
        TransactionType::ValidatorRegistration
        | TransactionType::ValidatorUpdate
        | TransactionType::ValidatorUnregister => TransactionPayload::Validator(
            tx.validator_data
                .ok_or_else(|| anyhow!("missing legacy validator_data"))?,
        ),
        TransactionType::DaoProposal => TransactionPayload::DaoProposal(
            tx.dao_proposal_data
                .ok_or_else(|| anyhow!("missing legacy dao_proposal_data"))?,
        ),
        TransactionType::DaoVote => TransactionPayload::DaoVote(
            tx.dao_vote_data
                .ok_or_else(|| anyhow!("missing legacy dao_vote_data"))?,
        ),
        TransactionType::DaoExecution => TransactionPayload::DaoExecution(
            tx.dao_execution_data
                .ok_or_else(|| anyhow!("missing legacy dao_execution_data"))?,
        ),
        TransactionType::UBIClaim => TransactionPayload::UbiClaim(
            tx.ubi_claim_data
                .ok_or_else(|| anyhow!("missing legacy ubi_claim_data"))?,
        ),
        TransactionType::ProfitDeclaration => TransactionPayload::ProfitDeclaration(
            tx.profit_declaration_data
                .ok_or_else(|| anyhow!("missing legacy profit_declaration_data"))?,
        ),
        TransactionType::TokenTransfer => TransactionPayload::TokenTransfer(
            tx.token_transfer_data
                .ok_or_else(|| anyhow!("missing legacy token_transfer_data"))?,
        ),
        TransactionType::TokenMint => TransactionPayload::TokenMint(
            tx.token_mint_data
                .ok_or_else(|| anyhow!("missing legacy token_mint_data"))?,
        ),
        TransactionType::GovernanceConfigUpdate => TransactionPayload::GovernanceConfigUpdate(
            tx.governance_config_data
                .ok_or_else(|| anyhow!("missing legacy governance_config_data"))?,
        ),
        TransactionType::BondingCurveDeploy => TransactionPayload::BondingCurveDeploy(
            tx.bonding_curve_deploy_data
                .ok_or_else(|| anyhow!("missing legacy bonding_curve_deploy_data"))?,
        ),
        TransactionType::BondingCurveBuy => TransactionPayload::BondingCurveBuy(
            tx.bonding_curve_buy_data
                .ok_or_else(|| anyhow!("missing legacy bonding_curve_buy_data"))?,
        ),
        TransactionType::BondingCurveSell => TransactionPayload::BondingCurveSell(
            tx.bonding_curve_sell_data
                .ok_or_else(|| anyhow!("missing legacy bonding_curve_sell_data"))?,
        ),
        TransactionType::BondingCurveGraduate => TransactionPayload::BondingCurveGraduate(
            tx.bonding_curve_graduate_data
                .ok_or_else(|| anyhow!("missing legacy bonding_curve_graduate_data"))?,
        ),
        TransactionType::UpdateOracleCommittee => TransactionPayload::OracleCommitteeUpdate(
            tx.oracle_committee_update_data
                .ok_or_else(|| anyhow!("missing legacy oracle_committee_update_data"))?,
        ),
        TransactionType::UpdateOracleConfig => TransactionPayload::OracleConfigUpdate(
            tx.oracle_config_update_data
                .ok_or_else(|| anyhow!("missing legacy oracle_config_update_data"))?,
        ),
        TransactionType::OracleAttestation => TransactionPayload::OracleAttestation(
            tx.oracle_attestation_data
                .ok_or_else(|| anyhow!("missing legacy oracle_attestation_data"))?,
        ),
        TransactionType::CancelOracleUpdate => TransactionPayload::CancelOracleUpdate(
            tx.cancel_oracle_update_data
                .ok_or_else(|| anyhow!("missing legacy cancel_oracle_update_data"))?,
        ),
        TransactionType::InitEntityRegistry => TransactionPayload::InitEntityRegistry(
            tx.init_entity_registry_data
                .ok_or_else(|| anyhow!("missing legacy init_entity_registry_data"))?,
        ),
        TransactionType::Transfer
        | TransactionType::Coinbase
        | TransactionType::ContractDeployment
        | TransactionType::ContractExecution
        | TransactionType::SessionCreation
        | TransactionType::SessionTermination
        | TransactionType::ContentUpload
        | TransactionType::UbiDistribution
        | TransactionType::DifficultyUpdate => TransactionPayload::None,
        _ => {
            return Err(anyhow!(
                "unsupported legacy transaction type {:?}",
                tx.transaction_type
            ))
        }
    };

    Ok(Transaction {
        version: tx.version,
        chain_id: tx.chain_id,
        transaction_type: tx.transaction_type,
        inputs: tx.inputs,
        outputs: tx.outputs,
        fee: tx.fee,
        signature: tx.signature,
        memo: tx.memo,
        payload,
    })
}
