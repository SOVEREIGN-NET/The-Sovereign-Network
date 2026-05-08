//! IPC message types for blockchain engine communication.
//!
//! All messages are serialized with bincode and length-prefixed (4-byte LE u32).

use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::blockchain::ValidatorInfo;
use crate::transaction::{
    DaoExecutionData, DaoProposalData, DaoVoteData, IdentityTransactionData, Transaction,
    TxFeeConfig, WalletTransactionData,
};
use crate::types::Hash;

/// Request from services to blockchain engine.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    // ── Scalar queries ──────────────────────────────────────────────
    QueryHeight,
    QueryBlockCount,
    QueryPendingCount,
    QueryIdentityCount,
    QueryWalletCount,
    QueryValidatorCount,

    // ── Lookup queries ──────────────────────────────────────────────
    QueryBlock { height: u64 },
    QueryLatestBlock,
    QueryPendingTransactions,
    QueryIdentityExists { did: String },
    QueryIdentity { did: String },
    QueryAllIdentities,
    QueryWalletExists { wallet_id: String },
    QueryWallet { wallet_id: String },
    QueryValidator { did: String },
    QueryIsCouncilMember { did: String },
    QueryTxFeeConfig,

    // ── DAO queries ─────────────────────────────────────────────────
    QueryDaoProposals,
    QueryDaoProposal { proposal_id: Hash },
    QueryDaoVotes { proposal_id: Hash },
    QueryDaoExecutions,
    QueryDaoTreasuryBalance,

    // ── Token queries ───────────────────────────────────────────────
    QueryTokenBalance { token_id: [u8; 32], key_id: [u8; 32] },

    // ── Mutations ───────────────────────────────────────────────────
    SubmitTransaction { tx: Transaction },
    SubmitSystemTransaction { tx: Transaction },

    // ── Lifecycle ───────────────────────────────────────────────────
    Ping,
    Shutdown,
}

/// Response from blockchain engine to services.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    // ── Scalar results ──────────────────────────────────────────────
    Height(u64),
    Count(usize),
    Balance(u128),
    Bool(bool),

    // ── Data results ────────────────────────────────────────────────
    Block(Option<Block>),
    Transactions(Vec<Transaction>),
    Identity(Option<IdentityTransactionData>),
    AllIdentities(Vec<(String, IdentityTransactionData)>),
    Wallet(Option<WalletTransactionData>),
    Validator(Option<ValidatorInfo>),
    FeeConfig(TxFeeConfig),

    // ── DAO results ─────────────────────────────────────────────────
    DaoProposals(Vec<DaoProposalData>),
    DaoProposal(Option<DaoProposalData>),
    DaoVotes(Vec<DaoVoteData>),
    DaoExecutions(Vec<DaoExecutionData>),
    OptionalBalance(Option<u128>),

    // ── Mutation results ────────────────────────────────────────────
    Ok,
    Error(String),

    // ── Lifecycle ───────────────────────────────────────────────────
    Pong,
}

/// Length-prefixed frame: 4-byte LE length + bincode payload.
pub const FRAME_HEADER_SIZE: usize = 4;
pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024; // 64 MB

/// Encode a message to a length-prefixed frame.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, bincode::Error> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}
