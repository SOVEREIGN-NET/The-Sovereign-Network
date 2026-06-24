//! IPC server — listens on a Unix domain socket and dispatches queries
//! to the blockchain engine.

use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::blockchain::Blockchain;
use crate::query::BlockchainQuery;
use super::protocol::*;

/// Start the IPC server on the given Unix socket path.
///
/// Spawns a background task that accepts connections and dispatches
/// requests to the blockchain. Each connection is handled concurrently.
pub async fn start_ipc_server(
    socket_path: &Path,
    blockchain: Arc<RwLock<Blockchain>>,
) -> std::io::Result<()> {
    // Remove stale socket file if it exists
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!("IPC server listening on {}", socket_path.display());

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let bc = blockchain.clone();
                    tokio::spawn(handle_connection(stream, bc));
                }
                Err(e) => {
                    error!("IPC accept error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    blockchain: Arc<RwLock<Blockchain>>,
) {
    loop {
        // Read frame header (4-byte LE length)
        let mut len_buf = [0u8; FRAME_HEADER_SIZE];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return; // Connection closed
        }
        let payload_len = u32::from_le_bytes(len_buf) as usize;
        if payload_len > MAX_FRAME_SIZE {
            warn!("IPC frame too large: {} bytes", payload_len);
            return;
        }

        // Read payload
        let mut payload = vec![0u8; payload_len];
        if stream.read_exact(&mut payload).await.is_err() {
            return;
        }

        // Deserialize request
        let request: IpcRequest = match bincode::deserialize(&payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("IPC deserialize error: {}", e);
                let resp = encode_frame(&IpcResponse::Error(format!("Bad request: {}", e)))
                    .unwrap_or_default();
                let _ = stream.write_all(&resp).await;
                continue;
            }
        };

        // Dispatch and build response
        let response = dispatch_request(&request, &blockchain).await;

        // Send response
        match encode_frame(&response) {
            Ok(frame) => {
                if stream.write_all(&frame).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                error!("IPC serialize error: {}", e);
                return;
            }
        }

        // Handle shutdown
        if matches!(request, IpcRequest::Shutdown) {
            return;
        }
    }
}

async fn dispatch_request(
    request: &IpcRequest,
    blockchain: &Arc<RwLock<Blockchain>>,
) -> IpcResponse {
    match request {
        // ── Scalar queries ──────────────────────────────────────────
        IpcRequest::QueryHeight => {
            let bc = blockchain.read().await;
            IpcResponse::Height(bc.query_height())
        }
        IpcRequest::QueryBlockCount => {
            let bc = blockchain.read().await;
            IpcResponse::Count(bc.query_block_count())
        }
        IpcRequest::QueryPendingCount => {
            let bc = blockchain.read().await;
            IpcResponse::Count(bc.query_pending_count())
        }
        IpcRequest::QueryIdentityCount => {
            let bc = blockchain.read().await;
            IpcResponse::Count(bc.query_identity_count())
        }
        IpcRequest::QueryWalletCount => {
            let bc = blockchain.read().await;
            IpcResponse::Count(bc.query_wallet_count())
        }
        IpcRequest::QueryValidatorCount => {
            let bc = blockchain.read().await;
            IpcResponse::Count(bc.query_validator_count())
        }

        // ── Lookup queries ──────────────────────────────────────────
        IpcRequest::QueryBlock { height } => {
            let bc = blockchain.read().await;
            IpcResponse::Block(bc.query_block(*height))
        }
        IpcRequest::QueryLatestBlock => {
            let bc = blockchain.read().await;
            IpcResponse::Block(bc.query_latest_block().cloned())
        }
        IpcRequest::QueryPendingTransactions => {
            let bc = blockchain.read().await;
            IpcResponse::Transactions(bc.query_pending_transactions())
        }
        IpcRequest::QueryIdentityExists { did } => {
            let bc = blockchain.read().await;
            IpcResponse::Bool(bc.query_identity_exists(did))
        }
        IpcRequest::QueryIdentity { did } => {
            let bc = blockchain.read().await;
            IpcResponse::Identity(bc.identity_transaction_data(did))
        }
        IpcRequest::QueryAllIdentities => {
            let bc = blockchain.read().await;
            let owned: Vec<(String, crate::transaction::IdentityTransactionData)> = bc
                .identity_registry_snapshot()
                .into_iter()
                .collect();
            IpcResponse::AllIdentities(owned)
        }
        IpcRequest::QueryWalletExists { wallet_id } => {
            let bc = blockchain.read().await;
            IpcResponse::Bool(bc.query_wallet_exists(wallet_id))
        }
        IpcRequest::QueryWallet { wallet_id } => {
            let bc = blockchain.read().await;
            IpcResponse::Wallet(bc.query_wallet(wallet_id).cloned())
        }
        IpcRequest::QueryValidator { did } => {
            let bc = blockchain.read().await;
            IpcResponse::Validator(bc.query_validator(did).cloned())
        }
        IpcRequest::QueryIsCouncilMember { did } => {
            let bc = blockchain.read().await;
            IpcResponse::Bool(bc.query_is_council_member(did))
        }
        IpcRequest::QueryTxFeeConfig => {
            let bc = blockchain.read().await;
            IpcResponse::FeeConfig(bc.query_tx_fee_config().clone())
        }

        // ── DAO queries ─────────────────────────────────────────────
        IpcRequest::QueryDaoProposals => {
            let bc = blockchain.read().await;
            IpcResponse::DaoProposals(bc.query_dao_proposals())
        }
        IpcRequest::QueryDaoProposal { proposal_id } => {
            let bc = blockchain.read().await;
            IpcResponse::DaoProposal(bc.query_dao_proposal(proposal_id))
        }
        IpcRequest::QueryDaoVotes { proposal_id } => {
            let bc = blockchain.read().await;
            IpcResponse::DaoVotes(bc.query_dao_votes(proposal_id))
        }
        IpcRequest::QueryDaoExecutions => {
            let bc = blockchain.read().await;
            IpcResponse::DaoExecutions(bc.query_dao_executions())
        }
        IpcRequest::QueryDaoTreasuryBalance => {
            let bc = blockchain.read().await;
            IpcResponse::OptionalBalance(bc.query_dao_treasury_balance())
        }

        // ── Token queries ───────────────────────────────────────────
        IpcRequest::QueryTokenBalance { token_id, key_id } => {
            let bc = blockchain.read().await;
            IpcResponse::Balance(bc.query_token_balance(token_id, key_id))
        }

        // ── Mutations ───────────────────────────────────────────────
        IpcRequest::SubmitTransaction { tx } => {
            let mut bc = blockchain.write().await;
            match crate::query::BlockchainMutate::submit_transaction(&mut *bc, tx.clone()) {
                Ok(()) => IpcResponse::Ok,
                Err(e) => IpcResponse::Error(e.to_string()),
            }
        }
        IpcRequest::SubmitSystemTransaction { tx } => {
            let mut bc = blockchain.write().await;
            match crate::query::BlockchainMutate::submit_system_transaction(
                &mut *bc,
                tx.clone(),
                "ipc_external",
            ) {
                Ok(()) => IpcResponse::Ok,
                Err(e) => IpcResponse::Error(e.to_string()),
            }
        }

        // ── Lifecycle ───────────────────────────────────────────────
        IpcRequest::Ping => IpcResponse::Pong,
        IpcRequest::Shutdown => {
            info!("IPC shutdown requested");
            IpcResponse::Ok
        }
    }
}
