//! IPC server — listens on a platform-native transport and dispatches queries
//! to the blockchain engine.
//!
//! - **Unix**: Unix domain socket
//! - **Windows**: TCP loopback (port written to path file for client discovery)

use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use super::{TransportListener, TransportStream};
use crate::blockchain::Blockchain;
use crate::query::BlockchainQuery;
use super::protocol::*;

/// Start the IPC server on the given socket path.
///
/// Spawns a background task that accepts connections and dispatches
/// requests to the blockchain. Each connection is handled concurrently.
///
/// - **Unix**: binds a `UnixListener` at `socket_path`
/// - **Windows**: binds a `TcpListener` on `127.0.0.1:0`, writes the assigned
///   port to `socket_path` as a text file for client discovery
pub async fn start_ipc_server(
    socket_path: &Path,
    blockchain: Arc<RwLock<Blockchain>>,
) -> std::io::Result<()> {
    // Remove stale socket file if it exists (Unix only)
    #[cfg(unix)]
    let _ = std::fs::remove_file(socket_path);

    #[cfg(unix)]
    let listener = TransportListener::bind(socket_path)?;

    #[cfg(not(unix))]
    let listener = {
        let l = TransportListener::bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap()).await?;
        let local_addr = l.local_addr()?;
        let port = local_addr.port();
        // Write the assigned port to the path file so the client can discover it
        tokio::fs::write(socket_path, port.to_string()).await?;
        info!("IPC server listening on 127.0.0.1:{} (port file: {})", port, socket_path.display());
        l
    };

    #[cfg(unix)]
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
    mut stream: TransportStream,
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
            IpcResponse::Wallet(bc.wallet_transaction_data(wallet_id))
        }
        IpcRequest::QueryValidator { did } => {
            let bc = blockchain.read().await;
            IpcResponse::Validator(bc.validator_info_by_did(did))
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
                crate::blockchain::SystemOriginator::IpcExternal,
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
