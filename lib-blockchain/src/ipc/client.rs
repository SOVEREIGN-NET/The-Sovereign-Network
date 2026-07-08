//! IPC client — connects to the blockchain engine via Unix domain socket
//! (Unix) or TCP loopback (Windows).
//!
//! Provides owned-type query methods equivalent to `BlockchainQuery`.
//! Can be used as a drop-in replacement for `Arc<RwLock<Blockchain>>` reads.

use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::warn;

use crate::block::Block;
use crate::blockchain::ValidatorInfo;
use crate::transaction::{
    DaoExecutionData, DaoProposalData, DaoVoteData, IdentityTransactionData, Transaction,
    TxFeeConfig, WalletTransactionData,
};
use crate::types::Hash;
use super::protocol::*;

// ── Platform-specific IPC types ──────────────────────────────────────
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
type IpcStream = UnixStream;

#[cfg(windows)]
use tokio::net::TcpStream;
#[cfg(windows)]
type IpcStream = TcpStream;

/// IPC client that connects to the blockchain engine.
///
/// Thread-safe: wraps the stream in a Mutex so multiple tasks can share it.
/// For higher throughput, consider a connection pool.
pub struct IpcClient {
    stream: Mutex<Option<IpcStream>>,
    socket_path: PathBuf,
}

impl IpcClient {
    /// Create a new client (does not connect yet).
    pub fn new(socket_path: &Path) -> Self {
        Self {
            stream: Mutex::new(None),
            socket_path: socket_path.to_path_buf(),
        }
    }

    /// Connect to the blockchain engine. Reconnects if already connected.
    ///
    /// On Unix: connects to the Unix domain socket at `socket_path`.
    /// On Windows: reads the TCP port from `socket_path` and connects to
    /// 127.0.0.1:{port}.
    pub async fn connect(&self) -> anyhow::Result<()> {
        #[cfg(unix)]
        let stream = UnixStream::connect(&self.socket_path).await?;

        #[cfg(windows)]
        let stream = {
            let port_str = std::fs::read_to_string(&self.socket_path)
                .map_err(|e| anyhow::anyhow!("Failed to read IPC port file '{}': {}", self.socket_path.display(), e))?;
            let port: u16 = port_str
                .trim()
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid IPC port in '{}': {}", self.socket_path.display(), e))?;
            TcpStream::connect(format!("127.0.0.1:{}", port)).await?
        };

        *self.stream.lock().await = Some(stream);
        Ok(())
    }

    /// Send a request and receive a response.
    async fn request(&self, req: &IpcRequest) -> anyhow::Result<IpcResponse> {
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("IPC not connected"))?;

        // Send request frame
        let frame = encode_frame(req)?;
        stream.write_all(&frame).await?;

        // Read response frame
        let mut len_buf = [0u8; FRAME_HEADER_SIZE];
        stream.read_exact(&mut len_buf).await?;
        let payload_len = u32::from_le_bytes(len_buf) as usize;
        if payload_len > MAX_FRAME_SIZE {
            return Err(anyhow::anyhow!("IPC response too large: {} bytes", payload_len));
        }

        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;

        Ok(bincode::deserialize(&payload)?)
    }

    // ── Query methods (owned return types) ──────────────────────────

    pub async fn query_height(&self) -> anyhow::Result<u64> {
        match self.request(&IpcRequest::QueryHeight).await? {
            IpcResponse::Height(h) => Ok(h),
            IpcResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_block_count(&self) -> anyhow::Result<usize> {
        match self.request(&IpcRequest::QueryBlockCount).await? {
            IpcResponse::Count(c) => Ok(c),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_block(&self, height: u64) -> anyhow::Result<Option<Block>> {
        match self.request(&IpcRequest::QueryBlock { height }).await? {
            IpcResponse::Block(b) => Ok(b),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_latest_block(&self) -> anyhow::Result<Option<Block>> {
        match self.request(&IpcRequest::QueryLatestBlock).await? {
            IpcResponse::Block(b) => Ok(b),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_pending_count(&self) -> anyhow::Result<usize> {
        match self.request(&IpcRequest::QueryPendingCount).await? {
            IpcResponse::Count(c) => Ok(c),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_identity_exists(&self, did: &str) -> anyhow::Result<bool> {
        match self.request(&IpcRequest::QueryIdentityExists { did: did.to_string() }).await? {
            IpcResponse::Bool(b) => Ok(b),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_identity(&self, did: &str) -> anyhow::Result<Option<IdentityTransactionData>> {
        match self.request(&IpcRequest::QueryIdentity { did: did.to_string() }).await? {
            IpcResponse::Identity(i) => Ok(i),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_identity_count(&self) -> anyhow::Result<usize> {
        match self.request(&IpcRequest::QueryIdentityCount).await? {
            IpcResponse::Count(c) => Ok(c),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_wallet_exists(&self, wallet_id: &str) -> anyhow::Result<bool> {
        match self.request(&IpcRequest::QueryWalletExists { wallet_id: wallet_id.to_string() }).await? {
            IpcResponse::Bool(b) => Ok(b),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_wallet(&self, wallet_id: &str) -> anyhow::Result<Option<WalletTransactionData>> {
        match self.request(&IpcRequest::QueryWallet { wallet_id: wallet_id.to_string() }).await? {
            IpcResponse::Wallet(w) => Ok(w),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_validator_count(&self) -> anyhow::Result<usize> {
        match self.request(&IpcRequest::QueryValidatorCount).await? {
            IpcResponse::Count(c) => Ok(c),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_validator(&self, did: &str) -> anyhow::Result<Option<ValidatorInfo>> {
        match self.request(&IpcRequest::QueryValidator { did: did.to_string() }).await? {
            IpcResponse::Validator(v) => Ok(v),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_is_council_member(&self, did: &str) -> anyhow::Result<bool> {
        match self.request(&IpcRequest::QueryIsCouncilMember { did: did.to_string() }).await? {
            IpcResponse::Bool(b) => Ok(b),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_token_balance(&self, token_id: &[u8; 32], key_id: &[u8; 32]) -> anyhow::Result<u128> {
        match self.request(&IpcRequest::QueryTokenBalance { token_id: *token_id, key_id: *key_id }).await? {
            IpcResponse::Balance(b) => Ok(b),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn query_dao_treasury_balance(&self) -> anyhow::Result<Option<u128>> {
        match self.request(&IpcRequest::QueryDaoTreasuryBalance).await? {
            IpcResponse::OptionalBalance(b) => Ok(b),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    // ── Mutation methods ────────────────────────────────────────────

    pub async fn submit_transaction(&self, tx: Transaction) -> anyhow::Result<()> {
        match self.request(&IpcRequest::SubmitTransaction { tx }).await? {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        match self.request(&IpcRequest::Ping).await? {
            IpcResponse::Pong => Ok(()),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }
}
