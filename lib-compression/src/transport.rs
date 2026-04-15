//! QUIC-based transport layer for shard distribution
//!
//! This module provides high-performance parallel shard transmission using QUIC streams.
//! Integrates with lib-network's `ShardProtocolHandler` and `QuicMeshProtocol` for real
//! peer-to-peer shard storage and retrieval over the ZHTP mesh.
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────┐
//!  │  lib-compression::ShardTransport (Client)    │
//!  │  ───────────────────────────────────────     │
//!  │  store_shard_remote() → Serialize → QUIC →   │
//!  │  fetch_shard_remote() ← Deserialize ← QUIC ←│
//!  └──────────────────┬──────────────────────────┘
//!                     │ bincode over QUIC UNI streams
//!  ┌──────────────────▼──────────────────────────┐
//!  │  lib-network::ShardProtocolHandler (Server)  │
//!  │  ───────────────────────────────────────     │
//!  │  handle_message() → ShardStorage             │
//!  └─────────────────────────────────────────────┘
//! ```

use crate::error::{CompressionError, Result};
use crate::shard::{Shard, ShardId};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

// Re-use the shard protocol message types from lib-network
use lib_network::protocols::shard_protocol::{
    ShardProtocolMessage, ShardProtocolHandler, SHARD_PROTOCOL_VERSION, MAX_SHARD_SIZE,
};
use lib_network::protocols::quic_mesh::QuicMeshProtocol;

/// Configuration for shard transport
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum parallel QUIC streams
    pub max_parallel_streams: usize,

    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,

    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,

    /// Maximum retry attempts
    pub max_retries: usize,

    /// Enable compression for shard data in transit
    pub enable_compression: bool,

    /// Local node identifier
    pub local_node_id: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_parallel_streams: 10,
            connect_timeout_ms: 5000,
            request_timeout_ms: 30000,
            max_retries: 3,
            enable_compression: true,
            local_node_id: format!("node-{}", std::process::id()),
        }
    }
}

/// QUIC-based transport for shard storage and retrieval
///
/// Integrates with lib-network's `ShardProtocolHandler` for message handling
/// and uses QUIC streams for encrypted peer-to-peer transmission.
///
/// When no QUIC mesh is available (e.g. testing), routes through the local
/// `ShardProtocolHandler` for in-process shard storage/fetch.
pub struct ShardTransport {
    config: TransportConfig,
    parallel_limiter: Arc<Semaphore>,
    /// Local protocol handler for in-process shard storage (always available)
    local_handler: Arc<ShardProtocolHandler>,
    /// Optional QUIC mesh for real peer-to-peer shard distribution
    quic_mesh: Option<Arc<QuicMeshProtocol>>,
}

impl ShardTransport {
    /// Create new shard transport with default configuration
    pub fn new() -> Self {
        Self::with_config(TransportConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: TransportConfig) -> Self {
        let parallel_limiter = Arc::new(Semaphore::new(config.max_parallel_streams));

        // 256 MB local storage capacity
        let local_handler = Arc::new(ShardProtocolHandler::new(
            config.local_node_id.clone(),
            256 * 1024 * 1024,
        ));

        info!(
            "Initialized ShardTransport [node={}] with {} parallel streams, {}ms timeout",
            config.local_node_id, config.max_parallel_streams, config.request_timeout_ms
        );

        Self {
            config,
            parallel_limiter,
            local_handler,
            quic_mesh: None,
        }
    }

    /// Attach a QUIC mesh protocol for remote peer-to-peer shard transport
    pub fn with_quic_mesh(mut self, mesh: Arc<QuicMeshProtocol>) -> Self {
        self.quic_mesh = Some(mesh);
        self
    }

    /// Set QUIC mesh after construction
    pub fn set_quic_mesh(&mut self, mesh: Arc<QuicMeshProtocol>) {
        self.quic_mesh = Some(mesh);
    }

    /// Get reference to the local shard protocol handler
    pub fn local_handler(&self) -> &Arc<ShardProtocolHandler> {
        &self.local_handler
    }

    /// Store shard via the shard protocol
    ///
    /// Serializes a `ShardProtocolMessage::StoreRequest`, sends it to the
    /// local handler (or over QUIC to a remote node), and validates the response.
    pub async fn store_shard_remote(
        &self,
        node_address: SocketAddr,
        shard: &Shard,
        ttl_seconds: u64,
    ) -> Result<bool> {
        // Acquire semaphore permit for parallelism control
        let _permit = self.parallel_limiter.acquire().await
            .map_err(|e| CompressionError::TransportFailed(format!("Semaphore error: {}", e)))?;

        debug!(
            "Storing shard {} on node {} (size: {} bytes)",
            shard.id, node_address, shard.size
        );

        // Validate shard size against protocol limits
        if shard.size > MAX_SHARD_SIZE {
            return Err(CompressionError::TransportFailed(format!(
                "Shard {} exceeds max size: {} > {} bytes",
                shard.id, shard.size, MAX_SHARD_SIZE
            )));
        }

        // Build protocol message
        let request = ShardProtocolMessage::StoreRequest {
            version: SHARD_PROTOCOL_VERSION,
            shard_id: shard.id.0,
            data: Bytes::from(shard.data.clone()),
            ttl_seconds,
            requester: self.config.local_node_id.clone(),
        };

        // Try QUIC remote transport first if available and the target is not the local node
        if let Some(ref mesh) = self.quic_mesh {
            let local_addr = mesh.local_addr();
            if node_address != local_addr {
                debug!("Attempting QUIC remote store to {} for shard {}", node_address, shard.id);

                let serialized = bincode::serialize(&request)
                    .map_err(|e| CompressionError::TransportFailed(
                        format!("Failed to serialize store request: {}", e),
                    ))?;

                match mesh.send_request_to_addr(
                    node_address,
                    &serialized,
                    // Response is small (StoreResponse)
                    64 * 1024,
                ).await {
                    Ok(response_bytes) => {
                        let response: ShardProtocolMessage = bincode::deserialize(&response_bytes)
                            .map_err(|e| CompressionError::TransportFailed(
                                format!("Failed to deserialize store response: {}", e),
                            ))?;

                        return match response {
                            ShardProtocolMessage::StoreResponse { stored, error, .. } => {
                                if !stored {
                                    warn!("Shard {} storage rejected by remote {}: {:?}", shard.id, node_address, error);
                                }
                                Ok(stored)
                            }
                            _ => Err(CompressionError::TransportFailed(
                                "Unexpected response to remote store request".into(),
                            )),
                        };
                    }
                    Err(e) => {
                        warn!("QUIC remote store failed for shard {} at {}: {}. Falling back to local handler.", shard.id, node_address, e);
                        // Fall through to local handler
                    }
                }
            }
        }

        // Dispatch to local handler (in-process fallback).
        let response = self
            .local_handler
            .handle_message(request, self.config.local_node_id.clone())
            .await
            .map_err(|e| CompressionError::TransportFailed(e))?;

        match response {
            ShardProtocolMessage::StoreResponse {
                stored, error, ..
            } => {
                if !stored {
                    warn!("Shard {} storage rejected: {:?}", shard.id, error);
                }
                Ok(stored)
            }
            _ => Err(CompressionError::TransportFailed(
                "Unexpected response to store request".into(),
            )),
        }
    }

    /// Fetch shard via the shard protocol
    ///
    /// Sends a `FetchRequest` and reconstructs the `Shard` from the response.
    pub async fn fetch_shard_remote(
        &self,
        node_address: SocketAddr,
        shard_id: ShardId,
        requester_id: String,
    ) -> Result<Shard> {
        // Acquire semaphore permit for parallelism control
        let _permit = self.parallel_limiter.acquire().await
            .map_err(|e| CompressionError::TransportFailed(format!("Semaphore error: {}", e)))?;

        debug!("Fetching shard {} from node {}", shard_id, node_address);

        // Build protocol message
        let request = ShardProtocolMessage::FetchRequest {
            version: SHARD_PROTOCOL_VERSION,
            shard_id: shard_id.0,
            requester: requester_id,
        };

        // Try QUIC remote transport first if available and target is not the local node
        if let Some(ref mesh) = self.quic_mesh {
            let local_addr = mesh.local_addr();
            if node_address != local_addr {
                debug!("Attempting QUIC remote fetch of shard {} from {}", shard_id, node_address);

                let serialized = bincode::serialize(&request)
                    .map_err(|e| CompressionError::TransportFailed(
                        format!("Failed to serialize fetch request: {}", e),
                    ))?;

                match mesh.send_request_to_addr(
                    node_address,
                    &serialized,
                    // Shard data can be up to MAX_SHARD_SIZE
                    MAX_SHARD_SIZE + 1024,
                ).await {
                    Ok(response_bytes) => {
                        let response: ShardProtocolMessage = bincode::deserialize(&response_bytes)
                            .map_err(|e| CompressionError::TransportFailed(
                                format!("Failed to deserialize fetch response: {}", e),
                            ))?;

                        return match response {
                            ShardProtocolMessage::FetchResponse {
                                shard_id: resp_id,
                                data: Some(data),
                                ..
                            } => {
                                if resp_id != shard_id.0 {
                                    return Err(CompressionError::TransportFailed(
                                        "Shard ID mismatch in remote response".into(),
                                    ));
                                }
                                Ok(Shard::new(data.to_vec()))
                            }
                            ShardProtocolMessage::FetchResponse { data: None, .. } => {
                                Err(CompressionError::ShardNotFound(shard_id.to_string()))
                            }
                            _ => Err(CompressionError::TransportFailed(
                                "Unexpected response to remote fetch request".into(),
                            )),
                        };
                    }
                    Err(e) => {
                        warn!("QUIC remote fetch failed for shard {} from {}: {}. Falling back to local handler.", shard_id, node_address, e);
                        // Fall through to local handler
                    }
                }
            }
        }

        // Fall back to local handler (in-process)
        let response = self
            .local_handler
            .handle_message(request, self.config.local_node_id.clone())
            .await
            .map_err(|e| CompressionError::TransportFailed(e))?;

        match response {
            ShardProtocolMessage::FetchResponse {
                shard_id: resp_id,
                data: Some(data),
                ..
            } => {
                if resp_id != shard_id.0 {
                    return Err(CompressionError::TransportFailed(
                        "Shard ID mismatch in response".into(),
                    ));
                }
                Ok(Shard::new(data.to_vec()))
            }
            ShardProtocolMessage::FetchResponse { data: None, .. } => {
                Err(CompressionError::ShardNotFound(shard_id.to_string()))
            }
            _ => Err(CompressionError::TransportFailed(
                "Unexpected response to fetch request".into(),
            )),
        }
    }

    /// Fetch multiple shards in parallel using multiple QUIC streams
    ///
    /// Provides massive bandwidth aggregation by fetching from different nodes concurrently.
    /// With 10 nodes @ 100 Mbps each = 1 Gbps effective bandwidth.
    pub async fn fetch_shards_parallel(
        &self,
        requests: Vec<(SocketAddr, ShardId, String)>,
    ) -> Result<Vec<Shard>> {
        use futures::stream::{self, StreamExt};

        info!(
            "Fetching {} shards in parallel (max {} concurrent)",
            requests.len(),
            self.config.max_parallel_streams
        );

        let results = stream::iter(requests)
            .map(|(addr, id, requester)| async move {
                let mut attempts = 0;
                let max_attempts = self.config.max_retries;

                loop {
                    match self.fetch_shard_remote(addr, id, requester.clone()).await {
                        Ok(shard) => return Ok(shard),
                        Err(e) if attempts < max_attempts => {
                            attempts += 1;
                            let delay_ms = 100 * (1 << attempts);
                            warn!(
                                "Fetch failed for shard {} (attempt {}/{}): {}. Retrying in {}ms...",
                                id, attempts, max_attempts, e, delay_ms
                            );
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        }
                        Err(e) => {
                            return Err(CompressionError::TransportFailed(format!(
                                "Failed to fetch shard {} after {} attempts: {}",
                                id, attempts, e
                            )));
                        }
                    }
                }
            })
            .buffer_unordered(self.config.max_parallel_streams)
            .collect::<Vec<_>>()
            .await;

        results.into_iter().collect()
    }

    /// Query which nodes are storing a specific shard
    pub async fn query_storage_nodes(
        &self,
        _bootstrap_node: SocketAddr,
        shard_id: ShardId,
    ) -> Result<Vec<(String, SocketAddr)>> {
        let request = ShardProtocolMessage::QueryNodesRequest {
            version: SHARD_PROTOCOL_VERSION,
            shard_id: shard_id.0,
            max_results: 20,
        };

        let response = self
            .local_handler
            .handle_message(request, self.config.local_node_id.clone())
            .await
            .map_err(|e| CompressionError::TransportFailed(e))?;

        match response {
            ShardProtocolMessage::QueryNodesResponse { nodes, .. } => Ok(nodes),
            _ => Ok(Vec::new()),
        }
    }

    /// Clean up expired shards in local storage
    pub async fn cleanup_expired(&self) {
        self.local_handler.cleanup_expired().await;
    }

    /// Get protocol statistics
    pub async fn get_stats(&self) -> lib_network::protocols::shard_protocol::ShardProtocolStats {
        self.local_handler.get_stats().await
    }
}

impl Default for ShardTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_creation() {
        let transport = ShardTransport::new();
        assert_eq!(transport.config.max_parallel_streams, 10);
    }

    #[tokio::test]
    async fn test_store_and_fetch_shard() {
        let transport = ShardTransport::new();
        let shard = Shard::new(vec![1, 2, 3, 4, 5]);
        let shard_id = shard.id;
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Store should succeed via local handler
        let result = transport.store_shard_remote(addr, &shard, 3600).await;
        assert!(result.is_ok(), "Store failed: {:?}", result);
        assert!(result.unwrap(), "Store returned false");

        // Fetch the stored shard
        let fetched = transport.fetch_shard_remote(addr, shard_id, "test".into()).await;
        assert!(fetched.is_ok(), "Fetch failed: {:?}", fetched);
        assert_eq!(fetched.unwrap().data, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_fetch_not_found() {
        let transport = ShardTransport::new();
        let shard_id = ShardId::from_data(&[99, 99, 99]);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let result = transport.fetch_shard_remote(addr, shard_id, "test".into()).await;
        assert!(result.is_err(), "Should fail for unknown shard");
    }

    #[tokio::test]
    async fn test_parallel_fetch() {
        let transport = ShardTransport::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Store some shards first
        let shard1 = Shard::new(vec![10, 20, 30]);
        let shard2 = Shard::new(vec![40, 50, 60]);
        transport
            .store_shard_remote(addr, &shard1, 3600)
            .await
            .unwrap();
        transport
            .store_shard_remote(addr, &shard2, 3600)
            .await
            .unwrap();

        // Parallel fetch
        let requests = vec![
            (addr, shard1.id, "test".into()),
            (addr, shard2.id, "test".into()),
        ];

        let result = transport.fetch_shards_parallel(requests).await;
        assert!(result.is_ok(), "Parallel fetch failed: {:?}", result);
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let transport = ShardTransport::new();
        let shard = Shard::new(vec![1, 2, 3]);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        transport
            .store_shard_remote(addr, &shard, 3600)
            .await
            .unwrap();

        let stats = transport.get_stats().await;
        assert_eq!(stats.store_requests, 1);
        assert_eq!(stats.store_success, 1);
        assert_eq!(stats.bytes_stored, 3);
    }
}
