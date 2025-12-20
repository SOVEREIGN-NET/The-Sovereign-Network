//! Chunked Upload Handler for Web4 Content
//!
//! Handles large file uploads by splitting them into chunks:
//! - POST /api/v1/web4/content/upload/init - Create upload session
//! - POST /api/v1/web4/content/upload/{id}/chunk/{index} - Upload chunk
//! - POST /api/v1/web4/content/upload/{id}/finalize - Assemble chunks
//! - GET  /api/v1/web4/content/upload/{id}/status - Check upload status
//!
//! ## Limits (configurable via UploadLimits)
//! - Max file size: 100MB default
//! - Max chunk size: 5MB default
//! - Max concurrent sessions per user: 3 default
//! - Max total sessions: 100 default
//!
//! ## TODO: Post-Alpha Storage Integration
//! Currently chunks are stored in-memory. For production:
//! - Stream chunks directly to blob storage (DHT/S3/disk)
//! - Use memory-mapped files for large uploads
//! - Implement resumable uploads with persistent session state

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use anyhow::anyhow;

/// Upload limits configuration
#[derive(Debug, Clone)]
pub struct UploadLimits {
    /// Maximum file size in bytes (default: 100MB)
    pub max_file_size: usize,
    /// Maximum chunk size in bytes (default: 5MB)
    pub max_chunk_size: usize,
    /// Minimum chunk size in bytes (default: 64KB)
    pub min_chunk_size: usize,
    /// Maximum concurrent sessions per user (default: 3)
    pub max_sessions_per_user: usize,
    /// Maximum total concurrent sessions (default: 100)
    pub max_total_sessions: usize,
    /// Maximum memory usage for chunks in bytes (default: 500MB)
    pub max_memory_usage: usize,
}

impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,      // 100MB
            max_chunk_size: 5 * 1024 * 1024,       // 5MB
            min_chunk_size: 64 * 1024,             // 64KB
            max_sessions_per_user: 3,
            max_total_sessions: 100,
            max_memory_usage: 500 * 1024 * 1024,   // 500MB
        }
    }
}

/// Chunked upload session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSession {
    /// Unique upload ID
    pub upload_id: String,
    /// Owner DID
    pub owner_did: String,
    /// Total file size
    pub total_size: usize,
    /// Chunk size
    pub chunk_size: usize,
    /// Number of chunks expected
    pub num_chunks: usize,
    /// Content type
    pub content_type: String,
    /// Hash of complete file (for integrity verification)
    pub total_hash: String,
    /// Created timestamp
    pub created_at: u64,
    /// Expiration timestamp (1 hour default)
    pub expires_at: u64,
    /// Uploaded chunk indices
    pub uploaded_chunks: Vec<usize>,
    /// Chunk CIDs by index
    pub chunk_cids: HashMap<usize, String>,
}

/// Init upload request
#[derive(Debug, Deserialize)]
pub struct InitUploadRequest {
    pub total_size: usize,
    pub chunk_size: usize,
    pub content_type: String,
    pub total_hash: String,
    pub num_chunks: usize,
}

/// Finalize upload request
#[derive(Debug, Deserialize)]
pub struct FinalizeUploadRequest {
    pub upload_id: String,
    pub chunk_cids: Vec<String>,
    pub total_hash: String,
}

/// Chunked upload manager
pub struct ChunkedUploadManager {
    /// Active upload sessions
    sessions: Arc<RwLock<HashMap<String, UploadSession>>>,
    /// Chunk storage (in-memory for now, should use blob storage)
    chunks: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Upload limits
    limits: UploadLimits,
    /// Current memory usage (atomic for lock-free reads)
    current_memory: AtomicUsize,
}

impl ChunkedUploadManager {
    pub fn new() -> Self {
        Self::with_limits(UploadLimits::default())
    }

    pub fn with_limits(limits: UploadLimits) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            chunks: Arc::new(RwLock::new(HashMap::new())),
            limits,
            current_memory: AtomicUsize::new(0),
        }
    }

    /// Get current memory usage
    pub fn memory_usage(&self) -> usize {
        self.current_memory.load(Ordering::Relaxed)
    }

    /// Count sessions for a specific user
    async fn count_user_sessions(&self, owner_did: &str) -> usize {
        let sessions = self.sessions.read().await;
        sessions.values().filter(|s| s.owner_did == owner_did).count()
    }

    /// Initialize a chunked upload session
    pub async fn init_upload(
        &self,
        owner_did: &str,
        request: InitUploadRequest,
    ) -> ZhtpResult<UploadSession> {
        // Validate file size limit
        if request.total_size > self.limits.max_file_size {
            warn!(
                owner_did = %owner_did,
                requested_size = request.total_size,
                max_size = self.limits.max_file_size,
                "Upload rejected: file too large"
            );
            return Err(anyhow!(
                "File size {} exceeds maximum allowed size of {} bytes",
                request.total_size,
                self.limits.max_file_size
            ));
        }

        // Validate chunk size
        if request.chunk_size > self.limits.max_chunk_size {
            return Err(anyhow!(
                "Chunk size {} exceeds maximum allowed size of {} bytes",
                request.chunk_size,
                self.limits.max_chunk_size
            ));
        }
        if request.chunk_size < self.limits.min_chunk_size {
            return Err(anyhow!(
                "Chunk size {} is below minimum size of {} bytes",
                request.chunk_size,
                self.limits.min_chunk_size
            ));
        }

        // Check memory availability
        let current_memory = self.current_memory.load(Ordering::Relaxed);
        if current_memory + request.total_size > self.limits.max_memory_usage {
            warn!(
                current_memory = current_memory,
                requested = request.total_size,
                max = self.limits.max_memory_usage,
                "Upload rejected: insufficient memory"
            );
            return Err(anyhow!(
                "Server memory limit reached. Try again later or use smaller files."
            ));
        }

        // Check per-user session limit
        let user_sessions = self.count_user_sessions(owner_did).await;
        if user_sessions >= self.limits.max_sessions_per_user {
            warn!(
                owner_did = %owner_did,
                current_sessions = user_sessions,
                max = self.limits.max_sessions_per_user,
                "Upload rejected: too many concurrent sessions"
            );
            return Err(anyhow!(
                "Maximum concurrent uploads ({}) reached. Complete or cancel existing uploads first.",
                self.limits.max_sessions_per_user
            ));
        }

        // Check total session limit
        let total_sessions = {
            let sessions = self.sessions.read().await;
            sessions.len()
        };
        if total_sessions >= self.limits.max_total_sessions {
            warn!(
                total_sessions = total_sessions,
                max = self.limits.max_total_sessions,
                "Upload rejected: server at capacity"
            );
            return Err(anyhow!(
                "Server is at capacity. Try again later."
            ));
        }

        let upload_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session = UploadSession {
            upload_id: upload_id.clone(),
            owner_did: owner_did.to_string(),
            total_size: request.total_size,
            chunk_size: request.chunk_size,
            num_chunks: request.num_chunks,
            content_type: request.content_type,
            total_hash: request.total_hash,
            created_at: now,
            expires_at: now + 3600, // 1 hour expiration
            uploaded_chunks: Vec::new(),
            chunk_cids: HashMap::new(),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(upload_id, session.clone());

        info!(
            upload_id = %session.upload_id,
            owner_did = %owner_did,
            total_size = session.total_size,
            num_chunks = session.num_chunks,
            "Chunked upload session created"
        );

        Ok(session)
    }

    /// Upload a single chunk
    pub async fn upload_chunk(
        &self,
        upload_id: &str,
        chunk_index: usize,
        chunk_hash: &str,
        chunk_data: Vec<u8>,
    ) -> ZhtpResult<String> {
        let chunk_size = chunk_data.len();

        // Validate chunk size against limits
        if chunk_size > self.limits.max_chunk_size {
            return Err(anyhow!(
                "Chunk size {} exceeds maximum of {} bytes",
                chunk_size,
                self.limits.max_chunk_size
            ));
        }

        // Check memory limit before storing
        let current = self.current_memory.load(Ordering::Relaxed);
        if current + chunk_size > self.limits.max_memory_usage {
            return Err(anyhow!(
                "Server memory limit reached. Try again later."
            ));
        }

        // Verify session exists and isn't expired
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(upload_id)
            .ok_or_else(|| anyhow!("Upload session not found: {}", upload_id))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > session.expires_at {
            sessions.remove(upload_id);
            return Err(anyhow!("Upload session expired"));
        }

        // Verify chunk index is valid
        if chunk_index >= session.num_chunks {
            return Err(anyhow!(
                "Invalid chunk index: {} (expected 0-{})",
                chunk_index,
                session.num_chunks - 1
            ));
        }

        // Verify chunk hash
        let computed_hash = hex::encode(&lib_crypto::hash_blake3(&chunk_data)[..16]);
        if computed_hash != chunk_hash {
            return Err(anyhow!(
                "Chunk hash mismatch: expected {}, got {}",
                chunk_hash,
                computed_hash
            ));
        }

        // Generate chunk CID
        let chunk_cid = format!(
            "bafk{}",
            hex::encode(&lib_crypto::hash_blake3(&chunk_data)[..16])
        );

        // Store chunk and track memory
        let chunk_key = format!("{}:{}", upload_id, chunk_index);
        let is_new_chunk = !session.uploaded_chunks.contains(&chunk_index);
        {
            let mut chunks = self.chunks.write().await;
            // Only count memory if this is a new chunk (not a retry)
            if is_new_chunk {
                self.current_memory.fetch_add(chunk_size, Ordering::Relaxed);
            }
            chunks.insert(chunk_key, chunk_data);
        }

        // Update session
        if is_new_chunk {
            session.uploaded_chunks.push(chunk_index);
        }
        session.chunk_cids.insert(chunk_index, chunk_cid.clone());

        debug!(
            upload_id = %upload_id,
            chunk_index = chunk_index,
            chunk_cid = %chunk_cid,
            chunk_size = chunk_size,
            memory_usage = self.current_memory.load(Ordering::Relaxed),
            progress = format!("{}/{}", session.uploaded_chunks.len(), session.num_chunks),
            "Chunk uploaded"
        );

        Ok(chunk_cid)
    }

    /// Finalize upload - assemble chunks into final blob
    pub async fn finalize_upload(
        &self,
        upload_id: &str,
        chunk_cids: &[String],
        total_hash: &str,
    ) -> ZhtpResult<String> {
        // Get session and extract needed data before modifying
        let (num_chunks, total_size, session_chunk_cids) = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(upload_id)
                .ok_or_else(|| anyhow!("Upload session not found: {}", upload_id))?;

            // Verify all chunks uploaded
            if session.uploaded_chunks.len() != session.num_chunks {
                return Err(anyhow!(
                    "Not all chunks uploaded: {}/{} uploaded",
                    session.uploaded_chunks.len(),
                    session.num_chunks
                ));
            }

            (session.num_chunks, session.total_size, session.chunk_cids.clone())
        };

        // Verify chunk CIDs match
        for (i, cid) in chunk_cids.iter().enumerate() {
            let expected = session_chunk_cids.get(&i)
                .ok_or_else(|| anyhow!("Missing chunk {} CID", i))?;
            if cid != expected {
                return Err(anyhow!(
                    "Chunk {} CID mismatch: expected {}, got {}",
                    i, expected, cid
                ));
            }
        }

        // Assemble chunks
        let mut assembled = Vec::with_capacity(total_size);
        {
            let chunks = self.chunks.read().await;
            for i in 0..num_chunks {
                let chunk_key = format!("{}:{}", upload_id, i);
                let chunk_data = chunks.get(&chunk_key)
                    .ok_or_else(|| anyhow!("Missing chunk data for index {}", i))?;
                assembled.extend_from_slice(chunk_data);
            }
        }

        // Verify total hash
        let computed_hash = hex::encode(&lib_crypto::hash_blake3(&assembled)[..16]);
        if computed_hash != total_hash {
            return Err(anyhow!(
                "Total hash mismatch: expected {}, got {}",
                total_hash,
                computed_hash
            ));
        }

        // Generate final content CID
        let content_cid = format!(
            "bafk{}",
            hex::encode(&lib_crypto::hash_blake3(&assembled)[..16])
        );

        info!(
            upload_id = %upload_id,
            content_cid = %content_cid,
            total_size = assembled.len(),
            "Chunked upload finalized"
        );

        // Cleanup session and chunks, reclaim memory
        let mut freed_memory = 0usize;
        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(upload_id);
        }
        {
            let mut chunks = self.chunks.write().await;
            for i in 0..num_chunks {
                let chunk_key = format!("{}:{}", upload_id, i);
                if let Some(chunk) = chunks.remove(&chunk_key) {
                    freed_memory += chunk.len();
                }
            }
        }
        // Decrement memory counter
        self.current_memory.fetch_sub(freed_memory, Ordering::Relaxed);

        info!(
            upload_id = %upload_id,
            freed_memory = freed_memory,
            remaining_memory = self.current_memory.load(Ordering::Relaxed),
            "Upload session cleaned up"
        );

        // TODO: Store assembled blob in persistent storage
        // For now, the content is assembled but not persisted
        // In production, this should call the blob storage system

        Ok(content_cid)
    }

    /// Get upload session status
    pub async fn get_status(&self, upload_id: &str) -> ZhtpResult<UploadSession> {
        let sessions = self.sessions.read().await;
        sessions.get(upload_id)
            .cloned()
            .ok_or_else(|| anyhow!("Upload session not found: {}", upload_id))
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut sessions = self.sessions.write().await;
        let expired: Vec<String> = sessions.iter()
            .filter(|(_, s)| s.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();

        let mut total_freed = 0usize;
        for id in &expired {
            if let Some(session) = sessions.remove(id) {
                // Cleanup chunks and track memory freed
                let mut chunks = self.chunks.write().await;
                for i in 0..session.num_chunks {
                    let chunk_key = format!("{}:{}", id, i);
                    if let Some(chunk) = chunks.remove(&chunk_key) {
                        total_freed += chunk.len();
                    }
                }
            }
        }

        // Reclaim memory
        if total_freed > 0 {
            self.current_memory.fetch_sub(total_freed, Ordering::Relaxed);
        }

        if !expired.is_empty() {
            info!(
                count = expired.len(),
                freed_bytes = total_freed,
                remaining_memory = self.current_memory.load(Ordering::Relaxed),
                "Cleaned up expired upload sessions"
            );
        }
    }

    /// Cancel an upload session (called by user or on error)
    pub async fn cancel_upload(&self, upload_id: &str) -> ZhtpResult<()> {
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(upload_id)
        };

        if let Some(session) = session {
            let mut freed = 0usize;
            let mut chunks = self.chunks.write().await;
            for i in 0..session.num_chunks {
                let chunk_key = format!("{}:{}", upload_id, i);
                if let Some(chunk) = chunks.remove(&chunk_key) {
                    freed += chunk.len();
                }
            }
            self.current_memory.fetch_sub(freed, Ordering::Relaxed);

            info!(
                upload_id = %upload_id,
                freed_bytes = freed,
                "Upload cancelled"
            );
            Ok(())
        } else {
            Err(anyhow!("Upload session not found: {}", upload_id))
        }
    }

    /// Get current stats for monitoring
    pub fn stats(&self) -> UploadStats {
        UploadStats {
            memory_usage: self.current_memory.load(Ordering::Relaxed),
            max_memory: self.limits.max_memory_usage,
        }
    }
}

/// Upload statistics for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct UploadStats {
    pub memory_usage: usize,
    pub max_memory: usize,
}

impl Default for ChunkedUploadManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle chunked upload API requests
pub async fn handle_chunked_upload(
    request: ZhtpRequest,
    manager: &ChunkedUploadManager,
    owner_did: &str,
) -> ZhtpResult<ZhtpResponse> {
    let path = &request.uri;

    // POST /api/v1/web4/content/upload/init
    if path == "/api/v1/web4/content/upload/init" {
        let init_req: InitUploadRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid init request: {}", e))?;

        let session = manager.init_upload(owner_did, init_req).await?;

        let response = serde_json::json!({
            "upload_id": session.upload_id,
            "num_chunks": session.num_chunks,
            "chunk_size": session.chunk_size,
            "expires_at": session.expires_at,
        });

        return Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ));
    }

    // POST /api/v1/web4/content/upload/{id}/chunk/{index}?hash=...
    if path.contains("/chunk/") {
        // Parse: /api/v1/web4/content/upload/{id}/chunk/{index}
        let parts: Vec<&str> = path.split('/').collect();
        // Expected: ["", "api", "v1", "web4", "content", "upload", "{id}", "chunk", "{index}"]
        if parts.len() < 9 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid chunk upload path".to_string(),
            ));
        }

        let upload_id = parts[6];
        let chunk_index_str = parts[8].split('?').next().unwrap_or(parts[8]);
        let chunk_index: usize = chunk_index_str.parse()
            .map_err(|_| anyhow!("Invalid chunk index: {}", chunk_index_str))?;

        // Extract hash from query string
        let chunk_hash = request.uri
            .split("hash=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .ok_or_else(|| anyhow!("Missing chunk hash parameter"))?;

        let chunk_cid = manager.upload_chunk(
            upload_id,
            chunk_index,
            chunk_hash,
            request.body,
        ).await?;

        let response = serde_json::json!({
            "chunk_cid": chunk_cid,
            "chunk_index": chunk_index,
        });

        return Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ));
    }

    // POST /api/v1/web4/content/upload/{id}/finalize
    if path.contains("/finalize") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 8 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid finalize path".to_string(),
            ));
        }

        let upload_id = parts[6];

        let finalize_req: FinalizeUploadRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid finalize request: {}", e))?;

        let content_id = manager.finalize_upload(
            upload_id,
            &finalize_req.chunk_cids,
            &finalize_req.total_hash,
        ).await?;

        let response = serde_json::json!({
            "content_id": content_id,
            "upload_id": upload_id,
        });

        return Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ));
    }

    // GET /api/v1/web4/content/upload/{id}/status
    if path.contains("/status") && request.method == lib_protocols::ZhtpMethod::Get {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 8 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid status path".to_string(),
            ));
        }

        let upload_id = parts[6];
        let session = manager.get_status(upload_id).await?;

        let response = serde_json::json!({
            "upload_id": session.upload_id,
            "total_size": session.total_size,
            "chunk_size": session.chunk_size,
            "num_chunks": session.num_chunks,
            "total_hash": session.total_hash,
            "uploaded_chunks": session.uploaded_chunks,
            "chunk_cids": session.chunk_cids,
            "expires_at": session.expires_at,
        });

        return Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ));
    }

    Ok(ZhtpResponse::error(
        ZhtpStatus::NotFound,
        format!("Unknown chunked upload endpoint: {}", path),
    ))
}
