//! SQLite storage backend for structured queryable data
//!
//! [DB-009] Implements persistent storage for:
//! - Content metadata (queryable by tags, owner, tier)
//! - Storage contracts (complex queries, joins)
//! - Reputation scores (aggregations)
//! - Audit logging (time-series queries)
//!
//! # Features
//!
//! - WAL mode enabled for better concurrent performance
//! - Automatic schema migrations
//! - Async operations via sqlx
//! - Type-safe queries

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use sqlx::{FromRow, Row};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, info, warn};

// ============================================================================
// Type Definitions
// ============================================================================

/// Content metadata stored in SQLite
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ContentMetadataRow {
    /// Content hash (primary key)
    pub content_hash: Vec<u8>,
    /// Size in bytes
    pub size: i64,
    /// Owner node/identity ID
    pub owner_id: String,
    /// Storage tier (hot, warm, cold, archive)
    pub tier: String,
    /// Encryption level (none, aes256, etc.)
    pub encryption_level: String,
    /// Creation timestamp (unix seconds)
    pub created_at: i64,
    /// Last update timestamp (unix seconds)
    pub updated_at: i64,
    /// JSON array of tags
    pub tags: Option<String>,
    /// Human-readable description
    pub description: Option<String>,
}

/// Storage contract record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct StorageContractRow {
    /// Unique contract identifier
    pub contract_id: String,
    /// Content hash being stored
    pub content_hash: Vec<u8>,
    /// Storage provider node ID
    pub provider_id: String,
    /// Client node ID requesting storage
    pub client_id: String,
    /// Contract status (active, expired, terminated)
    pub status: String,
    /// Contract start timestamp
    pub start_time: i64,
    /// Contract end timestamp
    pub end_time: i64,
    /// Price per day in smallest unit
    pub price_per_day: i64,
    /// Total amount paid
    pub total_paid: i64,
    /// Record creation timestamp
    pub created_at: i64,
    /// Record update timestamp
    pub updated_at: i64,
}

/// Reputation score record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ReputationScoreRow {
    /// Node identifier
    pub node_id: String,
    /// Computed reputation score (0.0 - 1.0)
    pub score: f64,
    /// Count of successful retrievals
    pub successful_retrievals: i64,
    /// Count of failed retrievals
    pub failed_retrievals: i64,
    /// Uptime percentage (0.0 - 100.0)
    pub uptime_percentage: f64,
    /// Last update timestamp
    pub last_updated: i64,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogRow {
    /// Auto-incremented ID
    pub id: i64,
    /// Event timestamp
    pub timestamp: i64,
    /// Event type identifier
    pub event_type: String,
    /// Associated node ID (optional)
    pub node_id: Option<String>,
    /// Associated content hash (optional)
    pub content_hash: Option<Vec<u8>>,
    /// JSON details
    pub details: Option<String>,
}

/// Contract status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractStatus {
    Active,
    Expired,
    Terminated,
    Pending,
}

impl std::fmt::Display for ContractStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractStatus::Active => write!(f, "active"),
            ContractStatus::Expired => write!(f, "expired"),
            ContractStatus::Terminated => write!(f, "terminated"),
            ContractStatus::Pending => write!(f, "pending"),
        }
    }
}

impl FromStr for ContractStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "active" => Ok(ContractStatus::Active),
            "expired" => Ok(ContractStatus::Expired),
            "terminated" => Ok(ContractStatus::Terminated),
            "pending" => Ok(ContractStatus::Pending),
            _ => Err(anyhow!("Unknown contract status: {}", s)),
        }
    }
}

// ============================================================================
// SqliteBackend Implementation
// ============================================================================

/// SQLite-based storage backend for structured data
///
/// Provides persistent, queryable storage for metadata, contracts,
/// reputation scores, and audit logs.
#[derive(Debug, Clone)]
pub struct SqliteBackend {
    pool: SqlitePool,
}

impl SqliteBackend {
    /// Open or create a SQLite database at the given path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file
    ///
    /// # Features
    ///
    /// - Creates database if it doesn't exist
    /// - Enables WAL mode for better concurrent performance
    /// - Runs migrations automatically
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let url = format!("sqlite:{}?mode=rwc", path.display());

        info!("Opening SQLite backend at: {}", path.display());

        // Configure connection options with WAL mode
        let options = SqliteConnectOptions::from_str(&url)?
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        // Create connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| anyhow!("Failed to connect to SQLite: {}", e))?;

        // Run migrations
        Self::run_migrations(&pool).await?;

        info!("SQLite backend initialized successfully");

        Ok(Self { pool })
    }

    /// Open an in-memory SQLite database (for testing)
    pub async fn open_in_memory() -> Result<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| anyhow!("Failed to create in-memory SQLite: {}", e))?;

        Self::run_migrations(&pool).await?;

        Ok(Self { pool })
    }

    /// Run database migrations
    async fn run_migrations(pool: &SqlitePool) -> Result<()> {
        debug!("Running SQLite migrations...");

        // Embedded migration SQL for [DB-009]
        const MIGRATION_V1: &str = r#"
-- Content metadata table
CREATE TABLE IF NOT EXISTS content_metadata (
    content_hash BLOB PRIMARY KEY,
    size INTEGER NOT NULL,
    owner_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    encryption_level TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    tags TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_content_owner ON content_metadata(owner_id);
CREATE INDEX IF NOT EXISTS idx_content_tier ON content_metadata(tier);
CREATE INDEX IF NOT EXISTS idx_content_created ON content_metadata(created_at);

-- Storage contracts table
CREATE TABLE IF NOT EXISTS storage_contracts (
    contract_id TEXT PRIMARY KEY,
    content_hash BLOB NOT NULL,
    provider_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    status TEXT NOT NULL,
    start_time INTEGER NOT NULL,
    end_time INTEGER NOT NULL,
    price_per_day INTEGER NOT NULL,
    total_paid INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (content_hash) REFERENCES content_metadata(content_hash)
);

CREATE INDEX IF NOT EXISTS idx_contracts_provider ON storage_contracts(provider_id);
CREATE INDEX IF NOT EXISTS idx_contracts_client ON storage_contracts(client_id);
CREATE INDEX IF NOT EXISTS idx_contracts_status ON storage_contracts(status);
CREATE INDEX IF NOT EXISTS idx_contracts_content ON storage_contracts(content_hash);

-- Reputation scores table
CREATE TABLE IF NOT EXISTS reputation_scores (
    node_id TEXT PRIMARY KEY,
    score REAL NOT NULL DEFAULT 0.0,
    successful_retrievals INTEGER NOT NULL DEFAULT 0,
    failed_retrievals INTEGER NOT NULL DEFAULT 0,
    uptime_percentage REAL NOT NULL DEFAULT 0.0,
    last_updated INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_reputation_score ON reputation_scores(score);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    event_type TEXT NOT NULL,
    node_id TEXT,
    content_hash BLOB,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_node ON audit_log(node_id);
"#;

        sqlx::raw_sql(MIGRATION_V1)
            .execute(pool)
            .await
            .map_err(|e| anyhow!("Migration failed: {}", e))?;

        debug!("Migrations completed successfully");
        Ok(())
    }

    /// Close the database connection pool
    pub async fn close(&self) {
        self.pool.close().await;
    }

    // ========================================================================
    // Content Metadata Operations
    // ========================================================================

    /// Insert or update content metadata
    pub async fn upsert_content_metadata(&self, metadata: &ContentMetadataRow) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO content_metadata
                (content_hash, size, owner_id, tier, encryption_level,
                 created_at, updated_at, tags, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(content_hash) DO UPDATE SET
                size = excluded.size,
                owner_id = excluded.owner_id,
                tier = excluded.tier,
                encryption_level = excluded.encryption_level,
                updated_at = excluded.updated_at,
                tags = excluded.tags,
                description = excluded.description
            "#,
        )
        .bind(&metadata.content_hash)
        .bind(metadata.size)
        .bind(&metadata.owner_id)
        .bind(&metadata.tier)
        .bind(&metadata.encryption_level)
        .bind(metadata.created_at)
        .bind(metadata.updated_at)
        .bind(&metadata.tags)
        .bind(&metadata.description)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to upsert content metadata: {}", e))?;

        Ok(())
    }

    /// Get content metadata by hash
    pub async fn get_content_metadata(
        &self,
        content_hash: &[u8],
    ) -> Result<Option<ContentMetadataRow>> {
        let result = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE content_hash = ?",
        )
        .bind(content_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get content metadata: {}", e))?;

        Ok(result)
    }

    /// Delete content metadata
    pub async fn delete_content_metadata(&self, content_hash: &[u8]) -> Result<bool> {
        let result = sqlx::query("DELETE FROM content_metadata WHERE content_hash = ?")
            .bind(content_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| anyhow!("Failed to delete content metadata: {}", e))?;

        Ok(result.rows_affected() > 0)
    }

    /// List content by owner
    pub async fn list_content_by_owner(&self, owner_id: &str) -> Result<Vec<ContentMetadataRow>> {
        let results = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE owner_id = ? ORDER BY created_at DESC",
        )
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to list content by owner: {}", e))?;

        Ok(results)
    }

    /// List content by tier
    pub async fn list_content_by_tier(&self, tier: &str) -> Result<Vec<ContentMetadataRow>> {
        let results = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE tier = ? ORDER BY created_at DESC",
        )
        .bind(tier)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to list content by tier: {}", e))?;

        Ok(results)
    }

    /// Search content by tag (JSON array contains)
    pub async fn search_content_by_tag(&self, tag: &str) -> Result<Vec<ContentMetadataRow>> {
        // SQLite JSON contains check
        let pattern = format!("%\"{}%", tag);
        let results = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE tags LIKE ? ORDER BY created_at DESC",
        )
        .bind(pattern)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to search content by tag: {}", e))?;

        Ok(results)
    }

    // ========================================================================
    // Storage Contract Operations
    // ========================================================================

    /// Insert a new storage contract
    pub async fn insert_contract(&self, contract: &StorageContractRow) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO storage_contracts
                (contract_id, content_hash, provider_id, client_id, status,
                 start_time, end_time, price_per_day, total_paid, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&contract.contract_id)
        .bind(&contract.content_hash)
        .bind(&contract.provider_id)
        .bind(&contract.client_id)
        .bind(&contract.status)
        .bind(contract.start_time)
        .bind(contract.end_time)
        .bind(contract.price_per_day)
        .bind(contract.total_paid)
        .bind(contract.created_at)
        .bind(contract.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to insert contract: {}", e))?;

        Ok(())
    }

    /// Get contract by ID
    pub async fn get_contract(&self, contract_id: &str) -> Result<Option<StorageContractRow>> {
        let result = sqlx::query_as::<_, StorageContractRow>(
            "SELECT * FROM storage_contracts WHERE contract_id = ?",
        )
        .bind(contract_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get contract: {}", e))?;

        Ok(result)
    }

    /// Update contract status
    pub async fn update_contract_status(
        &self,
        contract_id: &str,
        status: ContractStatus,
    ) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE storage_contracts SET status = ?, updated_at = ? WHERE contract_id = ?",
        )
        .bind(status.to_string())
        .bind(now)
        .bind(contract_id)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to update contract status: {}", e))?;

        Ok(result.rows_affected() > 0)
    }

    /// Update total paid amount
    pub async fn update_contract_payment(
        &self,
        contract_id: &str,
        additional_payment: i64,
    ) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE storage_contracts SET total_paid = total_paid + ?, updated_at = ? WHERE contract_id = ?",
        )
        .bind(additional_payment)
        .bind(now)
        .bind(contract_id)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to update contract payment: {}", e))?;

        Ok(result.rows_affected() > 0)
    }

    /// List contracts by provider
    pub async fn list_contracts_by_provider(
        &self,
        provider_id: &str,
    ) -> Result<Vec<StorageContractRow>> {
        let results = sqlx::query_as::<_, StorageContractRow>(
            "SELECT * FROM storage_contracts WHERE provider_id = ? ORDER BY created_at DESC",
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to list contracts by provider: {}", e))?;

        Ok(results)
    }

    /// List contracts by client
    pub async fn list_contracts_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<StorageContractRow>> {
        let results = sqlx::query_as::<_, StorageContractRow>(
            "SELECT * FROM storage_contracts WHERE client_id = ? ORDER BY created_at DESC",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to list contracts by client: {}", e))?;

        Ok(results)
    }

    /// List active contracts expiring before a given time
    pub async fn list_expiring_contracts(
        &self,
        before_timestamp: i64,
    ) -> Result<Vec<StorageContractRow>> {
        let results = sqlx::query_as::<_, StorageContractRow>(
            r#"
            SELECT * FROM storage_contracts
            WHERE status = 'active' AND end_time < ?
            ORDER BY end_time ASC
            "#,
        )
        .bind(before_timestamp)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to list expiring contracts: {}", e))?;

        Ok(results)
    }

    // ========================================================================
    // Reputation Score Operations
    // ========================================================================

    /// Upsert reputation score
    pub async fn upsert_reputation(&self, reputation: &ReputationScoreRow) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO reputation_scores
                (node_id, score, successful_retrievals, failed_retrievals,
                 uptime_percentage, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                score = excluded.score,
                successful_retrievals = excluded.successful_retrievals,
                failed_retrievals = excluded.failed_retrievals,
                uptime_percentage = excluded.uptime_percentage,
                last_updated = excluded.last_updated
            "#,
        )
        .bind(&reputation.node_id)
        .bind(reputation.score)
        .bind(reputation.successful_retrievals)
        .bind(reputation.failed_retrievals)
        .bind(reputation.uptime_percentage)
        .bind(reputation.last_updated)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to upsert reputation: {}", e))?;

        Ok(())
    }

    /// Get reputation by node ID
    pub async fn get_reputation(&self, node_id: &str) -> Result<Option<ReputationScoreRow>> {
        let result = sqlx::query_as::<_, ReputationScoreRow>(
            "SELECT * FROM reputation_scores WHERE node_id = ?",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get reputation: {}", e))?;

        Ok(result)
    }

    /// Increment successful retrieval count
    pub async fn record_successful_retrieval(&self, node_id: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            r#"
            INSERT INTO reputation_scores (node_id, score, successful_retrievals, failed_retrievals, uptime_percentage, last_updated)
            VALUES (?, 0.5, 1, 0, 100.0, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                successful_retrievals = successful_retrievals + 1,
                last_updated = ?
            "#,
        )
        .bind(node_id)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to record successful retrieval: {}", e))?;

        Ok(())
    }

    /// Increment failed retrieval count
    pub async fn record_failed_retrieval(&self, node_id: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            r#"
            INSERT INTO reputation_scores (node_id, score, successful_retrievals, failed_retrievals, uptime_percentage, last_updated)
            VALUES (?, 0.5, 0, 1, 100.0, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                failed_retrievals = failed_retrievals + 1,
                last_updated = ?
            "#,
        )
        .bind(node_id)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to record failed retrieval: {}", e))?;

        Ok(())
    }

    /// Get top N nodes by reputation score
    pub async fn get_top_nodes(&self, limit: u32) -> Result<Vec<ReputationScoreRow>> {
        let results = sqlx::query_as::<_, ReputationScoreRow>(
            "SELECT * FROM reputation_scores ORDER BY score DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get top nodes: {}", e))?;

        Ok(results)
    }

    /// Recalculate reputation score for a node
    pub async fn recalculate_reputation(&self, node_id: &str) -> Result<f64> {
        let reputation = self.get_reputation(node_id).await?;

        let score = match reputation {
            Some(rep) => {
                let total = rep.successful_retrievals + rep.failed_retrievals;
                if total == 0 {
                    0.5 // Default score
                } else {
                    // Score = success_rate * 0.7 + uptime * 0.3
                    let success_rate = rep.successful_retrievals as f64 / total as f64;
                    let uptime_factor = rep.uptime_percentage / 100.0;
                    success_rate * 0.7 + uptime_factor * 0.3
                }
            }
            None => 0.5,
        };

        // Update the score
        let now = chrono::Utc::now().timestamp();
        sqlx::query("UPDATE reputation_scores SET score = ?, last_updated = ? WHERE node_id = ?")
            .bind(score)
            .bind(now)
            .bind(node_id)
            .execute(&self.pool)
            .await
            .map_err(|e| anyhow!("Failed to update reputation score: {}", e))?;

        Ok(score)
    }

    // ========================================================================
    // Audit Log Operations
    // ========================================================================

    /// Append an audit log entry
    pub async fn append_audit_log(
        &self,
        event_type: &str,
        node_id: Option<&str>,
        content_hash: Option<&[u8]>,
        details: Option<&str>,
    ) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO audit_log (timestamp, event_type, node_id, content_hash, details)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(now)
        .bind(event_type)
        .bind(node_id)
        .bind(content_hash)
        .bind(details)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to append audit log: {}", e))?;

        Ok(result.last_insert_rowid())
    }

    /// Get audit logs within a time range
    pub async fn get_audit_logs(
        &self,
        start_time: i64,
        end_time: i64,
        limit: u32,
    ) -> Result<Vec<AuditLogRow>> {
        let results = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT * FROM audit_log
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get audit logs: {}", e))?;

        Ok(results)
    }

    /// Get audit logs by event type
    pub async fn get_audit_logs_by_type(
        &self,
        event_type: &str,
        limit: u32,
    ) -> Result<Vec<AuditLogRow>> {
        let results = sqlx::query_as::<_, AuditLogRow>(
            "SELECT * FROM audit_log WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(event_type)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get audit logs by type: {}", e))?;

        Ok(results)
    }

    /// Get audit logs for a specific node
    pub async fn get_audit_logs_by_node(
        &self,
        node_id: &str,
        limit: u32,
    ) -> Result<Vec<AuditLogRow>> {
        let results = sqlx::query_as::<_, AuditLogRow>(
            "SELECT * FROM audit_log WHERE node_id = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(node_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get audit logs by node: {}", e))?;

        Ok(results)
    }

    /// Prune old audit logs
    pub async fn prune_audit_logs(&self, before_timestamp: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM audit_log WHERE timestamp < ?")
            .bind(before_timestamp)
            .execute(&self.pool)
            .await
            .map_err(|e| anyhow!("Failed to prune audit logs: {}", e))?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!("Pruned {} old audit log entries", deleted);
        }

        Ok(deleted)
    }

    // ========================================================================
    // Statistics and Aggregations
    // ========================================================================

    /// Get total storage size by tier
    pub async fn get_storage_by_tier(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query("SELECT tier, SUM(size) as total_size FROM content_metadata GROUP BY tier")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| anyhow!("Failed to get storage by tier: {}", e))?;

        let mut results = Vec::new();
        for row in rows {
            let tier: String = row.get("tier");
            let total_size: i64 = row.get("total_size");
            results.push((tier, total_size));
        }

        Ok(results)
    }

    /// Get contract statistics
    pub async fn get_contract_stats(&self) -> Result<ContractStats> {
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_contracts,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_contracts,
                SUM(total_paid) as total_revenue
            FROM storage_contracts
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow!("Failed to get contract stats: {}", e))?;

        Ok(ContractStats {
            total_contracts: row.get("total_contracts"),
            active_contracts: row.get("active_contracts"),
            total_revenue: row.get("total_revenue"),
        })
    }
}

/// Contract statistics
#[derive(Debug, Clone, Default)]
pub struct ContractStats {
    pub total_contracts: i64,
    pub active_contracts: i64,
    pub total_revenue: i64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_backend() -> SqliteBackend {
        SqliteBackend::open_in_memory().await.unwrap()
    }

    #[tokio::test]
    async fn test_content_metadata_crud() {
        let backend = create_test_backend().await;

        let content_hash = vec![1u8; 32];
        let metadata = ContentMetadataRow {
            content_hash: content_hash.clone(),
            size: 1024,
            owner_id: "owner1".to_string(),
            tier: "hot".to_string(),
            encryption_level: "aes256".to_string(),
            created_at: 1000,
            updated_at: 1000,
            tags: Some(r#"["tag1", "tag2"]"#.to_string()),
            description: Some("Test content".to_string()),
        };

        // Insert
        backend.upsert_content_metadata(&metadata).await.unwrap();

        // Get
        let retrieved = backend.get_content_metadata(&content_hash).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.size, 1024);
        assert_eq!(retrieved.owner_id, "owner1");

        // Update
        let updated = ContentMetadataRow {
            size: 2048,
            updated_at: 2000,
            ..metadata.clone()
        };
        backend.upsert_content_metadata(&updated).await.unwrap();

        let retrieved = backend.get_content_metadata(&content_hash).await.unwrap();
        assert_eq!(retrieved.unwrap().size, 2048);

        // Delete
        let deleted = backend.delete_content_metadata(&content_hash).await.unwrap();
        assert!(deleted);

        let retrieved = backend.get_content_metadata(&content_hash).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_content_by_owner() {
        let backend = create_test_backend().await;

        // Insert multiple items for same owner
        for i in 0..3 {
            let metadata = ContentMetadataRow {
                content_hash: vec![i; 32],
                size: 1024 * (i as i64 + 1),
                owner_id: "owner1".to_string(),
                tier: "hot".to_string(),
                encryption_level: "none".to_string(),
                created_at: 1000 + i as i64,
                updated_at: 1000 + i as i64,
                tags: None,
                description: None,
            };
            backend.upsert_content_metadata(&metadata).await.unwrap();
        }

        let results = backend.list_content_by_owner("owner1").await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_storage_contract_crud() {
        let backend = create_test_backend().await;

        // First insert content metadata (foreign key requirement)
        let content_hash = vec![1u8; 32];
        let metadata = ContentMetadataRow {
            content_hash: content_hash.clone(),
            size: 1024,
            owner_id: "owner1".to_string(),
            tier: "hot".to_string(),
            encryption_level: "none".to_string(),
            created_at: 1000,
            updated_at: 1000,
            tags: None,
            description: None,
        };
        backend.upsert_content_metadata(&metadata).await.unwrap();

        // Insert contract
        let contract = StorageContractRow {
            contract_id: "contract1".to_string(),
            content_hash: content_hash.clone(),
            provider_id: "provider1".to_string(),
            client_id: "client1".to_string(),
            status: "active".to_string(),
            start_time: 1000,
            end_time: 2000,
            price_per_day: 100,
            total_paid: 0,
            created_at: 1000,
            updated_at: 1000,
        };
        backend.insert_contract(&contract).await.unwrap();

        // Get
        let retrieved = backend.get_contract("contract1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().status, "active");

        // Update status
        backend
            .update_contract_status("contract1", ContractStatus::Expired)
            .await
            .unwrap();

        let retrieved = backend.get_contract("contract1").await.unwrap();
        assert_eq!(retrieved.unwrap().status, "expired");

        // Update payment
        backend.update_contract_payment("contract1", 500).await.unwrap();

        let retrieved = backend.get_contract("contract1").await.unwrap();
        assert_eq!(retrieved.unwrap().total_paid, 500);
    }

    #[tokio::test]
    async fn test_reputation_scores() {
        let backend = create_test_backend().await;

        // Record some retrievals
        backend.record_successful_retrieval("node1").await.unwrap();
        backend.record_successful_retrieval("node1").await.unwrap();
        backend.record_failed_retrieval("node1").await.unwrap();

        let reputation = backend.get_reputation("node1").await.unwrap().unwrap();
        assert_eq!(reputation.successful_retrievals, 2);
        assert_eq!(reputation.failed_retrievals, 1);

        // Recalculate score
        let score = backend.recalculate_reputation("node1").await.unwrap();
        assert!(score > 0.0 && score < 1.0);

        // Get top nodes
        let top = backend.get_top_nodes(10).await.unwrap();
        assert_eq!(top.len(), 1);
    }

    #[tokio::test]
    async fn test_audit_log() {
        let backend = create_test_backend().await;

        // Append logs
        let id1 = backend
            .append_audit_log("content_stored", Some("node1"), None, Some(r#"{"size": 1024}"#))
            .await
            .unwrap();
        let id2 = backend
            .append_audit_log("content_retrieved", Some("node2"), None, None)
            .await
            .unwrap();

        assert!(id1 > 0);
        assert!(id2 > id1);

        // Get by type
        let logs = backend.get_audit_logs_by_type("content_stored", 100).await.unwrap();
        assert_eq!(logs.len(), 1);

        // Get by node
        let logs = backend.get_audit_logs_by_node("node1", 100).await.unwrap();
        assert_eq!(logs.len(), 1);

        // Get by time range
        let now = chrono::Utc::now().timestamp();
        let logs = backend.get_audit_logs(0, now + 1000, 100).await.unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_contract_stats() {
        let backend = create_test_backend().await;

        // Insert content first
        let content_hash = vec![1u8; 32];
        let metadata = ContentMetadataRow {
            content_hash: content_hash.clone(),
            size: 1024,
            owner_id: "owner1".to_string(),
            tier: "hot".to_string(),
            encryption_level: "none".to_string(),
            created_at: 1000,
            updated_at: 1000,
            tags: None,
            description: None,
        };
        backend.upsert_content_metadata(&metadata).await.unwrap();

        // Insert contracts
        for i in 0..3 {
            let contract = StorageContractRow {
                contract_id: format!("contract{}", i),
                content_hash: content_hash.clone(),
                provider_id: "provider1".to_string(),
                client_id: "client1".to_string(),
                status: if i == 0 { "active" } else { "expired" }.to_string(),
                start_time: 1000,
                end_time: 2000,
                price_per_day: 100,
                total_paid: 100 * (i as i64 + 1),
                created_at: 1000,
                updated_at: 1000,
            };
            backend.insert_contract(&contract).await.unwrap();
        }

        let stats = backend.get_contract_stats().await.unwrap();
        assert_eq!(stats.total_contracts, 3);
        assert_eq!(stats.active_contracts, 1);
        assert_eq!(stats.total_revenue, 600); // 100 + 200 + 300
    }
}
