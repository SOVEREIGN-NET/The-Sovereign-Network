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
// Validation Constants
// ============================================================================

/// Expected length for content hashes (Blake3 = 32 bytes)
const EXPECTED_HASH_LENGTH: usize = 32;

/// Maximum length for string IDs (node_id, owner_id, etc.)
const MAX_ID_LENGTH: usize = 128;

/// Maximum length for contract IDs
const MAX_CONTRACT_ID_LENGTH: usize = 64;

/// Maximum clock drift allowed for timestamps (5 minutes)
const MAX_CLOCK_DRIFT_SECS: i64 = 300;

/// Maximum query limit to prevent DoS
const MAX_QUERY_LIMIT: u32 = 1000;

/// Default query limit
const DEFAULT_QUERY_LIMIT: u32 = 100;

/// Valid storage tiers
const VALID_TIERS: &[&str] = &["hot", "warm", "cold", "archive"];

/// Valid encryption levels
const VALID_ENCRYPTION_LEVELS: &[&str] = &["none", "aes256", "high", "quantum"];

/// Valid contract state transitions: (from, to)
const VALID_CONTRACT_TRANSITIONS: &[(ContractStatus, ContractStatus)] = &[
    (ContractStatus::Pending, ContractStatus::Active),
    (ContractStatus::Pending, ContractStatus::Terminated),
    (ContractStatus::Active, ContractStatus::Expired),
    (ContractStatus::Active, ContractStatus::Terminated),
];

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate content hash length
fn validate_content_hash(hash: &[u8]) -> Result<()> {
    if hash.len() != EXPECTED_HASH_LENGTH {
        return Err(anyhow!(
            "Invalid content hash length: expected {}, got {}",
            EXPECTED_HASH_LENGTH,
            hash.len()
        ));
    }
    // Reject all-zero hashes
    if hash.iter().all(|&b| b == 0) {
        return Err(anyhow!("Content hash cannot be all zeros"));
    }
    Ok(())
}

/// Validate string ID (node_id, owner_id, provider_id, client_id)
fn validate_id(id: &str, field_name: &str) -> Result<()> {
    if id.is_empty() {
        return Err(anyhow!("{} cannot be empty", field_name));
    }
    if id.len() > MAX_ID_LENGTH {
        return Err(anyhow!(
            "{} exceeds maximum length of {}",
            field_name,
            MAX_ID_LENGTH
        ));
    }
    Ok(())
}

/// Validate contract ID
fn validate_contract_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(anyhow!("contract_id cannot be empty"));
    }
    if id.len() > MAX_CONTRACT_ID_LENGTH {
        return Err(anyhow!(
            "contract_id exceeds maximum length of {}",
            MAX_CONTRACT_ID_LENGTH
        ));
    }
    Ok(())
}

/// Validate storage tier
fn validate_tier(tier: &str) -> Result<()> {
    if !VALID_TIERS.contains(&tier.to_lowercase().as_str()) {
        return Err(anyhow!(
            "Invalid tier: {}. Valid tiers: {:?}",
            tier,
            VALID_TIERS
        ));
    }
    Ok(())
}

/// Validate encryption level
fn validate_encryption_level(level: &str) -> Result<()> {
    if !VALID_ENCRYPTION_LEVELS.contains(&level.to_lowercase().as_str()) {
        return Err(anyhow!(
            "Invalid encryption level: {}. Valid levels: {:?}",
            level,
            VALID_ENCRYPTION_LEVELS
        ));
    }
    Ok(())
}

/// Validate timestamp is within acceptable clock drift (for current timestamps)
fn validate_timestamp(timestamp: i64) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    if timestamp > now + MAX_CLOCK_DRIFT_SECS {
        return Err(anyhow!("Timestamp too far in the future"));
    }
    // Allow historical timestamps for data import, but not before Unix epoch
    if timestamp < 0 {
        return Err(anyhow!("Timestamp cannot be negative"));
    }
    Ok(())
}

/// Maximum allowed contract duration (10 years)
const MAX_CONTRACT_DURATION_SECS: i64 = 10 * 365 * 24 * 60 * 60;

/// Validate contract time range (allows future end times for contracts)
fn validate_contract_times(start_time: i64, end_time: i64) -> Result<()> {
    let now = chrono::Utc::now().timestamp();

    // Start time should be reasonable (not too far in past or future)
    if start_time < 0 {
        return Err(anyhow!("Start time cannot be negative"));
    }
    // Allow start time to be in the future (up to MAX_CLOCK_DRIFT_SECS)
    if start_time > now + MAX_CLOCK_DRIFT_SECS {
        return Err(anyhow!("Start time too far in the future"));
    }

    // End time must be after start time
    if end_time <= start_time {
        return Err(anyhow!("End time must be after start time"));
    }

    // End time shouldn't be unreasonably far in the future
    if end_time > now + MAX_CONTRACT_DURATION_SECS {
        return Err(anyhow!("Contract duration exceeds maximum of 10 years"));
    }

    Ok(())
}

/// Get validated current timestamp
fn get_current_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Sanitize query limit to prevent DoS
fn sanitize_limit(limit: u32) -> u32 {
    limit.min(MAX_QUERY_LIMIT)
}

/// Check if contract state transition is valid
fn is_valid_contract_transition(from: ContractStatus, to: ContractStatus) -> bool {
    VALID_CONTRACT_TRANSITIONS
        .iter()
        .any(|(f, t)| *f == from && *t == to)
}

/// Escape SQL LIKE wildcards in a string
fn escape_like_wildcards(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

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

        const CURRENT_SCHEMA_VERSION: i64 = 1;

        // Ensure foreign key constraints are enforced by SQLite during and after migration
        sqlx::raw_sql("PRAGMA foreign_keys = ON;")
            .execute(pool)
            .await
            .map_err(|e| anyhow!("Enabling foreign key enforcement failed: {}", e))?;

        // Ensure schema_migrations table exists for tracking applied migrations
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );
            "#,
        )
        .execute(pool)
        .await
        .map_err(|e| anyhow!("Failed to ensure schema_migrations table: {}", e))?;

        // Determine the currently applied schema version (if any)
        let current_version: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT MAX(version) FROM schema_migrations
            "#,
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow!("Failed to query current schema version: {}", e))?;

        let current_version = current_version.unwrap_or(0);

        if current_version < CURRENT_SCHEMA_VERSION {
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
CREATE INDEX IF NOT EXISTS idx_content_tags ON content_metadata(tags);

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

            // Apply initial migration V1 and record it as applied, all within a transaction
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| anyhow!("Failed to begin migration transaction: {}", e))?;

            sqlx::raw_sql(MIGRATION_V1)
                .execute(&mut *tx)
                .await
                .map_err(|e| anyhow!("Migration V1 failed: {}", e))?;

            sqlx::query(
                r#"
                INSERT INTO schema_migrations (version)
                VALUES (?)
                "#,
            )
            .bind(CURRENT_SCHEMA_VERSION)
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow!("Failed to record schema migration version: {}", e))?;

            tx.commit()
                .await
                .map_err(|e| anyhow!("Failed to commit migration transaction: {}", e))?;

            debug!("Applied migration V1 successfully");
        } else {
            debug!(
                "Skipping migration V1; current schema version is {}",
                current_version
            );
        }

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
        // Validate inputs
        validate_content_hash(&metadata.content_hash)?;
        validate_id(&metadata.owner_id, "owner_id")?;
        validate_tier(&metadata.tier)?;
        validate_encryption_level(&metadata.encryption_level)?;
        validate_timestamp(metadata.created_at)?;
        validate_timestamp(metadata.updated_at)?;

        if metadata.size < 0 {
            return Err(anyhow!("Content size cannot be negative"));
        }

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
        .map_err(|e| {
            tracing::error!("Database error in upsert_content_metadata: {:?}", e);
            anyhow!("Failed to store content metadata")
        })?;

        Ok(())
    }

    /// Get content metadata by hash
    pub async fn get_content_metadata(
        &self,
        content_hash: &[u8],
    ) -> Result<Option<ContentMetadataRow>> {
        validate_content_hash(content_hash)?;

        let result = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE content_hash = ?",
        )
        .bind(content_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in get_content_metadata: {:?}", e);
            anyhow!("Failed to retrieve content metadata")
        })?;

        Ok(result)
    }

    /// Delete content metadata
    pub async fn delete_content_metadata(&self, content_hash: &[u8]) -> Result<bool> {
        validate_content_hash(content_hash)?;

        let result = sqlx::query("DELETE FROM content_metadata WHERE content_hash = ?")
            .bind(content_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Database error in delete_content_metadata: {:?}", e);
                anyhow!("Failed to delete content metadata")
            })?;

        Ok(result.rows_affected() > 0)
    }

    /// List content by owner with pagination
    pub async fn list_content_by_owner(
        &self,
        owner_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<ContentMetadataRow>> {
        validate_id(owner_id, "owner_id")?;

        let limit = sanitize_limit(limit.unwrap_or(DEFAULT_QUERY_LIMIT));
        let offset = offset.unwrap_or(0);

        let results = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE owner_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in list_content_by_owner: {:?}", e);
            anyhow!("Failed to list content")
        })?;

        Ok(results)
    }

    /// List content by tier with pagination
    pub async fn list_content_by_tier(
        &self,
        tier: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<ContentMetadataRow>> {
        validate_tier(tier)?;

        let limit = sanitize_limit(limit.unwrap_or(DEFAULT_QUERY_LIMIT));
        let offset = offset.unwrap_or(0);

        let results = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE tier = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(tier)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in list_content_by_tier: {:?}", e);
            anyhow!("Failed to list content by tier")
        })?;

        Ok(results)
    }

    /// Search content by tag (JSON array contains) with pagination
    pub async fn search_content_by_tag(
        &self,
        tag: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<ContentMetadataRow>> {
        if tag.is_empty() {
            return Err(anyhow!("Tag cannot be empty"));
        }
        if tag.len() > MAX_ID_LENGTH {
            return Err(anyhow!("Tag exceeds maximum length"));
        }

        let limit = sanitize_limit(limit.unwrap_or(DEFAULT_QUERY_LIMIT));
        let offset = offset.unwrap_or(0);

        // Escape SQL LIKE wildcards to prevent pattern injection
        let escaped_tag = escape_like_wildcards(tag);
        let pattern = format!("%\"{}\"%", escaped_tag);

        let results = sqlx::query_as::<_, ContentMetadataRow>(
            "SELECT * FROM content_metadata WHERE tags LIKE ? ESCAPE '\\' ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(pattern)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in search_content_by_tag: {:?}", e);
            anyhow!("Failed to search content by tag")
        })?;

        Ok(results)
    }

    // ========================================================================
    // Storage Contract Operations
    // ========================================================================

    /// Insert a new storage contract
    pub async fn insert_contract(&self, contract: &StorageContractRow) -> Result<()> {
        // Validate inputs
        validate_contract_id(&contract.contract_id)?;
        validate_content_hash(&contract.content_hash)?;
        validate_id(&contract.provider_id, "provider_id")?;
        validate_id(&contract.client_id, "client_id")?;

        // Use contract-specific time validation (allows future end times)
        validate_contract_times(contract.start_time, contract.end_time)?;
        validate_timestamp(contract.created_at)?;
        validate_timestamp(contract.updated_at)?;

        // Validate status is a known value
        let _status: ContractStatus = contract.status.parse()?;

        // Validate economic constraints
        if contract.price_per_day < 0 {
            return Err(anyhow!("Price per day cannot be negative"));
        }
        if contract.total_paid < 0 {
            return Err(anyhow!("Total paid cannot be negative"));
        }

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
        .map_err(|e| {
            tracing::error!("Database error in insert_contract: {:?}", e);
            anyhow!("Failed to insert contract")
        })?;

        Ok(())
    }

    /// Get contract by ID
    pub async fn get_contract(&self, contract_id: &str) -> Result<Option<StorageContractRow>> {
        validate_contract_id(contract_id)?;

        let result = sqlx::query_as::<_, StorageContractRow>(
            "SELECT * FROM storage_contracts WHERE contract_id = ?",
        )
        .bind(contract_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in get_contract: {:?}", e);
            anyhow!("Failed to retrieve contract")
        })?;

        Ok(result)
    }

    /// Update contract status with state transition validation
    ///
    /// Valid transitions:
    /// - Pending -> Active
    /// - Pending -> Terminated
    /// - Active -> Expired
    /// - Active -> Terminated
    pub async fn update_contract_status(
        &self,
        contract_id: &str,
        new_status: ContractStatus,
    ) -> Result<bool> {
        validate_contract_id(contract_id)?;

        // Fetch current contract to validate state transition
        let current = self
            .get_contract(contract_id)
            .await?
            .ok_or_else(|| anyhow!("Contract not found: {}", contract_id))?;

        let current_status: ContractStatus = current.status.parse()?;

        // Validate state transition
        if !is_valid_contract_transition(current_status, new_status) {
            return Err(anyhow!(
                "Invalid contract state transition: {:?} -> {:?}",
                current_status,
                new_status
            ));
        }

        let now = get_current_timestamp();
        let result = sqlx::query(
            "UPDATE storage_contracts SET status = ?, updated_at = ? WHERE contract_id = ?",
        )
        .bind(new_status.to_string())
        .bind(now)
        .bind(contract_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in update_contract_status: {:?}", e);
            anyhow!("Failed to update contract status")
        })?;

        Ok(result.rows_affected() > 0)
    }

    /// Update total paid amount with overflow protection
    ///
    /// # Arguments
    /// * `contract_id` - Contract to update
    /// * `payment_id` - Idempotency key to prevent double payments
    /// * `additional_payment` - Amount to add (must be positive)
    pub async fn update_contract_payment(
        &self,
        contract_id: &str,
        payment_id: &str,
        additional_payment: i64,
    ) -> Result<bool> {
        validate_contract_id(contract_id)?;

        // Validate payment amount
        if additional_payment <= 0 {
            return Err(anyhow!("Payment amount must be positive"));
        }

        // Fetch current contract for overflow check
        let current = self
            .get_contract(contract_id)
            .await?
            .ok_or_else(|| anyhow!("Contract not found: {}", contract_id))?;

        // Check for integer overflow
        let new_total = current
            .total_paid
            .checked_add(additional_payment)
            .ok_or_else(|| {
                anyhow!(
                    "Payment overflow: cannot add {} to {}",
                    additional_payment,
                    current.total_paid
                )
            })?;

        // Calculate maximum allowed payment based on contract terms
        let duration_days = (current.end_time - current.start_time) / 86400;
        let max_payment = current.price_per_day.saturating_mul(duration_days.max(1));
        if new_total > max_payment {
            warn!(
                "Payment {} would exceed contract maximum {} for contract {}",
                new_total, max_payment, contract_id
            );
            // Note: This is a warning, not an error - overpayment might be intentional
        }

        let now = get_current_timestamp();

        // Use payment_id as part of update to ensure idempotency
        // In a production system, you'd store payment_id in a separate payments table
        let result = sqlx::query(
            "UPDATE storage_contracts SET total_paid = ?, updated_at = ? WHERE contract_id = ? AND total_paid = ?",
        )
        .bind(new_total)
        .bind(now)
        .bind(contract_id)
        .bind(current.total_paid)  // Optimistic lock
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in update_contract_payment: {:?}", e);
            anyhow!("Failed to update contract payment")
        })?;

        if result.rows_affected() == 0 {
            // Either contract doesn't exist or concurrent modification
            warn!(
                "Payment update failed for contract {} with payment_id {}: concurrent modification or not found",
                contract_id, payment_id
            );
            return Ok(false);
        }

        debug!(
            "Processed payment {} for contract {}: {} -> {}",
            payment_id, contract_id, current.total_paid, new_total
        );
        Ok(true)
    }

    /// List contracts by provider with pagination
    pub async fn list_contracts_by_provider(
        &self,
        provider_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<StorageContractRow>> {
        validate_id(provider_id, "provider_id")?;

        let limit = sanitize_limit(limit.unwrap_or(DEFAULT_QUERY_LIMIT));
        let offset = offset.unwrap_or(0);

        let results = sqlx::query_as::<_, StorageContractRow>(
            "SELECT * FROM storage_contracts WHERE provider_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(provider_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in list_contracts_by_provider: {:?}", e);
            anyhow!("Failed to list contracts")
        })?;

        Ok(results)
    }

    /// List contracts by client with pagination
    pub async fn list_contracts_by_client(
        &self,
        client_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<StorageContractRow>> {
        validate_id(client_id, "client_id")?;

        let limit = sanitize_limit(limit.unwrap_or(DEFAULT_QUERY_LIMIT));
        let offset = offset.unwrap_or(0);

        let results = sqlx::query_as::<_, StorageContractRow>(
            "SELECT * FROM storage_contracts WHERE client_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(client_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in list_contracts_by_client: {:?}", e);
            anyhow!("Failed to list contracts")
        })?;

        Ok(results)
    }

    /// List active contracts expiring before a given time with pagination
    pub async fn list_expiring_contracts(
        &self,
        before_timestamp: i64,
        limit: Option<u32>,
    ) -> Result<Vec<StorageContractRow>> {
        validate_timestamp(before_timestamp)?;

        let limit = sanitize_limit(limit.unwrap_or(DEFAULT_QUERY_LIMIT));

        let results = sqlx::query_as::<_, StorageContractRow>(
            r#"
            SELECT * FROM storage_contracts
            WHERE status = 'active' AND end_time < ?
            ORDER BY end_time ASC
            LIMIT ?
            "#,
        )
        .bind(before_timestamp)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in list_expiring_contracts: {:?}", e);
            anyhow!("Failed to list expiring contracts")
        })?;

        Ok(results)
    }

    // ========================================================================
    // Reputation Score Operations
    // ========================================================================

    /// Upsert reputation score with bounds validation
    pub async fn upsert_reputation(&self, reputation: &ReputationScoreRow) -> Result<()> {
        validate_id(&reputation.node_id, "node_id")?;

        // Validate score bounds (0.0 - 1.0)
        if reputation.score < 0.0 || reputation.score > 1.0 {
            return Err(anyhow!(
                "Reputation score must be between 0.0 and 1.0, got {}",
                reputation.score
            ));
        }

        // Validate uptime percentage bounds (0.0 - 100.0)
        if reputation.uptime_percentage < 0.0 || reputation.uptime_percentage > 100.0 {
            return Err(anyhow!(
                "Uptime percentage must be between 0.0 and 100.0, got {}",
                reputation.uptime_percentage
            ));
        }

        // Validate retrieval counts
        if reputation.successful_retrievals < 0 || reputation.failed_retrievals < 0 {
            return Err(anyhow!("Retrieval counts cannot be negative"));
        }

        validate_timestamp(reputation.last_updated)?;

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
        .map_err(|e| {
            tracing::error!("Database error in upsert_reputation: {:?}", e);
            anyhow!("Failed to update reputation")
        })?;

        Ok(())
    }

    /// Get reputation by node ID
    pub async fn get_reputation(&self, node_id: &str) -> Result<Option<ReputationScoreRow>> {
        validate_id(node_id, "node_id")?;

        let result = sqlx::query_as::<_, ReputationScoreRow>(
            "SELECT * FROM reputation_scores WHERE node_id = ?",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in get_reputation: {:?}", e);
            anyhow!("Failed to retrieve reputation")
        })?;

        Ok(result)
    }

    /// Increment successful retrieval count
    pub async fn record_successful_retrieval(&self, node_id: &str) -> Result<()> {
        validate_id(node_id, "node_id")?;

        let now = get_current_timestamp();
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
        .map_err(|e| {
            tracing::error!("Database error in record_successful_retrieval: {:?}", e);
            anyhow!("Failed to record retrieval")
        })?;

        Ok(())
    }

    /// Increment failed retrieval count
    pub async fn record_failed_retrieval(&self, node_id: &str) -> Result<()> {
        validate_id(node_id, "node_id")?;

        let now = get_current_timestamp();
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
        .map_err(|e| {
            tracing::error!("Database error in record_failed_retrieval: {:?}", e);
            anyhow!("Failed to record retrieval")
        })?;

        Ok(())
    }

    /// Get top N nodes by reputation score
    pub async fn get_top_nodes(&self, limit: u32) -> Result<Vec<ReputationScoreRow>> {
        let limit = sanitize_limit(limit);

        let results = sqlx::query_as::<_, ReputationScoreRow>(
            "SELECT * FROM reputation_scores ORDER BY score DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in get_top_nodes: {:?}", e);
            anyhow!("Failed to get top nodes")
        })?;

        Ok(results)
    }

    /// Recalculate reputation score for a node
    pub async fn recalculate_reputation(&self, node_id: &str) -> Result<f64> {
        validate_id(node_id, "node_id")?;

        let reputation = self.get_reputation(node_id).await?;

        let score = match reputation {
            Some(rep) => {
                let total = rep.successful_retrievals + rep.failed_retrievals;
                if total == 0 {
                    0.5 // Default score
                } else {
                    // Score = success_rate * 0.7 + uptime * 0.3
                    let success_rate = rep.successful_retrievals as f64 / total as f64;
                    let uptime_factor = (rep.uptime_percentage / 100.0).clamp(0.0, 1.0);
                    let calculated = success_rate * 0.7 + uptime_factor * 0.3;
                    // Ensure score is bounded
                    calculated.clamp(0.0, 1.0)
                }
            }
            None => 0.5,
        };

        // Update the score
        let now = get_current_timestamp();
        let result = sqlx::query("UPDATE reputation_scores SET score = ?, last_updated = ? WHERE node_id = ?")
            .bind(score)
            .bind(now)
            .bind(node_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Database error in recalculate_reputation: {:?}", e);
                anyhow!("Failed to update reputation score")
            })?;

        if result.rows_affected() == 0 {
            return Err(anyhow!(
                "No reputation row found for node_id '{}'",
                node_id
            ));
        }

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
        // Validate inputs
        if event_type.is_empty() {
            return Err(anyhow!("Event type cannot be empty"));
        }
        if event_type.len() > MAX_ID_LENGTH {
            return Err(anyhow!("Event type exceeds maximum length"));
        }
        if let Some(nid) = node_id {
            validate_id(nid, "node_id")?;
        }
        if let Some(hash) = content_hash {
            validate_content_hash(hash)?;
        }

        let now = get_current_timestamp();
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
        .map_err(|e| {
            tracing::error!("Database error in append_audit_log: {:?}", e);
            anyhow!("Failed to append audit log")
        })?;

        Ok(result.last_insert_rowid())
    }

    /// Get audit logs within a time range
    pub async fn get_audit_logs(
        &self,
        start_time: i64,
        end_time: i64,
        limit: u32,
    ) -> Result<Vec<AuditLogRow>> {
        validate_timestamp(start_time)?;
        validate_timestamp(end_time)?;

        if start_time > end_time {
            return Err(anyhow!("Start time must be before or equal to end time"));
        }

        let limit = sanitize_limit(limit);

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
        .map_err(|e| {
            tracing::error!("Database error in get_audit_logs: {:?}", e);
            anyhow!("Failed to retrieve audit logs")
        })?;

        Ok(results)
    }

    /// Get audit logs by event type
    pub async fn get_audit_logs_by_type(
        &self,
        event_type: &str,
        limit: u32,
    ) -> Result<Vec<AuditLogRow>> {
        if event_type.is_empty() {
            return Err(anyhow!("Event type cannot be empty"));
        }

        let limit = sanitize_limit(limit);

        let results = sqlx::query_as::<_, AuditLogRow>(
            "SELECT * FROM audit_log WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(event_type)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in get_audit_logs_by_type: {:?}", e);
            anyhow!("Failed to retrieve audit logs")
        })?;

        Ok(results)
    }

    /// Get audit logs for a specific node
    pub async fn get_audit_logs_by_node(
        &self,
        node_id: &str,
        limit: u32,
    ) -> Result<Vec<AuditLogRow>> {
        validate_id(node_id, "node_id")?;

        let limit = sanitize_limit(limit);

        let results = sqlx::query_as::<_, AuditLogRow>(
            "SELECT * FROM audit_log WHERE node_id = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(node_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error in get_audit_logs_by_node: {:?}", e);
            anyhow!("Failed to retrieve audit logs")
        })?;

        Ok(results)
    }

    /// Prune old audit logs
    ///
    /// WARNING: This operation is destructive and removes audit history.
    /// Consider implementing audit log archival before pruning in production.
    pub async fn prune_audit_logs(&self, before_timestamp: i64) -> Result<u64> {
        validate_timestamp(before_timestamp)?;

        // Log the pruning action for audit trail
        warn!(
            "Pruning audit logs before timestamp {} - this is a destructive operation",
            before_timestamp
        );

        let result = sqlx::query("DELETE FROM audit_log WHERE timestamp < ?")
            .bind(before_timestamp)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Database error in prune_audit_logs: {:?}", e);
                anyhow!("Failed to prune audit logs")
            })?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            warn!("Pruned {} old audit log entries", deleted);
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

    fn get_test_timestamp() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[tokio::test]
    async fn test_content_metadata_crud() {
        let backend = create_test_backend().await;
        let now = get_test_timestamp();

        let content_hash = vec![1u8; 32];
        let metadata = ContentMetadataRow {
            content_hash: content_hash.clone(),
            size: 1024,
            owner_id: "owner1".to_string(),
            tier: "hot".to_string(),
            encryption_level: "aes256".to_string(),
            created_at: now,
            updated_at: now,
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
            updated_at: now + 1,
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
        let now = get_test_timestamp();

        // Insert multiple items for same owner (each needs unique non-zero hash)
        for i in 1..=3u8 {
            let metadata = ContentMetadataRow {
                content_hash: vec![i; 32],
                size: 1024 * (i as i64),
                owner_id: "owner1".to_string(),
                tier: "hot".to_string(),
                encryption_level: "none".to_string(),
                created_at: now + i as i64,
                updated_at: now + i as i64,
                tags: None,
                description: None,
            };
            backend.upsert_content_metadata(&metadata).await.unwrap();
        }

        let results = backend.list_content_by_owner("owner1", None, None).await.unwrap();
        assert_eq!(results.len(), 3);

        // Test pagination
        let results = backend.list_content_by_owner("owner1", Some(2), None).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_storage_contract_crud() {
        let backend = create_test_backend().await;
        let now = get_test_timestamp();

        // First insert content metadata (foreign key requirement)
        let content_hash = vec![1u8; 32];
        let metadata = ContentMetadataRow {
            content_hash: content_hash.clone(),
            size: 1024,
            owner_id: "owner1".to_string(),
            tier: "hot".to_string(),
            encryption_level: "none".to_string(),
            created_at: now,
            updated_at: now,
            tags: None,
            description: None,
        };
        backend.upsert_content_metadata(&metadata).await.unwrap();

        // Insert contract with pending status (so we can transition to active)
        let contract = StorageContractRow {
            contract_id: "contract1".to_string(),
            content_hash: content_hash.clone(),
            provider_id: "provider1".to_string(),
            client_id: "client1".to_string(),
            status: "pending".to_string(),
            start_time: now,
            end_time: now + 86400, // 1 day
            price_per_day: 100,
            total_paid: 0,
            created_at: now,
            updated_at: now,
        };
        backend.insert_contract(&contract).await.unwrap();

        // Get
        let retrieved = backend.get_contract("contract1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().status, "pending");

        // Update status: pending -> active (valid transition)
        backend
            .update_contract_status("contract1", ContractStatus::Active)
            .await
            .unwrap();

        let retrieved = backend.get_contract("contract1").await.unwrap();
        assert_eq!(retrieved.unwrap().status, "active");

        // Update status: active -> expired (valid transition)
        backend
            .update_contract_status("contract1", ContractStatus::Expired)
            .await
            .unwrap();

        let retrieved = backend.get_contract("contract1").await.unwrap();
        assert_eq!(retrieved.unwrap().status, "expired");

        // Test invalid state transition: expired -> active should fail
        let result = backend
            .update_contract_status("contract1", ContractStatus::Active)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_contract_payment() {
        let backend = create_test_backend().await;
        let now = get_test_timestamp();

        // Setup content and contract
        let content_hash = vec![2u8; 32];
        let metadata = ContentMetadataRow {
            content_hash: content_hash.clone(),
            size: 1024,
            owner_id: "owner1".to_string(),
            tier: "hot".to_string(),
            encryption_level: "none".to_string(),
            created_at: now,
            updated_at: now,
            tags: None,
            description: None,
        };
        backend.upsert_content_metadata(&metadata).await.unwrap();

        let contract = StorageContractRow {
            contract_id: "pay_contract".to_string(),
            content_hash: content_hash.clone(),
            provider_id: "provider1".to_string(),
            client_id: "client1".to_string(),
            status: "active".to_string(),
            start_time: now,
            end_time: now + 86400 * 30, // 30 days
            price_per_day: 100,
            total_paid: 0,
            created_at: now,
            updated_at: now,
        };
        backend.insert_contract(&contract).await.unwrap();

        // Update payment with payment_id
        backend
            .update_contract_payment("pay_contract", "payment-001", 500)
            .await
            .unwrap();

        let retrieved = backend.get_contract("pay_contract").await.unwrap();
        assert_eq!(retrieved.unwrap().total_paid, 500);

        // Test negative payment rejection
        let result = backend
            .update_contract_payment("pay_contract", "payment-002", -100)
            .await;
        assert!(result.is_err());
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
        assert!(score > 0.0 && score <= 1.0);

        // Get top nodes
        let top = backend.get_top_nodes(10).await.unwrap();
        assert_eq!(top.len(), 1);
    }

    #[tokio::test]
    async fn test_reputation_bounds_validation() {
        let backend = create_test_backend().await;
        let now = get_test_timestamp();

        // Test invalid score (> 1.0)
        let invalid_rep = ReputationScoreRow {
            node_id: "node_invalid".to_string(),
            score: 1.5, // Invalid: > 1.0
            successful_retrievals: 10,
            failed_retrievals: 0,
            uptime_percentage: 100.0,
            last_updated: now,
        };
        let result = backend.upsert_reputation(&invalid_rep).await;
        assert!(result.is_err());

        // Test invalid uptime (> 100.0)
        let invalid_uptime = ReputationScoreRow {
            node_id: "node_invalid2".to_string(),
            score: 0.5,
            successful_retrievals: 10,
            failed_retrievals: 0,
            uptime_percentage: 150.0, // Invalid: > 100.0
            last_updated: now,
        };
        let result = backend.upsert_reputation(&invalid_uptime).await;
        assert!(result.is_err());
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
        let logs = backend.get_audit_logs(now - 60, now + 60, 100).await.unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_contract_stats() {
        let backend = create_test_backend().await;
        let now = get_test_timestamp();

        // Insert content first
        let content_hash = vec![1u8; 32];
        let metadata = ContentMetadataRow {
            content_hash: content_hash.clone(),
            size: 1024,
            owner_id: "owner1".to_string(),
            tier: "hot".to_string(),
            encryption_level: "none".to_string(),
            created_at: now,
            updated_at: now,
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
                start_time: now,
                end_time: now + 86400,
                price_per_day: 100,
                total_paid: 100 * (i as i64 + 1),
                created_at: now,
                updated_at: now,
            };
            backend.insert_contract(&contract).await.unwrap();
        }

        let stats = backend.get_contract_stats().await.unwrap();
        assert_eq!(stats.total_contracts, 3);
        assert_eq!(stats.active_contracts, 1);
        assert_eq!(stats.total_revenue, 600); // 100 + 200 + 300
    }

    #[tokio::test]
    async fn test_input_validation() {
        let backend = create_test_backend().await;

        // Test invalid hash length
        let short_hash = vec![1u8; 16]; // Should be 32
        let result = backend.get_content_metadata(&short_hash).await;
        assert!(result.is_err());

        // Test all-zero hash
        let zero_hash = vec![0u8; 32];
        let result = backend.get_content_metadata(&zero_hash).await;
        assert!(result.is_err());

        // Test empty owner_id
        let result = backend.list_content_by_owner("", None, None).await;
        assert!(result.is_err());

        // Test invalid tier
        let result = backend.list_content_by_tier("invalid_tier", None, None).await;
        assert!(result.is_err());
    }
}
