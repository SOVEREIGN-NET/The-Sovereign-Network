use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use uuid::Uuid;
use log::{error, info, warn};

/// Audit event types for comprehensive security logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    // Authentication events
    UserLogin,
    UserLogout,
    UserLoginFailed,
    UserAccountLocked,
    UserPasswordChanged,
    UserCreated,
    UserDeleted,
    UserRoleChanged,
    
    // API events
    ApiKeyCreated,
    ApiKeyUsed,
    ApiKeyRevoked,
    ApiKeyExpired,
    
    // System events
    SystemStartup,
    SystemShutdown,
    SystemOperation,
    ConfigurationChanged,
    ServiceStarted,
    ServiceStopped,
    
    // Security events
    SecurityBreach,
    SuspiciousActivity,
    RateLimitExceeded,
    UnauthorizedAccess,
    CsrfTokenValidationFailed,
    InvalidCertificate,
    TlsHandshakeFailed,
    
    // Data events
    DataAccessed,
    DataModified,
    DataDeleted,
    DataExported,
    SensitiveDataAccessed,
    
    // Network events
    ConnectionEstablished,
    ConnectionClosed,
    NetworkError,
    DDoSAttackDetected,
    
    // Consensus events
    ValidatorRegistered,
    ValidatorSlashed,
    BlockProduced,
    BlockValidated,
    ConsensusFailure,
    
    // Administrative events
    AdminActionPerformed,
    PolicyChanged,
    UserPermissionChanged,
    SystemMaintenance,
}

/// Audit event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub event_id: String,
    /// Timestamp in Unix seconds
    pub timestamp: u64,
    /// Event type
    pub event_type: AuditEventType,
    /// Event severity
    pub severity: AuditSeverity,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User ID if applicable
    pub user_id: Option<String>,
    /// Session ID if applicable
    pub session_id: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Event description
    pub description: String,
    /// Additional event data
    pub metadata: HashMap<String, String>,
    /// Resource affected
    pub resource: Option<String>,
    /// Action performed
    pub action: Option<String>,
    /// Result of the action
    pub result: AuditResult,
    /// Request ID for correlation
    pub request_id: Option<String>,
}

/// Result of audited action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
    Error,
}

/// Audit trail configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_file_path: PathBuf,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub buffer_size: usize,
    pub flush_interval_seconds: u64,
    pub log_levels: Vec<AuditSeverity>,
    pub log_event_types: Vec<AuditEventType>,
    pub encrypt_logs: bool,
    pub compress_old_logs: bool,
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file_path: PathBuf::from("./logs/audit.jsonl"),
            max_file_size_mb: 100,
            max_files: 10,
            buffer_size: 1000,
            flush_interval_seconds: 30,
            log_levels: vec![
                AuditSeverity::Info,
                AuditSeverity::Warning,
                AuditSeverity::Error,
                AuditSeverity::Critical,
            ],
            log_event_types: vec![], // Empty means log all types
            encrypt_logs: false,
            compress_old_logs: true,
            retention_days: 365,
        }
    }
}

/// Audit trail system for comprehensive security logging
#[derive(Debug)]
pub struct AuditTrail {
    config: AuditConfig,
    event_sender: mpsc::Sender<AuditEvent>,
    stats: Arc<RwLock<AuditStats>>,
}

/// Audit statistics
#[derive(Debug, Default, Clone, Serialize)]
pub struct AuditStats {
    pub total_events: u64,
    pub events_by_type: HashMap<String, u64>,
    pub events_by_severity: HashMap<String, u64>,
    pub events_by_result: HashMap<String, u64>,
    pub last_event_time: Option<u64>,
    pub buffer_overflows: u64,
    pub write_errors: u64,
}

impl AuditTrail {
    /// Create new audit trail system
    pub async fn new(config: AuditConfig) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::channel(config.buffer_size);
        let stats = Arc::new(RwLock::new(AuditStats::default()));

        // Ensure log directory exists
        if let Some(parent) = config.log_file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let audit_trail = Self {
            config: config.clone(),
            event_sender,
            stats: stats.clone(),
        };

        // Start the audit writer task
        Self::start_audit_writer(config, event_receiver, stats).await;

        info!("Audit trail system initialized");
        Ok(audit_trail)
    }

    /// Log an audit event
    pub async fn log_event(&self, mut event: AuditEvent) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Set timestamp if not already set
        if event.timestamp == 0 {
            event.timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();
        }

        // Generate event ID if not set
        if event.event_id.is_empty() {
            event.event_id = Uuid::new_v4().to_string();
        }

        // Check if we should log this event type
        if !self.config.log_event_types.is_empty() {
            let event_type_matches = self.config.log_event_types.iter()
                .any(|t| std::mem::discriminant(t) == std::mem::discriminant(&event.event_type));
            if !event_type_matches {
                return Ok(());
            }
        }

        // Check if we should log this severity level
        let severity_matches = self.config.log_levels.iter()
            .any(|s| std::mem::discriminant(s) == std::mem::discriminant(&event.severity));
        if !severity_matches {
            return Ok(());
        }

        // Send event to writer
        if let Err(_) = self.event_sender.try_send(event.clone()) {
            // Buffer is full, increment overflow counter
            let mut stats = self.stats.write().await;
            stats.buffer_overflows += 1;
            warn!("Audit event buffer overflow, event dropped: {}", event.event_id);
        }

        Ok(())
    }

    /// Log authentication event
    pub async fn log_auth_event(
        &self,
        event_type: AuditEventType,
        user_id: Option<String>,
        source_ip: Option<String>,
        user_agent: Option<String>,
        result: AuditResult,
        description: String,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<()> {
        let event = AuditEvent {
            event_id: String::new(), // Will be generated
            timestamp: 0, // Will be set
            event_type,
            severity: match result {
                AuditResult::Success => AuditSeverity::Info,
                AuditResult::Failure | AuditResult::Denied => AuditSeverity::Warning,
                AuditResult::Error => AuditSeverity::Error,
            },
            source_ip,
            user_id,
            session_id: None,
            user_agent,
            description,
            metadata: metadata.unwrap_or_default(),
            resource: Some("authentication".to_string()),
            action: Some("authenticate".to_string()),
            result,
            request_id: None,
        };

        self.log_event(event).await
    }

    /// Log API access event
    pub async fn log_api_event(
        &self,
        method: &str,
        path: &str,
        user_id: Option<String>,
        source_ip: Option<String>,
        user_agent: Option<String>,
        result: AuditResult,
        response_code: u16,
        request_id: Option<String>,
    ) -> Result<()> {
        let severity = match response_code {
            200..=299 => AuditSeverity::Info,
            400..=499 => AuditSeverity::Warning,
            500..=599 => AuditSeverity::Error,
            _ => AuditSeverity::Info,
        };

        let mut metadata = HashMap::new();
        metadata.insert("method".to_string(), method.to_string());
        metadata.insert("response_code".to_string(), response_code.to_string());

        let event = AuditEvent {
            event_id: String::new(),
            timestamp: 0,
            event_type: AuditEventType::DataAccessed,
            severity,
            source_ip,
            user_id,
            session_id: None,
            user_agent,
            description: format!("{} {}", method, path),
            metadata,
            resource: Some(path.to_string()),
            action: Some(method.to_string()),
            result,
            request_id,
        };

        self.log_event(event).await
    }

    /// Log security event
    pub async fn log_security_event(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        source_ip: Option<String>,
        description: String,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<()> {
        let event = AuditEvent {
            event_id: String::new(),
            timestamp: 0,
            event_type,
            severity,
            source_ip,
            user_id: None,
            session_id: None,
            user_agent: None,
            description,
            metadata: metadata.unwrap_or_default(),
            resource: Some("security".to_string()),
            action: Some("security_check".to_string()),
            result: AuditResult::Success, // Security events are informational
            request_id: None,
        };

        self.log_event(event).await
    }

    /// Log system event
    pub async fn log_system_event(
        &self,
        event_type: AuditEventType,
        description: String,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<()> {
        let event = AuditEvent {
            event_id: String::new(),
            timestamp: 0,
            event_type,
            severity: AuditSeverity::Info,
            source_ip: None,
            user_id: None,
            session_id: None,
            user_agent: None,
            description,
            metadata: metadata.unwrap_or_default(),
            resource: Some("system".to_string()),
            action: Some("system_operation".to_string()),
            result: AuditResult::Success,
            request_id: None,
        };

        self.log_event(event).await
    }

    /// Get audit statistics
    pub async fn get_stats(&self) -> AuditStats {
        self.stats.read().await.clone()
    }

    /// Search audit events (simplified version)
    pub async fn search_events(
        &self,
        start_time: u64,
        end_time: u64,
        _event_types: Option<Vec<AuditEventType>>,
        _user_id: Option<String>,
        _max_results: usize,
    ) -> Result<Vec<AuditEvent>> {
        // In a production system, this would query a database or search through log files
        // For now, return empty results
        info!("Audit search requested: {} to {}", start_time, end_time);
        Ok(Vec::new())
    }

    /// Start the audit writer task
    async fn start_audit_writer(
        config: AuditConfig,
        mut event_receiver: mpsc::Receiver<AuditEvent>,
        stats: Arc<RwLock<AuditStats>>,
    ) {
        tokio::spawn(async move {
            let mut file_writer = AuditFileWriter::new(config.clone()).await
                .expect("Failed to create audit file writer");

            let mut flush_interval = interval(Duration::from_secs(config.flush_interval_seconds));
            let mut events_buffer = Vec::new();

            loop {
                tokio::select! {
                    // Receive new events
                    Some(event) = event_receiver.recv() => {
                        events_buffer.push(event);
                        
                        // Flush if buffer is full
                        if events_buffer.len() >= config.buffer_size {
                            Self::write_events(&mut file_writer, &mut events_buffer, &stats).await;
                        }
                    }
                    
                    // Periodic flush
                    _ = flush_interval.tick() => {
                        if !events_buffer.is_empty() {
                            Self::write_events(&mut file_writer, &mut events_buffer, &stats).await;
                        }
                    }
                }
            }
        });
    }

    /// Write events to file and update statistics
    async fn write_events(
        file_writer: &mut AuditFileWriter,
        events_buffer: &mut Vec<AuditEvent>,
        stats: &Arc<RwLock<AuditStats>>,
    ) {
        if events_buffer.is_empty() {
            return;
        }

        match file_writer.write_events(events_buffer).await {
            Ok(_) => {
                // Update statistics
                let mut stats_guard = stats.write().await;
                for event in events_buffer.iter() {
                    stats_guard.total_events += 1;
                    stats_guard.last_event_time = Some(event.timestamp);
                    
                    let event_type_key = format!("{:?}", event.event_type);
                    *stats_guard.events_by_type.entry(event_type_key).or_insert(0) += 1;
                    
                    let severity_key = format!("{:?}", event.severity);
                    *stats_guard.events_by_severity.entry(severity_key).or_insert(0) += 1;
                    
                    let result_key = format!("{:?}", event.result);
                    *stats_guard.events_by_result.entry(result_key).or_insert(0) += 1;
                }
            }
            Err(e) => {
                error!("Failed to write audit events: {}", e);
                let mut stats_guard = stats.write().await;
                stats_guard.write_errors += 1;
            }
        }

        events_buffer.clear();
    }
}

/// File writer for audit events
struct AuditFileWriter {
    config: AuditConfig,
    current_file_size: u64,
    current_file_index: u32,
}

impl AuditFileWriter {
    async fn new(config: AuditConfig) -> Result<Self> {
        Ok(Self {
            config,
            current_file_size: 0,
            current_file_index: 0,
        })
    }

    async fn write_events(&mut self, events: &[AuditEvent]) -> Result<()> {
        // Check if we need to rotate the log file
        self.check_file_rotation().await?;

        let file_path = self.get_current_file_path();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        for event in events {
            let json_line = serde_json::to_string(event)?;
            writeln!(file, "{}", json_line)?;
            self.current_file_size += json_line.len() as u64 + 1; // +1 for newline
        }

        file.flush()?;
        Ok(())
    }

    async fn check_file_rotation(&mut self) -> Result<()> {
        let max_size_bytes = self.config.max_file_size_mb * 1024 * 1024;
        
        if self.current_file_size >= max_size_bytes {
            self.rotate_files().await?;
        }
        
        Ok(())
    }

    async fn rotate_files(&mut self) -> Result<()> {
        // Move current files
        for i in (1..self.config.max_files).rev() {
            let old_path = self.get_file_path(i - 1);
            let new_path = self.get_file_path(i);
            
            if old_path.exists() {
                if new_path.exists() {
                    tokio::fs::remove_file(&new_path).await?;
                }
                tokio::fs::rename(&old_path, &new_path).await?;
            }
        }

        // Reset current file
        self.current_file_size = 0;
        self.current_file_index = 0;

        info!("Audit log files rotated");
        Ok(())
    }

    fn get_current_file_path(&self) -> PathBuf {
        self.get_file_path(self.current_file_index)
    }

    fn get_file_path(&self, index: u32) -> PathBuf {
        if index == 0 {
            self.config.log_file_path.clone()
        } else {
            let mut path = self.config.log_file_path.clone();
            let file_name = path.file_stem().unwrap().to_string_lossy();
            let extension = path.extension().unwrap_or_default().to_string_lossy();
            
            path.set_file_name(format!("{}.{}.{}", file_name, index, extension));
            path
        }
    }
}

/// Audit event builder for convenient event creation
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            event: AuditEvent {
                event_id: String::new(),
                timestamp: 0,
                event_type,
                severity: AuditSeverity::Info,
                source_ip: None,
                user_id: None,
                session_id: None,
                user_agent: None,
                description: String::new(),
                metadata: HashMap::new(),
                resource: None,
                action: None,
                result: AuditResult::Success,
                request_id: None,
            },
        }
    }

    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.event.severity = severity;
        self
    }

    pub fn source_ip(mut self, ip: String) -> Self {
        self.event.source_ip = Some(ip);
        self
    }

    pub fn user_id(mut self, user_id: String) -> Self {
        self.event.user_id = Some(user_id);
        self
    }

    pub fn session_id(mut self, session_id: String) -> Self {
        self.event.session_id = Some(session_id);
        self
    }

    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.event.user_agent = Some(user_agent);
        self
    }

    pub fn description(mut self, description: String) -> Self {
        self.event.description = description;
        self
    }

    pub fn resource(mut self, resource: String) -> Self {
        self.event.resource = Some(resource);
        self
    }

    pub fn action(mut self, action: String) -> Self {
        self.event.action = Some(action);
        self
    }

    pub fn result(mut self, result: AuditResult) -> Self {
        self.event.result = result;
        self
    }

    pub fn request_id(mut self, request_id: String) -> Self {
        self.event.request_id = Some(request_id);
        self
    }

    pub fn metadata(mut self, key: String, value: String) -> Self {
        self.event.metadata.insert(key, value);
        self
    }

    pub fn build(self) -> AuditEvent {
        self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_audit_trail() {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("audit.jsonl");

        let config = AuditConfig {
            enabled: true,
            log_file_path: log_path,
            max_file_size_mb: 1,
            max_files: 3,
            buffer_size: 10,
            flush_interval_seconds: 1,
            ..Default::default()
        };

        let audit_trail = AuditTrail::new(config).await.unwrap();

        // Log a test event
        let event = AuditEventBuilder::new(AuditEventType::UserLogin)
            .user_id("test_user".to_string())
            .source_ip("127.0.0.1".to_string())
            .description("Test login event".to_string())
            .result(AuditResult::Success)
            .build();

        audit_trail.log_event(event).await.unwrap();

        // Wait for flush
        tokio::time::sleep(Duration::from_secs(2)).await;

        let stats = audit_trail.get_stats().await;
        assert_eq!(stats.total_events, 1);
    }

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEventBuilder::new(AuditEventType::UserLogin)
            .severity(AuditSeverity::Warning)
            .user_id("test_user".to_string())
            .description("Test event".to_string())
            .metadata("key".to_string(), "value".to_string())
            .build();

        assert_eq!(event.user_id, Some("test_user".to_string()));
        assert_eq!(event.description, "Test event");
        assert_eq!(event.metadata.get("key"), Some(&"value".to_string()));
    }
}
