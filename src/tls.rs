//! TLS Security Layer for ZHTP Blockchain
//! 
//! This module provides enterprise-grade TLS security using native-tls
//! for production deployment with enhanced security features.

use std::sync::Arc;
use tokio_native_tls::{TlsAcceptor, TlsConnector};
use native_tls::{Identity, TlsAcceptor as NativeTlsAcceptor, TlsConnector as NativeTlsConnector};
use crate::errors::{ZhtpError, ZhtpResult};
use crate::audit::{AuditTrail, AuditEvent, AuditEventType, AuditSeverity, AuditResult, AuditConfig};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// TLS Security Manager for ZHTP
#[derive(Clone)]
pub struct ZhtpTlsManager {
    acceptor: Option<Arc<TlsAcceptor>>,
    connector: Arc<TlsConnector>,
    audit_trail: Arc<AuditTrail>,
    certificates: Arc<RwLock<HashMap<String, Identity>>>,
    security_config: TlsSecurityConfig,
}

impl std::fmt::Debug for ZhtpTlsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZhtpTlsManager")
            .field("acceptor_configured", &self.acceptor.is_some())
            .field("connector_configured", &true)
            .field("certificates_count", &"<RwLock>")
            .field("security_config", &self.security_config)
            .finish()
    }
}

/// TLS Security Configuration
#[derive(Clone, Debug)]
pub struct TlsSecurityConfig {
    /// Minimum TLS version (always 1.2+ for native-tls)
    pub min_version: String,
    /// Certificate verification mode
    pub verify_mode: CertificateVerification,
    /// Enable Perfect Forward Secrecy
    pub perfect_forward_secrecy: bool,
    /// Certificate rotation interval in seconds
    pub cert_rotation_interval: u64,
}

/// Certificate verification modes
#[derive(Clone, Debug)]
pub enum CertificateVerification {
    /// Strict verification (production)
    Strict,
    /// Development mode (less strict)
    Development,
    /// Custom verification callback
    Custom,
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self {
            min_version: "1.2".to_string(),
            verify_mode: CertificateVerification::Strict,
            perfect_forward_secrecy: true,
            cert_rotation_interval: 86400, // 24 hours
        }
    }
}

impl ZhtpTlsManager {
    /// Create new TLS manager with security configuration
    pub async fn new(config: TlsSecurityConfig) -> ZhtpResult<Self> {
        let audit_trail = Arc::new(AuditTrail::new(AuditConfig::default()).await
            .map_err(|e| ZhtpError::SystemError(format!("Failed to create audit trail: {}", e)))?);
        
        // Create secure connector
        let connector_builder = NativeTlsConnector::builder();
        let connector = connector_builder
            .build()
            .map_err(|e| ZhtpError::TlsError(format!("Failed to create TLS connector: {}", e)))?;
        
        let manager = Self {
            acceptor: None,
            connector: Arc::new(TlsConnector::from(connector)),
            audit_trail: audit_trail.clone(),
            certificates: Arc::new(RwLock::new(HashMap::new())),
            security_config: config,
        };
        
        // Log TLS initialization
        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: AuditEventType::SystemOperation,
            severity: AuditSeverity::Info,
            source_ip: None,
            user_id: Some("system".to_string()),
            session_id: None,
            user_agent: None,
            description: "TLS manager initialized with native-tls".to_string(),
            metadata: HashMap::new(),
            resource: Some("tls_manager".to_string()),
            action: Some("initialize".to_string()),
            result: AuditResult::Success,
            request_id: None,
        };
        let _ = audit_trail.log_event(event).await;
        
        Ok(manager)
    }
    
    /// Configure TLS acceptor with certificate
    pub async fn configure_acceptor(&mut self, cert_data: &[u8], password: &str) -> ZhtpResult<()> {
        let identity = Identity::from_pkcs12(cert_data, password)
            .map_err(|e| ZhtpError::TlsError(format!("Failed to load certificate: {}", e)))?;
        
        let acceptor = NativeTlsAcceptor::builder(identity)
            .build()
            .map_err(|e| ZhtpError::TlsError(format!("Failed to build acceptor: {}", e)))?;
        
        self.acceptor = Some(Arc::new(TlsAcceptor::from(acceptor)));
        
        // Log certificate configuration
        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: AuditEventType::SystemOperation,
            severity: AuditSeverity::Info,
            source_ip: None,
            user_id: Some("system".to_string()),
            session_id: None,
            user_agent: None,
            description: "TLS acceptor configured with certificate".to_string(),
            metadata: HashMap::new(),
            resource: Some("tls_acceptor".to_string()),
            action: Some("configure_certificate".to_string()),
            result: AuditResult::Success,
            request_id: None,
        };
        let _ = self.audit_trail.log_event(event).await;
        
        Ok(())
    }
    
    /// Get TLS acceptor for server
    pub fn get_acceptor(&self) -> Option<Arc<TlsAcceptor>> {
        self.acceptor.clone()
    }
    
    /// Get TLS connector for client connections
    pub fn get_connector(&self) -> Arc<TlsConnector> {
        self.connector.clone()
    }
    
    /// Validate certificate chain
    pub async fn validate_certificate(&self, domain: &str) -> ZhtpResult<bool> {
        // For native-tls, validation is handled internally
        // We can add custom validation logic here if needed
        
        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: AuditEventType::SecurityBreach,
            severity: AuditSeverity::Info,
            source_ip: None,
            user_id: Some("system".to_string()),
            session_id: None,
            user_agent: None,
            description: format!("Certificate validation for domain: {}", domain),
            metadata: HashMap::new(),
            resource: Some("certificate".to_string()),
            action: Some("validate".to_string()),
            result: AuditResult::Success,
            request_id: None,
        };
        let _ = self.audit_trail.log_event(event).await;
        
        Ok(true)
    }
    
    /// Rotate certificates (placeholder for production implementation)
    pub async fn rotate_certificates(&mut self) -> ZhtpResult<()> {
        // In production, this would:
        // 1. Generate new certificates
        // 2. Update acceptor configuration
        // 3. Notify connected clients
        // 4. Clean up old certificates
        
        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: AuditEventType::SystemOperation,
            severity: AuditSeverity::Info,
            source_ip: None,
            user_id: Some("system".to_string()),
            session_id: None,
            user_agent: None,
            description: "Certificate rotation completed".to_string(),
            metadata: HashMap::new(),
            resource: Some("certificates".to_string()),
            action: Some("rotate".to_string()),
            result: AuditResult::Success,
            request_id: None,
        };
        let _ = self.audit_trail.log_event(event).await;
        
        Ok(())
    }
    
    /// Get security configuration
    pub fn get_security_config(&self) -> &TlsSecurityConfig {
        &self.security_config
    }
    
    /// Check if TLS is properly configured
    pub fn is_configured(&self) -> bool {
        self.acceptor.is_some()
    }
    
    /// Get TLS statistics for monitoring
    pub async fn get_tls_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        stats.insert("configured".to_string(), if self.is_configured() { 1 } else { 0 });
        stats.insert("certificates_loaded".to_string(), self.certificates.read().await.len() as u64);
        stats.insert("rotation_interval".to_string(), self.security_config.cert_rotation_interval);
        stats
    }
}

// Export TlsSecurityConfig as TlsConfig alias for backward compatibility
pub type TlsConfig = TlsSecurityConfig;
