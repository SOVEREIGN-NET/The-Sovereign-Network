//! ZHTP Identity Integration
//! 
//! Bridge module for integrating lib-identity package with ZHTP protocols.
//! Provides protocol-level identity management, authentication, and zero-knowledge
//! identity proofs for Web4 applications.

use crate::types::ZhtpRequest;
use crate::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Use actual lib-identity types
use lib_identity::{
    IdentityManager, AccessLevel, IdentityVerification, IdentityProofParams,
    ZkCredential, CredentialType, IdentityAttestation, AttestationType,
    IdentityId, CitizenshipResult
};
use lib_proofs::ZkProof;

// Enhanced identity types for protocol integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolIdentityProof {
    pub zk_proof: ZkProof,
    pub credential: ZkCredential,
    pub attestation: Option<IdentityAttestation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAttribute {
    pub name: String,
    pub value: String,
    pub verified: bool,
    pub attestation_type: Option<AttestationType>,
}

#[derive(Debug, thiserror::Error)]
pub enum CoreIdentityError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("Insufficient access level: required {required}, have {current}")]
    InsufficientAccess { required: AccessLevel, current: AccessLevel },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerificationResult {
    pub identity_id: IdentityId,
    pub is_valid: bool,
    pub access_level: AccessLevel,
    pub attributes: Vec<IdentityAttribute>,
    pub credential_score: u32,
    pub risk_level: String,
    pub citizenship_status: Option<CitizenshipResult>,
}

/// Protocol-level identity service for ZHTP
pub struct ProtocolIdentityService {
    /// Core identity manager
    identity_manager: IdentityManager,
    /// Active identity sessions
    sessions: std::sync::RwLock<HashMap<String, IdentitySession>>,
    /// Service configuration
    config: IdentityServiceConfig,
}

/// Identity service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityServiceConfig {
    /// Enable identity caching
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
    /// Require zero-knowledge proofs for authentication
    pub require_zk_proofs: bool,
    /// Enable identity verification
    pub enable_verification: bool,
    /// Maximum session duration (seconds)
    pub max_session_duration: u64,
    /// Enable multi-factor authentication
    pub enable_mfa: bool,
    /// Identity reputation tracking
    pub enable_reputation: bool,
}

/// Identity session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySession {
    /// Session ID
    pub session_id: String,
    /// Associated identity
    pub identity_id: IdentityId,
    /// Session creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Session expiry time
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Session permissions and access level
    pub access_level: AccessLevel,
    /// Zero-knowledge proof of session
    pub session_proof: Option<ProtocolIdentityProof>,
    /// Session metadata
    pub metadata: SessionMetadata,
}

/// Session metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Client IP address
    pub client_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Geographic location
    pub geo_location: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Session activity log
    pub activity_log: Vec<SessionActivity>,
}

/// Session activity entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionActivity {
    /// Activity timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Activity type
    pub activity_type: String,
    /// Activity details
    pub details: String,
    /// Resource accessed
    pub resource: Option<String>,
}

/// Identity authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAuthRequest {
    /// Identity credential
    pub credential: ZkCredential,
    /// Zero-knowledge proof (optional)
    pub zk_proof: Option<ProtocolIdentityProof>,
    /// Requested access level
    pub requested_access_level: AccessLevel,
    /// Session duration (seconds)
    pub session_duration: Option<u64>,
    /// Client metadata
    pub client_metadata: Option<ClientMetadata>,
}

/// Client metadata for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Client IP address
    pub ip_address: String,
    /// User agent string
    pub user_agent: String,
    /// Client public key
    pub public_key: Option<String>,
    /// Device information
    pub device_info: Option<String>,
}

/// Identity authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAuthResponse {
    /// Authentication success
    pub success: bool,
    /// Session token (if successful)
    pub session_token: Option<String>,
    /// Session information
    pub session: Option<IdentitySession>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Authentication metadata
    pub metadata: AuthMetadata,
}

/// Authentication metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMetadata {
    /// Authentication timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Authentication method used
    pub auth_method: String,
    /// Zero-knowledge proof verified
    pub zk_verified: bool,
    /// Multi-factor authentication used
    pub mfa_used: bool,
    /// Identity reputation score
    pub reputation_score: Option<f64>,
}

impl ProtocolIdentityService {
    /// Create new protocol identity service
    pub fn new(identity_manager: IdentityManager, config: IdentityServiceConfig) -> Self {
        Self {
            identity_manager,
            sessions: std::sync::RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Authenticate identity from ZHTP request
    pub async fn authenticate_request(&mut self, request: &ZhtpRequest) -> Result<Option<IdentitySession>> {
        // Extract authentication headers
        let auth_header = request.headers.get("Authorization");
        let session_token = request.headers.get("X-Session-Token");
        let zk_proof_header = request.headers.get("X-ZK-Identity-Proof");

        // Try session token first
        if let Some(token) = session_token {
            if let Some(session) = self.get_session(&token).await? {
                if !self.is_session_expired(&session) {
                    return Ok(Some(session));
                } else {
                    self.invalidate_session(&token).await?;
                }
            }
        }

        // Try authorization header
        if let Some(auth) = auth_header {
            return self.authenticate_with_header(&auth, zk_proof_header.as_ref(), request).await;
        }

        Ok(None)
    }

    /// Create new identity session
    pub async fn create_session(&mut self, auth_request: IdentityAuthRequest) -> Result<IdentityAuthResponse> {
        // Use actual identity verification from lib-identity
        let verification_params = IdentityProofParams {
            min_age: None,
            jurisdiction: None,
            required_credentials: vec![],
            privacy_level: 50,
            min_reputation: Some(50),
            proof_type: "protocol_auth".to_string(),
            require_citizenship: matches!(auth_request.requested_access_level, AccessLevel::FullCitizen),
            required_location: None,
        };

        let identity_verification = self.identity_manager
            .verify_identity(&auth_request.credential.subject, &verification_params)
            .await
            .map_err(|e| ProtocolError::IdentityError(format!("Identity verification failed: {}", e)))?;

        if !identity_verification.verified {
            return Ok(IdentityAuthResponse {
                success: false,
                session_token: None,
                session: None,
                error: Some(format!("Identity verification failed: {}", 
                    if identity_verification.requirements_failed.is_empty() { 
                        "Unknown verification error".to_string() 
                    } else { 
                        format!("Failed requirements: {:?}", identity_verification.requirements_failed) 
                    })),
                metadata: AuthMetadata {
                    timestamp: chrono::Utc::now(),
                    auth_method: "credential".to_string(),
                    zk_verified: false,
                    mfa_used: false,
                    reputation_score: None,
                },
            });
        }

        // Verify zero-knowledge proof if provided and required
        let mut zk_verified = false;
        if let Some(zk_proof) = &auth_request.zk_proof {
            if self.config.require_zk_proofs {
                // Basic ZK proof validation (check non-empty structure)
                let zk_result = !zk_proof.zk_proof.is_empty();
                
                if !zk_result {
                    return Ok(IdentityAuthResponse {
                        success: false,
                        session_token: None,
                        session: None,
                        error: Some("Invalid zero-knowledge proof".to_string()),
                        metadata: AuthMetadata {
                            timestamp: chrono::Utc::now(),
                            auth_method: "zk_proof".to_string(),
                            zk_verified: false,
                            mfa_used: false,
                            reputation_score: Some(identity_verification.privacy_score as f64),
                        },
                    });
                }
                zk_verified = true;
            }
        } else if self.config.require_zk_proofs {
            return Ok(IdentityAuthResponse {
                success: false,
                session_token: None,
                session: None,
                error: Some("Zero-knowledge proof required".to_string()),
                metadata: AuthMetadata {
                    timestamp: chrono::Utc::now(),
                    auth_method: "missing_zk".to_string(),
                    zk_verified: false,
                    mfa_used: false,
                    reputation_score: Some(identity_verification.privacy_score as f64),
                },
            });
        }

        // Determine user's access level based on verification results
        let user_access_level = self.determine_access_level(&identity_verification);
        
        // Check access level authorization
        if !self.check_access_permission(user_access_level.clone(), auth_request.requested_access_level.clone()) {
            return Ok(IdentityAuthResponse {
                success: false,
                session_token: None,
                session: None,
                error: Some(format!(
                    "Insufficient access level: required {:?}, have {:?}",
                    auth_request.requested_access_level,
                    user_access_level
                )),
                metadata: AuthMetadata {
                    timestamp: chrono::Utc::now(),
                    auth_method: "access_denied".to_string(),
                    zk_verified,
                    mfa_used: false,
                    reputation_score: Some(identity_verification.privacy_score as f64),
                },
            });
        }

        // Create session
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_duration = auth_request.session_duration
            .unwrap_or(self.config.max_session_duration)
            .min(self.config.max_session_duration);

        let session = IdentitySession {
            session_id: session_id.clone(),
            identity_id: identity_verification.identity_id,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(session_duration as i64),
            access_level: user_access_level.clone(),
            session_proof: auth_request.zk_proof.clone(),
            metadata: SessionMetadata {
                client_ip: auth_request.client_metadata.as_ref().map(|m| m.ip_address.clone()),
                user_agent: auth_request.client_metadata.as_ref().map(|m| m.user_agent.clone()),
                geo_location: None, // TODO: Implement geo lookup
                device_fingerprint: auth_request.client_metadata.as_ref().and_then(|m| m.device_info.clone()),
                activity_log: vec![SessionActivity {
                    timestamp: chrono::Utc::now(),
                    activity_type: "session_created".to_string(),
                    details: format!("Identity session created with access level {:?}", user_access_level.clone()),
                    resource: None,
                }],
            },
        };

        // Store session
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.clone(), session.clone());
        drop(sessions);

        Ok(IdentityAuthResponse {
            success: true,
            session_token: Some(session_id),
            session: Some(session),
            error: None,
            metadata: AuthMetadata {
                timestamp: chrono::Utc::now(),
                auth_method: if zk_verified { "credential+zk" } else { "credential" }.to_string(),
                zk_verified,
                mfa_used: false, // TODO: Implement MFA
                reputation_score: Some(identity_verification.privacy_score as f64),
            },
        })
    }

    /// Get identity session by token
    pub async fn get_session(&self, session_token: &str) -> Result<Option<IdentitySession>> {
        let sessions = self.sessions.read().unwrap();
        Ok(sessions.get(session_token).cloned())
    }

    /// Invalidate identity session
    pub async fn invalidate_session(&self, session_token: &str) -> Result<bool> {
        let mut sessions = self.sessions.write().unwrap();
        Ok(sessions.remove(session_token).is_some())
    }

    /// Check if session is expired
    pub fn is_session_expired(&self, session: &IdentitySession) -> bool {
        chrono::Utc::now() > session.expires_at
    }

    /// Log session activity
    pub async fn log_session_activity(
        &self,
        session_token: &str,
        activity_type: String,
        details: String,
        resource: Option<String>,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(session) = sessions.get_mut(session_token) {
            session.metadata.activity_log.push(SessionActivity {
                timestamp: chrono::Utc::now(),
                activity_type,
                details,
                resource,
            });
        }
        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let mut sessions = self.sessions.write().unwrap();
        let initial_count = sessions.len();
        let now = chrono::Utc::now();
        
        sessions.retain(|_, session| session.expires_at > now);
        
        Ok(initial_count - sessions.len())
    }

    /// Get session statistics
    pub async fn get_session_stats(&self) -> SessionStats {
        let sessions = self.sessions.read().unwrap();
        let now = chrono::Utc::now();
        
        let total_sessions = sessions.len();
        let active_sessions = sessions.values()
            .filter(|s| s.expires_at > now)
            .count();
        let expired_sessions = total_sessions - active_sessions;
        
        SessionStats {
            total_sessions,
            active_sessions,
            expired_sessions,
            average_session_duration: self.calculate_average_session_duration(&sessions),
        }
    }

    // Private helper methods

    async fn authenticate_with_header(
        &mut self,
        auth_header: &str,
        zk_proof_header: Option<&String>,
        request: &ZhtpRequest,
    ) -> Result<Option<IdentitySession>> {
        // Parse authorization header
        if let Some(credential) = self.parse_auth_header(auth_header)? {
            let zk_proof = if let Some(proof_str) = zk_proof_header {
                self.parse_zk_proof(proof_str)?
            } else {
                None
            };

            let client_metadata = self.extract_client_metadata(request);
            
            let auth_request = IdentityAuthRequest {
                credential,
                zk_proof,
                requested_access_level: AccessLevel::Visitor, // Default access level
                session_duration: None,
                client_metadata,
            };

            let auth_response = self.create_session(auth_request).await?;
            
            if auth_response.success {
                Ok(auth_response.session)
            } else {
                Err(ProtocolError::IdentityError(
                    auth_response.error.unwrap_or_else(|| "Authentication failed".to_string())
                ))
            }
        } else {
            Ok(None)
        }
    }

    fn parse_auth_header(&self, auth_header: &str) -> Result<Option<ZkCredential>> {
        // Parse different authentication header formats
        if auth_header.starts_with("Bearer ") {
            let token = auth_header.split_whitespace().nth(1)
                .ok_or_else(|| ProtocolError::IdentityError("Invalid Bearer token format".to_string()))?;
            
            // Create ZkCredential from bearer token
            Ok(Some(ZkCredential::from_bearer_token(token)?))
        } else if auth_header.starts_with("ZHTP ") {
            let credential_data = auth_header.split_whitespace().nth(1)
                .ok_or_else(|| ProtocolError::IdentityError("Invalid ZHTP auth format".to_string()))?;
            
            // Parse ZkCredential from ZHTP format
            match serde_json::from_str(credential_data) {
                Ok(credential) => Ok(Some(credential)),
                Err(e) => Err(ProtocolError::IdentityError(format!("Failed to parse ZHTP credential: {}", e))),
            }
        } else {
            Ok(None)
        }
    }

    fn parse_zk_proof(&self, proof_str: &str) -> Result<Option<ProtocolIdentityProof>> {
        // Parse ZK proof from header
        match serde_json::from_str(proof_str) {
            Ok(proof) => Ok(Some(proof)),
            Err(e) => {
                tracing::warn!("Failed to parse ZK proof: {}", e);
                Ok(None)
            }
        }
    }

    fn extract_client_metadata(&self, request: &ZhtpRequest) -> Option<ClientMetadata> {
        let ip_address = request.headers.get("X-Forwarded-For")
            .or_else(|| request.headers.get("X-Real-IP"))
            .unwrap_or_else(|| "unknown".to_string());
        
        let user_agent = request.headers.get("User-Agent")
            .unwrap_or_else(|| "unknown".to_string());

        Some(ClientMetadata {
            ip_address,
            user_agent,
            public_key: request.headers.get("X-Public-Key"),
            device_info: request.headers.get("X-Device-Info"),
        })
    }

    fn calculate_average_session_duration(&self, sessions: &HashMap<String, IdentitySession>) -> f64 {
        if sessions.is_empty() {
            return 0.0;
        }

        let total_duration: i64 = sessions.values()
            .map(|s| (s.expires_at - s.created_at).num_seconds())
            .sum();

        total_duration as f64 / sessions.len() as f64
    }

    /// Determine access level based on verification results
    fn determine_access_level(&self, verification: &IdentityVerification) -> AccessLevel {
        // Determine access level based on verification requirements met
        if verification.requirements_met.contains(&CredentialType::Custom("Citizenship".to_string())) {
            AccessLevel::FullCitizen
        } else if verification.requirements_met.contains(&CredentialType::Custom("Organization".to_string())) {
            AccessLevel::Organization
        } else if verification.requirements_met.contains(&CredentialType::Custom("Device".to_string())) {
            AccessLevel::Device
        } else if verification.privacy_score < 30 {
            AccessLevel::Restricted
        } else {
            AccessLevel::Visitor
        }
    }

    /// Check if user has permission for requested access level
    fn check_access_permission(&self, user_level: AccessLevel, requested_level: AccessLevel) -> bool {
        match (user_level, requested_level) {
            // FullCitizen can access everything
            (AccessLevel::FullCitizen, _) => true,
            // Organization can access organization and visitor
            (AccessLevel::Organization, AccessLevel::Organization | AccessLevel::Visitor) => true,
            // Device can access device and visitor (if not restricted)
            (AccessLevel::Device, AccessLevel::Device | AccessLevel::Visitor) => true,
            // Visitor can only access visitor level
            (AccessLevel::Visitor, AccessLevel::Visitor) => true,
            // Restricted cannot access anything higher
            (AccessLevel::Restricted, AccessLevel::Restricted) => true,
            // All other combinations are denied
            _ => false,
        }
    }
}

/// Session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    /// Total number of sessions
    pub total_sessions: usize,
    /// Number of active sessions
    pub active_sessions: usize,
    /// Number of expired sessions
    pub expired_sessions: usize,
    /// Average session duration in seconds
    pub average_session_duration: f64,
}

impl Default for IdentityServiceConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_ttl: 3600, // 1 hour
            require_zk_proofs: true,
            enable_verification: true,
            max_session_duration: 86400, // 24 hours
            enable_mfa: false,
            enable_reputation: true,
        }
    }
}

// Helper trait extensions for ZkCredential
trait ZkCredentialExt {
    fn from_bearer_token(token: &str) -> Result<Self>
    where
        Self: Sized;
}

impl ZkCredentialExt for ZkCredential {
    fn from_bearer_token(token: &str) -> Result<Self> {
        use lib_crypto::Hash;
        use lib_proofs::ZeroKnowledgeProof;
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Create a basic credential from bearer token
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Create dummy identity IDs for issuer and subject
        let issuer = Hash::from_bytes(&lib_crypto::hash_blake3(b"protocol_issuer"));
        let subject = Hash::from_bytes(&lib_crypto::hash_blake3(token.as_bytes()));
        
        // Create a basic ZK proof structure (this would be replaced with proof)
        let proof = ZeroKnowledgeProof::new(
            "Bearer".to_string(),
            token.as_bytes().to_vec(),
            subject.to_string().as_bytes().to_vec(),
            Vec::new(),
            None, // No Plonky2 proof for bearer tokens
        );
        
        Ok(ZkCredential::new(
            CredentialType::Custom("BearerToken".to_string()),
            issuer,
            subject,
            proof,
            Some(current_time + 3600),           // expires_at (1 hour expiration)
            token.as_bytes().to_vec(),           // metadata (token data)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_service_creation() {
        let identity_manager = IdentityManager::new();
        let config = IdentityServiceConfig::default();
        let service = ProtocolIdentityService::new(identity_manager, config);
        
        let stats = service.get_session_stats().await;
        assert_eq!(stats.total_sessions, 0);
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let identity_manager = IdentityManager::new();
        let config = IdentityServiceConfig::default();
        let service = ProtocolIdentityService::new(identity_manager, config);
        
        let cleaned = service.cleanup_expired_sessions().await.unwrap();
        assert_eq!(cleaned, 0);
    }
}
