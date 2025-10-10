//! Session Manager for ZHTP Server
//! 
//! Manages authenticated user sessions with secure tokens

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use lib_identity::{SessionToken, IdentityId};
use tokio::sync::RwLock;
use std::sync::Arc;

/// Session manager for the ZHTP server
#[derive(Debug)]
pub struct SessionManager {
    /// Active sessions by token
    sessions: Arc<RwLock<HashMap<String, SessionToken>>>,
    /// Sessions by identity ID for cleanup
    sessions_by_identity: Arc<RwLock<HashMap<IdentityId, Vec<String>>>>,
    /// Default session duration
    default_session_duration: u64,
    /// Maximum concurrent sessions per identity
    max_sessions_per_identity: usize,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            sessions_by_identity: Arc::new(RwLock::new(HashMap::new())),
            default_session_duration: 24 * 60 * 60, // 24 hours
            max_sessions_per_identity: 5,
        }
    }

    /// Create a new session for an authenticated identity
    pub async fn create_session(&self, identity_id: IdentityId) -> Result<String> {
        // Clean up expired sessions first
        self.cleanup_expired_sessions().await;
        
        // Check session limits
        let sessions_by_identity = self.sessions_by_identity.read().await;
        if let Some(existing_sessions) = sessions_by_identity.get(&identity_id) {
            if existing_sessions.len() >= self.max_sessions_per_identity {
                drop(sessions_by_identity);
                // Remove oldest session
                self.remove_oldest_session(&identity_id).await?;
            } else {
                drop(sessions_by_identity);
            }
        } else {
            drop(sessions_by_identity);
        }
        
        // Create new session token
        let session_token = SessionToken::new(identity_id.clone(), self.default_session_duration)?;
        let token_string = session_token.token.clone();
        
        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(token_string.clone(), session_token);
        drop(sessions);
        
        // Update sessions by identity
        let mut sessions_by_identity = self.sessions_by_identity.write().await;
        sessions_by_identity
            .entry(identity_id.clone())
            .or_insert_with(Vec::new)
            .push(token_string.clone());
        drop(sessions_by_identity);
        
        tracing::info!(
            "🎫 New session created for identity {}: {}",
            hex::encode(&identity_id.0[..8]),
            &token_string[..16]
        );
        
        Ok(token_string)
    }

    /// Validate and get session token
    pub async fn validate_session(&self, token: &str) -> Result<SessionToken> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(token) {
            if session.is_valid() {
                session.touch(); // Update last used timestamp
                Ok(session.clone())
            } else {
                // Session expired, remove it
                let identity_id = session.identity_id.clone();
                sessions.remove(token);
                drop(sessions);
                
                // Remove from sessions by identity
                let mut sessions_by_identity = self.sessions_by_identity.write().await;
                if let Some(identity_sessions) = sessions_by_identity.get_mut(&identity_id) {
                    identity_sessions.retain(|t| t != token);
                    if identity_sessions.is_empty() {
                        sessions_by_identity.remove(&identity_id);
                    }
                }
                
                Err(anyhow!("Session expired"))
            }
        } else {
            Err(anyhow!("Invalid session token"))
        }
    }

    /// Remove a session (signout)
    pub async fn remove_session(&self, token: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.remove(token) {
            let identity_id = session.identity_id;
            drop(sessions);
            
            // Remove from sessions by identity
            let mut sessions_by_identity = self.sessions_by_identity.write().await;
            if let Some(identity_sessions) = sessions_by_identity.get_mut(&identity_id) {
                identity_sessions.retain(|t| t != token);
                if identity_sessions.is_empty() {
                    sessions_by_identity.remove(&identity_id);
                }
            }
            
            tracing::info!(
                "🚪 Session removed for identity {}: {}",
                hex::encode(&identity_id.0[..8]),
                &token[..16]
            );
            
            Ok(())
        } else {
            Err(anyhow!("Session not found"))
        }
    }

    /// Remove all sessions for an identity
    pub async fn remove_all_sessions(&self, identity_id: &IdentityId) -> Result<usize> {
        let mut sessions_by_identity = self.sessions_by_identity.write().await;
        
        if let Some(identity_sessions) = sessions_by_identity.remove(identity_id) {
            let session_count = identity_sessions.len();
            drop(sessions_by_identity);
            
            // Remove all sessions for this identity
            let mut sessions = self.sessions.write().await;
            for token in identity_sessions {
                sessions.remove(&token);
            }
            
            tracing::info!(
                "🚪 All {} sessions removed for identity {}",
                session_count,
                hex::encode(&identity_id.0[..8])
            );
            
            Ok(session_count)
        } else {
            Ok(0)
        }
    }

    /// Get active session count for an identity
    pub async fn get_session_count(&self, identity_id: &IdentityId) -> usize {
        let sessions_by_identity = self.sessions_by_identity.read().await;
        sessions_by_identity
            .get(identity_id)
            .map(|sessions| sessions.len())
            .unwrap_or(0)
    }

    /// Get all active sessions for an identity
    pub async fn get_identity_sessions(&self, identity_id: &IdentityId) -> Vec<SessionToken> {
        let sessions_by_identity = self.sessions_by_identity.read().await;
        let sessions = self.sessions.read().await;
        
        if let Some(identity_sessions) = sessions_by_identity.get(identity_id) {
            identity_sessions
                .iter()
                .filter_map(|token| sessions.get(token).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let mut sessions_by_identity = self.sessions_by_identity.write().await;
        
        let mut expired_tokens = Vec::new();
        let mut identity_cleanup = HashMap::new();
        
        // Find expired sessions
        for (token, session) in sessions.iter() {
            if !session.is_valid() {
                expired_tokens.push(token.clone());
                identity_cleanup
                    .entry(session.identity_id.clone())
                    .or_insert_with(Vec::new)
                    .push(token.clone());
            }
        }
        
        // Remove expired sessions
        let mut removed_count = 0;
        for token in expired_tokens {
            sessions.remove(&token);
            removed_count += 1;
        }
        
        // Clean up sessions by identity mapping
        for (identity_id, expired_tokens) in identity_cleanup {
            if let Some(identity_sessions) = sessions_by_identity.get_mut(&identity_id) {
                for token in expired_tokens {
                    identity_sessions.retain(|t| t != &token);
                }
                if identity_sessions.is_empty() {
                    sessions_by_identity.remove(&identity_id);
                }
            }
        }
        
        if removed_count > 0 {
            tracing::info!(" Cleaned up {} expired sessions", removed_count);
        }
    }

    /// Get total active session count
    pub async fn get_total_session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Remove oldest session for an identity to enforce limits
    async fn remove_oldest_session(&self, identity_id: &IdentityId) -> Result<()> {
        let sessions_by_identity = self.sessions_by_identity.read().await;
        let sessions = self.sessions.read().await;
        
        if let Some(identity_sessions) = sessions_by_identity.get(identity_id) {
            // Find oldest session
            let mut oldest_token = None;
            let mut oldest_created = u64::MAX;
            
            for token in identity_sessions {
                if let Some(session) = sessions.get(token) {
                    if session.created_at < oldest_created {
                        oldest_created = session.created_at;
                        oldest_token = Some(token.clone());
                    }
                }
            }
            
            drop(sessions);
            drop(sessions_by_identity);
            
            if let Some(token) = oldest_token {
                self.remove_session(&token).await?;
            }
        }
        
        Ok(())
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(&self) {
        let session_manager = SessionManager {
            sessions: Arc::clone(&self.sessions),
            sessions_by_identity: Arc::clone(&self.sessions_by_identity),
            default_session_duration: self.default_session_duration,
            max_sessions_per_identity: self.max_sessions_per_identity,
        };
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
            
            loop {
                interval.tick().await;
                session_manager.cleanup_expired_sessions().await;
            }
        });
        
        tracing::info!(" Session cleanup task started (runs every 5 minutes)");
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}