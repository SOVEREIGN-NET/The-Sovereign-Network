//! Web4 service access grants from the original identity.rs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::{IdentityId, AccessLevel};

/// Web4 service access grants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4Access {
    /// Citizen's identity ID
    pub identity_id: IdentityId,
    /// Service access tokens for each Web4 service
    pub service_tokens: HashMap<String, String>,
    /// Global access proof
    pub access_proof: [u8; 32],
    /// Access granted timestamp
    pub granted_at: u64,
    /// Access level
    pub access_level: AccessLevel,
    /// Any access restrictions (none for full citizens)
    pub restrictions: Vec<String>,
}

impl Web4Access {
    /// Create new Web4 access
    pub fn new(
        identity_id: IdentityId,
        service_tokens: HashMap<String, String>,
        access_proof: [u8; 32],
        granted_at: u64,
        access_level: AccessLevel,
        restrictions: Vec<String>,
    ) -> Self {
        Self {
            identity_id,
            service_tokens,
            access_proof,
            granted_at,
            access_level,
            restrictions,
        }
    }
    
    /// Grant access to all Web4 services - IMPLEMENTATION FROM ORIGINAL
    pub async fn grant_web4_access(identity_id: &IdentityId) -> Result<Self> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Generate service access tokens
        let mut service_tokens = HashMap::new();
        
        // Core Web4 services
        let services = vec![
            "zhtp.browse",      // Web4 browsing
            "zhtp.publish",     // Content publishing
            "zhtp.storage",     // Decentralized storage
            "zhtp.messaging",   // Private messaging
            "zhtp.identity",    // Identity services
            "zhtp.wallet",      // Wallet services
            "zhtp.voting",      // DAO voting
            "zhtp.marketplace", // Decentralized marketplace
            "zhtp.compute",     // Distributed computing
            "zhtp.ai",          // AI services
        ];

        for service in services {
            let token = lib_crypto::hash_blake3(
                &[identity_id.0.as_slice(), service.as_bytes(), &current_time.to_le_bytes()].concat()
            );
            service_tokens.insert(service.to_string(), hex::encode(token));
        }

        // Generate global access proof
        let access_proof = lib_crypto::hash_blake3(
            &[
                identity_id.0.as_slice(),
                "web4_full_access".as_bytes(),
                &current_time.to_le_bytes(),
            ].concat()
        );

        tracing::info!(
            "WEB4 ACCESS GRANTED: Citizen {} has full access to {} services",
            hex::encode(&identity_id.0[..8]),
            service_tokens.len()
        );

        Ok(Self::new(
            identity_id.clone(),
            service_tokens,
            access_proof,
            current_time,
            AccessLevel::FullCitizen,
            vec![], // No restrictions for citizens
        ))
    }

    
    /// Check if has access to specific service
    pub fn has_service_access(&self, service: &str) -> bool {
        self.service_tokens.contains_key(service) && 
        self.access_level == AccessLevel::FullCitizen
    }
    
    /// Get service token for specific service
    pub fn get_service_token(&self, service: &str) -> Option<&String> {
        self.service_tokens.get(service)
    }
    
    /// Get all available services
    pub fn get_available_services(&self) -> Vec<&String> {
        self.service_tokens.keys().collect()
    }
    
    /// Check if access is unrestricted
    pub fn is_unrestricted(&self) -> bool {
        self.restrictions.is_empty() && self.access_level == AccessLevel::FullCitizen
    }
    
    /// Get access summary
    pub fn get_access_summary(&self) -> Web4AccessSummary {
        Web4AccessSummary {
            identity_id: self.identity_id.clone(),
            service_count: self.service_tokens.len(),
            access_level: self.access_level.clone(),
            is_unrestricted: self.is_unrestricted(),
            granted_at: self.granted_at,
            restrictions_count: self.restrictions.len(),
        }
    }
    
    /// Add new service access
    pub fn add_service_access(&mut self, service: String, token: String) {
        self.service_tokens.insert(service, token);
    }
    
    /// Remove service access
    pub fn remove_service_access(&mut self, service: &str) {
        self.service_tokens.remove(service);
    }
    
    /// Update access level
    pub fn update_access_level(&mut self, new_level: AccessLevel) {
        self.access_level = new_level;
    }
    
    /// Add restriction
    pub fn add_restriction(&mut self, restriction: String) {
        if !self.restrictions.contains(&restriction) {
            self.restrictions.push(restriction);
        }
    }
    
    /// Remove restriction
    pub fn remove_restriction(&mut self, restriction: &str) {
        self.restrictions.retain(|r| r != restriction);
    }
}

/// Web4 access summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4AccessSummary {
    pub identity_id: IdentityId,
    pub service_count: usize,
    pub access_level: AccessLevel,
    pub is_unrestricted: bool,
    pub granted_at: u64,
    pub restrictions_count: usize,
}
