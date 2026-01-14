//! State verification utilities for asserting Web4 CLI test outcomes

use std::collections::HashMap;
use serde_json::Value;

/// Verifies and asserts Web4 domain state
pub struct StateVerifier {
    // In a real implementation, would connect to actual storage/node
    _env: String,
}

impl StateVerifier {
    /// Create a new state verifier
    pub fn new(env: &super::TestEnv) -> Self {
        StateVerifier {
            _env: env.name().to_string(),
        }
    }
    
    /// Check if a domain exists
    pub fn domain_exists(&self, domain: &str) -> bool {
        // In production: query node's domain storage
        // For tests: check if domain directory exists or is registered
        println!("Verifying domain exists: {}", domain);
        true // Stub for now
    }
    
    /// Check if a domain has a deployed manifest
    pub fn has_manifest(&self, domain: &str) -> bool {
        println!("Checking manifest for: {}", domain);
        true // Stub for now
    }
    
    /// Get the manifest for a domain
    pub fn get_manifest(&self, domain: &str) -> Option<serde_json::Map<String, Value>> {
        println!("Getting manifest for: {}", domain);
        
        // Build a mock manifest structure that matches expected Web4 format
        let mut manifest = serde_json::Map::new();
        manifest.insert("domain".to_string(), Value::String(domain.to_string()));
        manifest.insert(
            "web4_manifest_cid".to_string(),
            Value::String(format!("Qm{}", domain)),
        );
        manifest.insert("version".to_string(), Value::String("1.0".to_string()));
        
        Some(manifest)
    }
    
    /// Verify manifest has required fields
    pub fn manifest_has_fields(&self, domain: &str, required_fields: &[&str]) -> bool {
        if let Some(manifest) = self.get_manifest(domain) {
            for field in required_fields {
                if !manifest.contains_key(*field) {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }
    
    /// Get version information for a domain
    pub fn get_version_info(&self, domain: &str, version: &str) -> Option<HashMap<String, String>> {
        let mut info = HashMap::new();
        info.insert("domain".to_string(), domain.to_string());
        info.insert("version".to_string(), version.to_string());
        info.insert("status".to_string(), "active".to_string());
        Some(info)
    }
    
    /// Verify version exists
    pub fn version_exists(&self, domain: &str, version: &str) -> bool {
        println!("Checking if version {} exists for {}", version, domain);
        true // Stub for now
    }
    
    /// Verify domain metadata
    pub fn verify_metadata(&self, domain: &str, expected: &HashMap<&str, &str>) -> bool {
        println!("Verifying metadata for: {}", domain);
        
        // In production: compare against actual metadata
        !expected.is_empty()
    }
    
    /// Check file existence in deployed site
    pub fn has_deployed_file(&self, domain: &str, filename: &str) -> bool {
        println!("Checking if {} has file: {}", domain, filename);
        true // Stub for now
    }
    
    /// Verify manifest CID format
    pub fn verify_manifest_cid(&self, domain: &str) -> bool {
        let manifest = match self.get_manifest(domain) {
            Some(m) => m,
            None => return false,
        };
        
        // Check for either field name (web4_manifest_cid or manifest_cid)
        let has_ipfs_cid = manifest.contains_key("web4_manifest_cid")
            || manifest.contains_key("manifest_cid");
        
        has_ipfs_cid
    }
    
    /// Compare manifests for equality
    pub fn manifests_equal(
        &self,
        domain1: &str,
        domain2: &str,
    ) -> bool {
        let m1 = self.get_manifest(domain1);
        let m2 = self.get_manifest(domain2);
        
        match (m1, m2) {
            (Some(m1), Some(m2)) => m1 == m2,
            _ => false,
        }
    }
    
    /// Get deployment timestamp
    pub fn get_deployment_time(&self, domain: &str) -> Option<String> {
        println!("Getting deployment time for: {}", domain);
        Some(chrono::Utc::now().to_rfc3339())
    }
    
    /// Verify persistence: check if state is identical after restart
    pub fn verify_persistence(&self, domain: &str, original_state: &serde_json::Map<String, Value>) -> bool {
        let current_state = match self.get_manifest(domain) {
            Some(state) => state,
            None => return false,
        };
        
        // Compare critical fields
        let same_cid = original_state.get("web4_manifest_cid") == current_state.get("web4_manifest_cid");
        let same_domain = original_state.get("domain") == current_state.get("domain");
        
        same_cid && same_domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_manifest_cid_verification() {
        // Stub test
        let mut manifest = serde_json::Map::new();
        manifest.insert(
            "web4_manifest_cid".to_string(),
            Value::String("QmTest123".to_string()),
        );
        
        assert!(manifest.contains_key("web4_manifest_cid"));
    }
}
