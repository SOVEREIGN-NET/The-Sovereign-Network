//! # ZHTP Protocols - Web4 Protocol Stack
//! 
//! Complete implementations of ZHTP (Zero Knowledge Hypertext Transfer Protocol),
//! ZDNS (Zero Knowledge Domain Name System), and other Web4 protocols.
//! 
//! ##  ZHTP IS A NATIVE PROTOCOL - COMPLETE ISP REPLACEMENT 
//! 
//! ZHTP is a completely new internet stack designed specifically for Web4:
//! - Zero-knowledge proof validation at transport layer
//! - Post-quantum cryptographic security built-in
//! - Economic incentives embedded in protocol headers
//! - Mandatory DAO fees for Universal Basic Income funding
//! - Quantum-resistant mesh routing with  capability
//! - Native support for .zhtp domains and Web4 addressing
//! - Proof-of-Useful-Work consensus for free internet access
//! 
//! ## Security Architecture
//! 
//! ZHTP implements proper cryptographic security with client-side signing:
//! - Clients sign transactions with their private keys
//! - Servers verify signatures using registered public keys
//! - No private key material is ever transmitted
//! - Identity verification against blockchain registry
//! 
//! ## Protocol Stack
//! 
//! ZHTP replaces the entire traditional internet stack:
//! 1. **ISPs**: Mesh networking with economic incentives for routing
//! 2. **DNS**: Zero-knowledge domain system (ZDNS) 
//! 3. **HTTP/HTTPS**: Native ZHTP protocol with built-in privacy
//! 4. **TLS**: Post-quantum encryption by default
//! 5. **CDNs**: Distributed content with economic rewards
//! 6. **Governments**: DAO governance with UBI for all participants
//! 
//! The result: **A free internet that pays users to participate**
//! 
//! ## Core Features
//! 
//! ### ZHTP v1.0 Protocol
//! - HTTP replacement with built-in economics
//! - Zero-knowledge proof validation
//! - Post-quantum cryptography (CRYSTALS-Dilithium, CRYSTALS-Kyber)
//! - Mandatory 2% DAO fees for UBI funding
//! - Complete  capability
//! 
//! ### ZDNS v1.0 System
//! - DNS replacement with ownership proofs
//! - Zero-knowledge domain records
//! - Decentralized name resolution
//! - Post-quantum secure domain management
//! 
//! ### Web4 API System
//! - 50+ production endpoints
//! - Multi-wallet integration (MetaMask, Phantom, native ZHTP)
//! - Identity management with ZK-DID
//! - DAO governance integration
//! - Mesh network monitoring
//! - Economic incentive tracking
//! 
//! ## Usage
//! 
//! ```rust
//! use lib_protocols::{ZhtpServer, ServerConfig, ZhtpMethod, ZhtpRequest, ZhtpStatus};
//! use lib_economy::Priority;
//! use std::collections::HashMap;
//! 
//! // Create ZHTP server configuration
//! let config = ServerConfig::default();
//! let server = ZhtpServer::new(config);
//! 
//! // Create a ZHTP request manually
//! let mut headers = lib_protocols::ZhtpHeaders::new();
//! headers.set("Content-Type", "application/json".to_string());
//! 
//! let request = ZhtpRequest {
//!     method: ZhtpMethod::Get,
//!     uri: "/api/wallet/balance".to_string(),
//!     version: "1.0".to_string(),
//!     headers,
//!     body: vec![],
//!     timestamp: 1234567890,
//!     requester: None,
//!     auth_proof: None,
//! };
//! 
//! // Note: In async context, you would process the request
//! // let response = server.handle_request(request).await?;
//! ```

// Re-export all public types and modules
pub mod types;
pub mod zhtp;
pub mod handlers;
pub mod validation;
pub mod secure_transfer;
pub mod zdns;
pub mod identity;
pub mod crypto;
pub mod economics;
#[cfg(feature = "storage")]
pub mod storage;
#[cfg(not(feature = "storage"))]
pub mod storage_stub;
pub mod integration;
pub mod wire;

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(feature = "testing")]
// pub mod testing;

use crate::types::ZHTP_VERSION;

// Protocol constants
pub const ZDNS_VERSION: &str = "1.0";

// Re-export commonly used types
pub use types::{
    ZhtpStatus, ZhtpMethod, ZhtpHeaders, ZhtpRequest, ZhtpResponse,
    AccessPolicy, ContentMetadata, ServerContent,
    CachedContent, ContentSearchResult, StorageSearchQuery,
    StorageRequirements, StorageQuality,
};

pub use zhtp::{ZhtpServer, ServerConfig};
pub use zdns::{ZdnsServer, ZdnsConfig, ZdnsRecord, ZdnsRecordType, ZdnsQuery, ZdnsResponse, web4_integration};

// API modules moved to zhtp crate - no longer exported from lib-protocols

// Re-export handler functions
pub use handlers::{
    handle_get, handle_post, handle_put, handle_delete,
    handle_head, handle_options, handle_verify,
    ZhtpHandlers, HandlerConfig,
};

// Re-export validation functions  
pub use validation::{
    ZhtpValidator, ValidationConfig, ValidationResult, ValidationError,
    ValidationCategory, ValidationSeverity, RateLimitConfig, validate_access_policy,
};

// Re-export integration modules
pub use crypto::{ZhtpCrypto, CryptoConfig};
pub use economics::{ZhtpEconomics, EconomicConfig, EconomicAssessment, EconomicStats};
#[cfg(feature = "storage")]
pub use storage::{StorageIntegration, StorageConfig, StorageContract, StorageStats};
#[cfg(not(feature = "storage"))]
pub use storage_stub::{StorageIntegration, StorageConfig, StorageContract};
pub use identity::{ProtocolIdentityService, IdentityServiceConfig, IdentitySession, IdentityAuthRequest, IdentityAuthResponse};
pub use integration::{ZhtpIntegration, IntegrationConfig, IntegrationStats};
pub use wire::{ZhtpRequestWire, ZhtpResponseWire, read_request, write_request, read_response, write_response, WIRE_VERSION};
use crate::zhtp::ZHTP_VERSION;

// Re-export ZDNS functions
pub use zdns::{
    SecurityConfig, MeshNodeSelection,
};

// Error types
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid ZHTP request: {0}")]
    InvalidRequest(String),
    
    #[error("Access denied: {0}")]
    AccessDenied(String),
    
    #[error("DAO fee validation failed: {0}")]
    DaoFeeError(String),
    
    #[error("Zero-knowledge proof invalid: {0}")]
    ZkProofError(String),
    
    #[error("Content validation failed: {0}")]
    ContentError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Identity error: {0}")]
    IdentityError(String),
    
    #[error("Economic validation error: {0}")]
    EconomicError(String),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl From<anyhow::Error> for ProtocolError {
    fn from(error: anyhow::Error) -> Self {
        ProtocolError::InternalError(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

// Protocol result type
pub type ProtocolResult<T> = anyhow::Result<T>;

/// Initialize the ZHTP protocol system
pub async fn initialize() -> ProtocolResult<()> {
    tracing::info!(" Initializing ZHTP Protocol Stack v{}", ZHTP_VERSION);
    tracing::info!("Web4 Internet Infrastructure Ready");
    tracing::info!("DAO fee system active for UBI funding");
    tracing::info!("Post-quantum cryptography enabled");
    tracing::info!("Mesh networking ready for ");
    Ok(())
}

/// Get protocol version information
pub fn version_info() -> serde_json::Value {
    serde_json::json!({
        "lib_version": ZHTP_VERSION,
        "zdns_version": ZDNS_VERSION,
        "features": {
            "post_quantum": true,
            "zero_knowledge": true,
            "dao_fees": true,
            "ubi_funding": true,
            "mesh_networking": true,
            "isp_bypass": true,
            "multi_wallet": true,
            "zk_did": true
        },
        "api_endpoints": 50,
        "protocol_stack": "complete_isp_replacement"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initialization() {
        let result = initialize().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert_eq!(info["lib_version"], ZHTP_VERSION);
        assert_eq!(info["zdns_version"], ZDNS_VERSION);
        assert_eq!(info["features"]["post_quantum"], true);
        assert_eq!(info["api_endpoints"], 50);
    }
}
