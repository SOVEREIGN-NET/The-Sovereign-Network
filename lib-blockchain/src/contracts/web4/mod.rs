//! # Web4 Website Smart Contracts
//!
//! Smart contracts for decentralized website hosting, domain management, and content 
//! distribution through the ZHTP blockchain and DHT network.
//!
//! ## Features
//! - Domain registration and ownership management
//! - Content hash mapping for decentralized storage
//! - Website metadata and routing configuration
//! - Content versioning and updates
//! - Access control and permissions

pub mod core;
pub mod functions;
pub mod types;

pub use core::{Web4Contract, ContentStatistics};
pub use functions::{
    calculate_total_size, create_default_metadata, create_route, create_website_contract,
    deploy_website, format_file_size, generate_contract_id, get_website_stats, 
    is_valid_route_path, validate_deployment_data
};
pub use types::{
    WebsiteMetadata, ContentRoute, DomainRecord, WebsiteDeploymentData, DomainStatus, 
    Web4Operation, Web4Query, Web4Response, Web4Error,
    DirectoryNode, NodeType, FileMetadata, WebsiteManifest, DeploymentPackage, DependencyRef,
    ExecutableRef, WasmDeployment, WasmPermission, WasmMetadata
};


/// Re-export core Web4 contract functionality
pub use core::Web4Contract as WebsiteContract;

/// Web4 contract gas costs
pub const GAS_DOMAIN_REGISTER: u64 = 5000; // Domain registration
pub const GAS_CONTENT_UPDATE: u64 = 3000;  // Content update
pub const GAS_ROUTE_ADD: u64 = 2000;       // Add new route
pub const GAS_METADATA_UPDATE: u64 = 1500; // Update metadata
pub const GAS_OWNERSHIP_TRANSFER: u64 = 4000; // Transfer ownership

/// Web4 contract version
pub const WEB4_CONTRACT_VERSION: &str = "1.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_web4_gas_costs() {
        assert_eq!(GAS_DOMAIN_REGISTER, 5000);
        assert_eq!(GAS_CONTENT_UPDATE, 3000);
        assert_eq!(GAS_ROUTE_ADD, 2000);
        assert_eq!(GAS_METADATA_UPDATE, 1500);
        assert_eq!(GAS_OWNERSHIP_TRANSFER, 4000);
    }

    #[test]
    fn test_web4_version() {
        assert_eq!(WEB4_CONTRACT_VERSION, "1.0.0");
    }
}