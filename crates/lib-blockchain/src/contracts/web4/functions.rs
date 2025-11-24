//! Web4 contract functions and utilities

use crate::contracts::web4::types::*;
use crate::contracts::web4::core::Web4Contract;

/// Create a new Web4 website contract with deployment data
pub fn create_website_contract(
    contract_id: String,
    deployment_data: WebsiteDeploymentData,
) -> Result<Web4Contract, Web4Error> {
    // Validate deployment data
    if deployment_data.domain.is_empty() {
        return Err(Web4Error::InvalidDomain("Domain cannot be empty".to_string()));
    }
    
    if deployment_data.owner.is_empty() {
        return Err(Web4Error::InvalidMetadata("Owner cannot be empty".to_string()));
    }
    
    if deployment_data.routes.is_empty() {
        return Err(Web4Error::InvalidMetadata("At least one route is required".to_string()));
    }
    
    // Validate domain format
    if !deployment_data.domain.ends_with(".zhtp") {
        return Err(Web4Error::InvalidDomain(format!(
            "Domain must end with .zhtp: {}", 
            deployment_data.domain
        )));
    }
    
    // Create the contract
    let contract = Web4Contract::new(
        contract_id,
        deployment_data.domain.clone(),
        deployment_data.owner.clone(),
        deployment_data.metadata.clone(),
        deployment_data,
    );
    
    Ok(contract)
}

/// Deploy a website to the Web4 network
pub fn deploy_website(
    domain: String,
    owner: String,
    routes: Vec<ContentRoute>,
    metadata: WebsiteMetadata,
) -> Result<Web4Contract, Web4Error> {
    let contract_id = generate_contract_id(&domain);
    
    let deployment_data = WebsiteDeploymentData {
        domain: domain.clone(),
        metadata,
        routes,
        owner: owner.clone(),
        config: std::collections::HashMap::new(),
    };
    
    create_website_contract(contract_id, deployment_data)
}

/// Generate a unique contract ID for a domain
pub fn generate_contract_id(domain: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    domain.hash(&mut hasher);
    chrono::Utc::now().timestamp_nanos().hash(&mut hasher);
    
    format!("web4_{}_{:x}", domain.replace('.', "_"), hasher.finish())
}

/// Validate website deployment data
pub fn validate_deployment_data(data: &WebsiteDeploymentData) -> Result<(), Web4Error> {
    // Validate domain
    if !data.domain.ends_with(".zhtp") {
        return Err(Web4Error::InvalidDomain(
            "Domain must end with .zhtp".to_string()
        ));
    }
    
    // Validate routes
    if data.routes.is_empty() {
        return Err(Web4Error::InvalidMetadata(
            "At least one route is required".to_string()
        ));
    }
    
    // Check for root route
    let has_root = data.routes.iter().any(|r| r.path == "/");
    if !has_root {
        return Err(Web4Error::InvalidMetadata(
            "Root route (/) is required".to_string()
        ));
    }
    
    // Validate content hashes
    for route in &data.routes {
        if route.content_hash.is_empty() {
            return Err(Web4Error::InvalidContentHash(
                "Content hash cannot be empty".to_string()
            ));
        }
        
        // Basic validation for DHT/ hashes
        let is_valid = route.content_hash.starts_with("Qm") ||
                       route.content_hash.starts_with("dht:") ||
                       route.content_hash.starts_with(":");
        
        if !is_valid {
            return Err(Web4Error::InvalidContentHash(
                format!("Invalid content hash format: {}", route.content_hash)
            ));
        }
    }
    
    // Validate metadata
    if data.metadata.title.is_empty() {
        return Err(Web4Error::InvalidMetadata(
            "Website title cannot be empty".to_string()
        ));
    }
    
    Ok(())
}

/// Create default website metadata
pub fn create_default_metadata(title: String, author: String) -> WebsiteMetadata {
    let current_time = chrono::Utc::now().timestamp() as u64;
    
    WebsiteMetadata {
        title,
        description: "A Web4 decentralized website".to_string(),
        author,
        version: "1.0.0".to_string(),
        tags: vec!["web4".to_string(), "zhtp".to_string()],
        language: "en".to_string(),
        created_at: current_time,
        updated_at: current_time,
        custom: std::collections::HashMap::new(),
    }
}

/// Create a basic website route
pub fn create_route(
    path: String,
    content_hash: String,
    content_type: String,
    size: u64,
) -> ContentRoute {
    ContentRoute {
        path,
        content_hash,
        content_type,
        size,
        metadata: std::collections::HashMap::new(),
        updated_at: chrono::Utc::now().timestamp() as u64,
    }
}

/// Calculate total website size from routes
pub fn calculate_total_size(routes: &[ContentRoute]) -> u64 {
    routes.iter().map(|r| r.size).sum()
}

/// Get website statistics from a contract
pub fn get_website_stats(contract: &Web4Contract) -> WebsiteStats {
    let routes: Vec<ContentRoute> = contract.routes.values().cloned().collect();
    let total_size = calculate_total_size(&routes);
    
    WebsiteStats {
        domain: contract.domain.clone(),
        total_routes: routes.len() as u64,
        total_size,
        owner: contract.owner.clone(),
        created_at: contract.created_at,
        updated_at: contract.updated_at,
        status: contract.domain_record.status.clone(),
    }
}

/// Website statistics structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebsiteStats {
    pub domain: String,
    pub total_routes: u64,
    pub total_size: u64,
    pub owner: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub status: DomainStatus,
}

/// Web4 contract operation result
pub type Web4Result<T> = Result<T, Web4Error>;

/// Helper function to format file size
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size_f = size as f64;
    let mut unit_index = 0;
    
    while size_f >= 1024.0 && unit_index < UNITS.len() - 1 {
        size_f /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", size, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size_f, UNITS[unit_index])
    }
}

/// Helper function to validate route path
pub fn is_valid_route_path(path: &str) -> bool {
    // Basic validation for web routes
    path.starts_with('/') 
        && !path.contains("..") 
        && !path.contains("//")
        && path.len() <= 1000
        && path.chars().all(|c| {
            c.is_alphanumeric() || 
            c == '/' || c == '-' || c == '_' || c == '.' || c == '?' || c == '=' || c == '&'
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_route() -> ContentRoute {
        ContentRoute {
            path: "/".to_string(),
            content_hash: "QmXoYpo9YdJkX8kGd7YtT6yC2FJLzMQvE5rE7Nvh4eJnX5".to_string(),
            content_type: "text/html".to_string(),
            size: 1024,
            metadata: HashMap::new(),
            updated_at: 1633024800,
        }
    }

    #[test]
    fn test_create_website_contract() {
        let metadata = create_default_metadata("Test Site".to_string(), "test@example.com".to_string());
        let deployment_data = WebsiteDeploymentData {
            domain: "test.zhtp".to_string(),
            metadata,
            routes: vec![create_test_route()],
            owner: "test_owner".to_string(),
            config: HashMap::new(),
        };

        let result = create_website_contract("contract_123".to_string(), deployment_data);
        assert!(result.is_ok());
        
        let contract = result.unwrap();
        assert_eq!(contract.domain, "test.zhtp");
        assert_eq!(contract.owner, "test_owner");
    }

    #[test]
    fn test_validate_deployment_data() {
        let metadata = create_default_metadata("Test Site".to_string(), "test@example.com".to_string());
        let deployment_data = WebsiteDeploymentData {
            domain: "test.zhtp".to_string(),
            metadata,
            routes: vec![create_test_route()],
            owner: "test_owner".to_string(),
            config: HashMap::new(),
        };

        assert!(validate_deployment_data(&deployment_data).is_ok());
    }

    #[test]
    fn test_validate_deployment_data_invalid_domain() {
        let metadata = create_default_metadata("Test Site".to_string(), "test@example.com".to_string());
        let deployment_data = WebsiteDeploymentData {
            domain: "test.com".to_string(), // Invalid domain
            metadata,
            routes: vec![create_test_route()],
            owner: "test_owner".to_string(),
            config: HashMap::new(),
        };

        assert!(validate_deployment_data(&deployment_data).is_err());
    }

    #[test]
    fn test_generate_contract_id() {
        let id1 = generate_contract_id("test.zhtp");
        let id2 = generate_contract_id("test.zhtp");
        
        // IDs should be different due to timestamp
        assert_ne!(id1, id2);
        assert!(id1.starts_with("web4_test_zhtp_"));
    }

    #[test]
    fn test_calculate_total_size() {
        let routes = vec![
            ContentRoute {
                path: "/".to_string(),
                content_hash: "QmHash1".to_string(),
                content_type: "text/html".to_string(),
                size: 1024,
                metadata: HashMap::new(),
                updated_at: 1633024800,
            },
            ContentRoute {
                path: "/about".to_string(),
                content_hash: "QmHash2".to_string(),
                content_type: "text/html".to_string(),
                size: 512,
                metadata: HashMap::new(),
                updated_at: 1633024800,
            },
        ];

        assert_eq!(calculate_total_size(&routes), 1536);
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(100), "100 B");
        assert_eq!(format_file_size(1024), "1.00 KB");
        assert_eq!(format_file_size(1048576), "1.00 MB");
        assert_eq!(format_file_size(1073741824), "1.00 GB");
    }

    #[test]
    fn test_is_valid_route_path() {
        assert!(is_valid_route_path("/"));
        assert!(is_valid_route_path("/about"));
        assert!(is_valid_route_path("/api/data"));
        assert!(is_valid_route_path("/search?q=test&type=all"));
        
        assert!(!is_valid_route_path("about")); // No leading slash
        assert!(!is_valid_route_path("/path/../hack")); // Directory traversal
        assert!(!is_valid_route_path("/path//double")); // Double slash
    }
}
