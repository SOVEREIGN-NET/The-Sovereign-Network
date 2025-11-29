//! Core Web4 smart contract implementation for decentralized website hosting

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::contracts::web4::types::*;
use crate::types::{ContractResult, ContractCall};

/// Web4 Website Smart Contract
/// 
/// Manages decentralized website hosting, domain registration, and content routing
/// through smart contracts integrated with DHT storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Web4Contract {
    /// Contract identifier
    pub contract_id: String,
    /// Domain being managed by this contract
    pub domain: String,
    /// Website metadata
    pub metadata: WebsiteMetadata,
    /// Content routes mapping
    pub routes: HashMap<String, ContentRoute>,
    /// Domain ownership record
    pub domain_record: DomainRecord,
    /// Contract owner
    pub owner: String,
    /// Contract creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Contract configuration
    pub config: HashMap<String, String>,
}

impl Web4Contract {
    /// Create a new Web4 contract for website hosting
    pub fn new(
        contract_id: String,
        domain: String,
        owner: String,
        metadata: WebsiteMetadata,
        deployment_data: WebsiteDeploymentData,
    ) -> Self {
        let current_time = chrono::Utc::now().timestamp() as u64;
        
        // Convert deployment routes to HashMap
        let mut routes = HashMap::new();
        for route in deployment_data.routes {
            routes.insert(route.path.clone(), route);
        }
        
        // Create domain record
        let domain_record = DomainRecord {
            domain: domain.clone(),
            owner: owner.clone(),
            contract_address: contract_id.clone(),
            registered_at: current_time,
            expires_at: current_time + (365 * 24 * 3600), // 1 year default
            status: DomainStatus::Active,
        };
        
        Self {
            contract_id,
            domain,
            metadata,
            routes,
            domain_record,
            owner,
            created_at: current_time,
            updated_at: current_time,
            config: deployment_data.config,
        }
    }
    
    /// Register or update domain ownership
    pub fn register_domain(&mut self, domain: String, owner: String, duration_years: u32) -> Result<Web4Response, Web4Error> {
        // Validate domain name
        if !Self::is_valid_domain(&domain) {
            return Err(Web4Error::InvalidDomain(domain));
        }
        
        // Check if caller is authorized
        if self.owner != owner && !self.domain_record.domain.is_empty() {
            return Err(Web4Error::Unauthorized);
        }
        
        let current_time = chrono::Utc::now().timestamp() as u64;
        let duration_seconds = (duration_years as u64) * 365 * 24 * 3600;
        
        self.domain = domain.clone();
        self.domain_record = DomainRecord {
            domain: domain.clone(),
            owner: owner.clone(),
            contract_address: self.contract_id.clone(),
            registered_at: current_time,
            expires_at: current_time + duration_seconds,
            status: DomainStatus::Active,
        };
        
        self.owner = owner;
        self.updated_at = current_time;
        
        Ok(Web4Response::Success {
            message: format!("Domain {} registered successfully for {} years", domain, duration_years),
            data: Some(serde_json::to_value(&self.domain_record).unwrap()),
        })
    }
    
    /// Update content for a specific route
    pub fn update_content(&mut self, route_path: String, content_hash: String, content_type: String, size: u64) -> Result<Web4Response, Web4Error> {
        // Validate content hash
        if !Self::is_valid_content_hash(&content_hash) {
            return Err(Web4Error::InvalidContentHash(content_hash));
        }
        
        let current_time = chrono::Utc::now().timestamp() as u64;
        
        // Update existing route or create new one
        let route = ContentRoute {
            path: route_path.clone(),
            content_hash: content_hash.clone(),
            content_type,
            size,
            metadata: HashMap::new(),
            updated_at: current_time,
        };
        
        self.routes.insert(route_path.clone(), route);
        self.updated_at = current_time;
        
        Ok(Web4Response::Success {
            message: format!("Content updated for route {} with hash {}", route_path, content_hash),
            data: Some(serde_json::json!({
                "route": route_path,
                "content_hash": content_hash,
                "updated_at": current_time
            })),
        })
    }
    
    /// Add a new content route
    pub fn add_route(&mut self, route: ContentRoute) -> Result<Web4Response, Web4Error> {
        // Check if route already exists
        if self.routes.contains_key(&route.path) {
            return Err(Web4Error::RouteAlreadyExists(route.path.clone()));
        }
        
        // Validate content hash
        if !Self::is_valid_content_hash(&route.content_hash) {
            return Err(Web4Error::InvalidContentHash(route.content_hash.clone()));
        }
        
        let route_path = route.path.clone();
        self.routes.insert(route_path.clone(), route);
        self.updated_at = chrono::Utc::now().timestamp() as u64;
        
        Ok(Web4Response::Success {
            message: format!("Route {} added successfully", route_path),
            data: Some(serde_json::json!({
                "route": route_path,
                "total_routes": self.routes.len()
            })),
        })
    }
    
    /// Remove a content route
    pub fn remove_route(&mut self, route_path: String) -> Result<Web4Response, Web4Error> {
        if self.routes.remove(&route_path).is_none() {
            return Err(Web4Error::RouteNotFound(route_path));
        }
        
        self.updated_at = chrono::Utc::now().timestamp() as u64;
        
        Ok(Web4Response::Success {
            message: format!("Route {} removed successfully", route_path),
            data: Some(serde_json::json!({
                "removed_route": route_path,
                "remaining_routes": self.routes.len()
            })),
        })
    }
    
    /// Update website metadata
    pub fn update_metadata(&mut self, metadata: WebsiteMetadata) -> Result<Web4Response, Web4Error> {
        self.metadata = metadata;
        self.updated_at = chrono::Utc::now().timestamp() as u64;
        
        Ok(Web4Response::Success {
            message: "Website metadata updated successfully".to_string(),
            data: Some(serde_json::to_value(&self.metadata).unwrap()),
        })
    }
    
    /// Transfer domain ownership
    pub fn transfer_ownership(
        &mut self,
        domain: String,
        new_owner: String,
    ) -> Result<Web4Response, Web4Error> {
        if self.domain_record.domain != domain {
            return Err(Web4Error::DomainNotFound(domain));
        }

        self.domain_record.owner = new_owner.clone();
        self.owner = new_owner;

        Ok(Web4Response::Success {
            message: format!("Ownership of {} transferred successfully", domain),
            data: Some(serde_json::to_value(&self.domain_record).unwrap()),
        })
    }
    
    /// Get content hash for a specific route
    pub fn get_content_hash(&self, route_path: String) -> Result<Web4Response, Web4Error> {
        match self.routes.get(&route_path) {
            Some(route) => Ok(Web4Response::ContentHash(route.content_hash.clone())),
            None => Err(Web4Error::RouteNotFound(route_path)),
        }
    }
    
    /// Get all routes
    pub fn get_routes(&self) -> Web4Response {
        let routes: Vec<ContentRoute> = self.routes.values().cloned().collect();
        Web4Response::Routes(routes)
    }
    
    /// Get website metadata
    pub fn get_metadata(&self) -> Web4Response {
        Web4Response::Metadata(self.metadata.clone())
    }
    
    /// Get domain information
    pub fn get_domain_info(&self) -> Web4Response {
        Web4Response::Domain(self.domain_record.clone())
    }
    
    /// Get domain record by name
    pub fn get_domain(&self, domain: &str) -> Result<DomainRecord, Web4Error> {
        if self.domain_record.domain == domain {
            Ok(self.domain_record.clone())
        } else {
            Err(Web4Error::DomainNotFound(domain.to_string()))
        }
    }
    
    /// Get domain owner
    pub fn get_owner(&self) -> Web4Response {
        Web4Response::Owner(self.owner.clone())
    }
    
    /// Check if domain is available
    pub fn is_domain_available(&self, domain: String) -> Web4Response {
        let available = self.domain.is_empty() || self.domain != domain;
        Web4Response::DomainAvailable(available)
    }
    
    /// Get contract statistics
    pub fn get_stats(&self) -> Web4Response {
        let total_size: u64 = self.routes.values().map(|r| r.size).sum();
        
        Web4Response::Stats {
            total_routes: self.routes.len() as u64,
            total_size,
            last_updated: self.updated_at,
            domain_status: self.domain_record.status.clone(),
        }
    }

    // ========================================================================
    // MANIFEST-BASED DEPLOYMENT METHODS
    // ========================================================================

    /// Create a new Web4 contract from a deployment package
    pub fn from_deployment_package(
        contract_id: String,
        package: DeploymentPackage,
    ) -> Result<Self, Web4Error> {
        // Validate manifest
        package.manifest.validate()
            .map_err(|e| Web4Error::InvalidMetadata(format!("Invalid manifest: {}", e)))?;

        // Validate domain
        if !Self::is_valid_domain(&package.domain) {
            return Err(Web4Error::InvalidDomain(package.domain));
        }

        let current_time = chrono::Utc::now().timestamp() as u64;

        // Convert manifest routes to ContentRoute format
        let mut routes = HashMap::new();
        for (route_path, file_path) in &package.manifest.entry_points {
            if let Some(node) = package.manifest.root_directory.find_node(file_path) {
                if let Some(content_hash) = &node.content_hash {
                    if let NodeType::File { mime_type, size, .. } = &node.node_type {
                        let content_route = ContentRoute {
                            path: route_path.clone(),
                            content_hash: content_hash.clone(),
                            content_type: mime_type.clone(),
                            size: *size,
                            metadata: HashMap::new(),
                            updated_at: current_time,
                        };
                        routes.insert(route_path.clone(), content_route);
                    }
                }
            }
        }

        // Create domain record
        let domain_record = DomainRecord {
            domain: package.domain.clone(),
            owner: package.owner.clone(),
            contract_address: contract_id.clone(),
            registered_at: current_time,
            expires_at: current_time + (365 * 24 * 3600), // 1 year default
            status: DomainStatus::Active,
        };

        Ok(Self {
            contract_id,
            domain: package.domain,
            metadata: package.metadata,
            routes,
            domain_record,
            owner: package.owner,
            created_at: current_time,
            updated_at: current_time,
            config: package.config,
        })
    }

    /// Deploy a complete website from a manifest
    pub fn deploy_from_manifest(&mut self, manifest: WebsiteManifest) -> Result<Web4Response, Web4Error> {
        // Validate manifest
        manifest.validate()
            .map_err(|e| Web4Error::InvalidMetadata(format!("Invalid manifest: {}", e)))?;

        let current_time = chrono::Utc::now().timestamp() as u64;

        // Clear existing routes
        self.routes.clear();

        // Convert manifest to routes
        let mut deployed_count = 0;
        for (route_path, file_path) in &manifest.entry_points {
            if let Some(node) = manifest.root_directory.find_node(file_path) {
                if let Some(content_hash) = &node.content_hash {
                    if let NodeType::File { mime_type, size, .. } = &node.node_type {
                        let content_route = ContentRoute {
                            path: route_path.clone(),
                            content_hash: content_hash.clone(),
                            content_type: mime_type.clone(),
                            size: *size,
                            metadata: HashMap::new(),
                            updated_at: current_time,
                        };
                        self.routes.insert(route_path.clone(), content_route);
                        deployed_count += 1;
                    }
                }
            }
        }

        self.updated_at = current_time;

        Ok(Web4Response::Success {
            message: format!("Deployed {} routes from manifest", deployed_count),
            data: Some(serde_json::json!({
                "total_routes": deployed_count,
                "total_size": manifest.total_size,
                "file_count": manifest.file_count,
                "manifest_hash": manifest.manifest_hash,
            })),
        })
    }

    /// Add a directory tree to the website
    pub fn add_directory_tree(&mut self, directory: DirectoryNode, base_route: String) -> Result<Web4Response, Web4Error> {
        let current_time = chrono::Utc::now().timestamp() as u64;
        let mut added_count = 0;

        // Recursively add all files from the directory tree
        fn add_files_recursive(
            routes: &mut HashMap<String, ContentRoute>,
            node: &DirectoryNode,
            base_route: &str,
            current_time: u64,
            added_count: &mut u32,
        ) -> Result<(), Web4Error> {
            match &node.node_type {
                NodeType::File { mime_type, size, .. } => {
                    if let Some(content_hash) = &node.content_hash {
                        let route_path = if base_route.is_empty() {
                            node.path.clone()
                        } else {
                            format!("{}{}", base_route, node.path)
                        };

                        let content_route = ContentRoute {
                            path: route_path.clone(),
                            content_hash: content_hash.clone(),
                            content_type: mime_type.clone(),
                            size: *size,
                            metadata: HashMap::new(),
                            updated_at: current_time,
                        };

                        routes.insert(route_path, content_route);
                        *added_count += 1;
                    }
                }
                NodeType::Directory => {
                    // Process all children
                    for child in &node.children {
                        add_files_recursive(routes, child, base_route, current_time, added_count)?;
                    }
                }
                NodeType::Symlink { .. } => {
                    // Symlinks not yet supported
                }
            }

            Ok(())
        }

        add_files_recursive(&mut self.routes, &directory, &base_route, current_time, &mut added_count)?;
        self.updated_at = current_time;

        Ok(Web4Response::Success {
            message: format!("Added {} files from directory tree", added_count),
            data: Some(serde_json::json!({
                "added_routes": added_count,
                "base_route": base_route,
            })),
        })
    }

    /// Resolve a file path through the manifest structure
    pub fn resolve_path(&self, path: &str) -> Option<&ContentRoute> {
        // Try direct route match first
        if let Some(route) = self.routes.get(path) {
            return Some(route);
        }

        // Try with trailing slash variations
        let path_with_slash = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };

        if let Some(route) = self.routes.get(&path_with_slash) {
            return Some(route);
        }

        // Try index.html if path is a directory
        let index_path = if path.ends_with('/') {
            format!("{}index.html", path)
        } else {
            format!("{}/index.html", path)
        };

        self.routes.get(&index_path)
    }

    /// Get all files matching a pattern
    pub fn find_files(&self, pattern: &str) -> Vec<&ContentRoute> {
        self.routes
            .iter()
            .filter(|(path, _)| path.contains(pattern))
            .map(|(_, route)| route)
            .collect()
    }

    /// Get directory listing for a path
    pub fn list_directory(&self, dir_path: &str) -> Vec<String> {
        let normalized_path = if dir_path.ends_with('/') {
            dir_path.to_string()
        } else {
            format!("{}/", dir_path)
        };

        let mut files = Vec::new();
        for (path, _) in &self.routes {
            if path.starts_with(&normalized_path) {
                // Get relative path from directory
                let relative = &path[normalized_path.len()..];
                // Only include direct children (no subdirectories)
                if !relative.contains('/') || (relative.ends_with('/') && relative.matches('/').count() == 1) {
                    files.push(path.clone());
                }
            }
        }

        files.sort();
        files
    }
    
    /// Validate domain name format
    fn is_valid_domain(domain: &str) -> bool {
        // Basic domain validation for .zhtp domains
        domain.ends_with(".zhtp") 
            && domain.len() > 5 
            && domain.len() < 100
            && domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
            && !domain.starts_with('-')
            && !domain.ends_with('-')
    }
    
    /// Validate content hash format (/DHT hash)
    fn is_valid_content_hash(hash: &str) -> bool {
        // Basic validation for /DHT content hashes
        (hash.starts_with("Qm") && hash.len() == 46) || 
        (hash.starts_with("dht:") && hash.len() > 10) ||
        (hash.starts_with(":") && hash.len() > 10)
    }
    
    /// Get detailed metadata for a specific content route
    pub fn get_route_metadata(&self, path: &str) -> Option<HashMap<String, String>> {
        self.routes.get(path).map(|route| route.metadata.clone())
    }
    
    /// Get all content statistics for the website
    pub fn get_content_statistics(&self) -> ContentStatistics {
        let mut total_size = 0u64;
        let mut total_access_count = 0u64;
        let mut content_types: HashMap<String, u64> = HashMap::new();
        
        for route in self.routes.values() {
            total_size += route.size;
            
            // Extract access count from metadata if available
            if let Some(access_count) = route.metadata.get("access_count")
                .and_then(|s| s.parse::<u64>().ok()) {
                total_access_count += access_count;
            }
            
            // Count content types
            *content_types.entry(route.content_type.clone()).or_insert(0) += 1;
        }
        
        ContentStatistics {
            domain: self.domain.clone(),
            total_routes: self.routes.len(),
            total_size,
            total_access_count,
            content_types,
            last_updated: self.updated_at,
            created_at: self.created_at,
        }
    }
    
    /// Get metadata summary for all routes
    pub fn get_all_routes_metadata(&self) -> HashMap<String, HashMap<String, String>> {
        self.routes.iter()
            .map(|(path, route)| (path.clone(), route.metadata.clone()))
            .collect()
    }
}

/// Content statistics for a website
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentStatistics {
    /// Domain name
    pub domain: String,
    /// Total number of routes
    pub total_routes: usize,
    /// Total content size in bytes
    pub total_size: u64,
    /// Total access count across all content
    pub total_access_count: u64,
    /// Content types distribution
    pub content_types: HashMap<String, u64>,
    /// Last update timestamp
    pub last_updated: u64,
    /// Creation timestamp
    pub created_at: u64,
}

impl Web4Contract {
    /// Execute a Web4 contract function call
    pub fn execute(&mut self, call: ContractCall) -> ContractResult {
        match call.method.as_str() {
            "register_domain" => {
                let args: (String, String, u32) = match serde_json::from_slice(&call.params) {
                    Ok(args) => args,
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&format!("Invalid arguments: {}", e));
                        return result;
                    }
                };
                
                match self.register_domain(args.0, args.1, args.2) {
                    Ok(response) => {
                        match ContractResult::with_return_data(&response, 5000) {
                            Ok(result) => result,
                            Err(_) => {
                                let mut result = ContractResult::with_gas(5000);
                                result.gas_used = 5000;
                                result
                            }
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "update_content" => {
                let args: (String, String, String, u64) = match serde_json::from_slice(&call.params) {
                    Ok(args) => args,
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&format!("Invalid arguments: {}", e));
                        return result;
                    }
                };
                
                match self.update_content(args.0, args.1, args.2, args.3) {
                    Ok(response) => {
                        match ContractResult::with_return_data(&response, 3000) {
                            Ok(result) => result,
                            Err(_) => {
                                let mut result = ContractResult::with_gas(3000);
                                result.gas_used = 3000;
                                result
                            }
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "add_route" => {
                let route: ContentRoute = match serde_json::from_slice(&call.params) {
                    Ok(route) => route,
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&format!("Invalid route data: {}", e));
                        return result;
                    }
                };
                
                match self.add_route(route) {
                    Ok(response) => {
                        match ContractResult::with_return_data(&response, 2000) {
                            Ok(result) => result,
                            Err(_) => {
                                let mut result = ContractResult::with_gas(2000);
                                result.gas_used = 2000;
                                result
                            }
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "remove_route" => {
                let route_path: String = match serde_json::from_slice(&call.params) {
                    Ok(path) => path,
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&format!("Invalid route path: {}", e));
                        return result;
                    }
                };
                
                match self.remove_route(route_path) {
                    Ok(response) => {
                        match ContractResult::with_return_data(&response, 1500) {
                            Ok(result) => result,
                            Err(_) => ContractResult::with_gas(1500)
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "update_metadata" => {
                let metadata: WebsiteMetadata = match serde_json::from_slice(&call.params) {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&format!("Invalid metadata: {}", e));
                        return result;
                    }
                };
                
                match self.update_metadata(metadata) {
                    Ok(response) => {
                        match ContractResult::with_return_data(&response, 1500) {
                            Ok(result) => result,
                            Err(_) => ContractResult::with_gas(1500)
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "transfer_ownership" => {
                let new_owner: String = match serde_json::from_slice(&call.params) {
                    Ok(owner) => owner,
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&format!("Invalid owner: {}", e));
                        return result;
                    }
                };
                
                match self.transfer_ownership(self.domain.clone(), new_owner) {
                    Ok(response) => {
                        match ContractResult::with_return_data(&response, 4000) {
                            Ok(result) => result,
                            Err(_) => {
                                let mut result = ContractResult::with_gas(4000);
                                result.gas_used = 4000;
                                result
                            }
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(1000);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "get_content_hash" => {
                let route: String = match serde_json::from_slice(&call.params) {
                    Ok(route) => route,
                    Err(e) => {
                        let mut result = ContractResult::failure(100);
                        let _ = result.set_return_data(&format!("Invalid route: {}", e));
                        return result;
                    }
                };
                
                match self.get_content_hash(route) {
                    Ok(hash) => {
                        match ContractResult::with_return_data(&hash, 300) {
                            Ok(result) => result,
                            Err(_) => {
                                let mut result = ContractResult::with_gas(300);
                                result.gas_used = 300;
                                result
                            }
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(100);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "get_routes" => {
                let routes = self.get_routes();
                match ContractResult::with_return_data(&routes, 500) {
                    Ok(result) => result,
                    Err(_) => ContractResult::with_gas(500)
                }
            }
            "get_metadata" => {
                let metadata = self.get_metadata();
                match ContractResult::with_return_data(&metadata, 300) {
                    Ok(result) => result,
                    Err(_) => ContractResult::with_gas(300)
                }
            }
            "get_domain" => {
                let domain: String = match serde_json::from_slice(&call.params) {
                    Ok(domain) => domain,
                    Err(e) => {
                        let mut result = ContractResult::failure(100);
                        let _ = result.set_return_data(&format!("Invalid domain: {}", e));
                        return result;
                    }
                };
                
                match self.get_domain(&domain) {
                    Ok(response) => {
                        match ContractResult::with_return_data(&response, 500) {
                            Ok(result) => result,
                            Err(_) => {
                                let mut result = ContractResult::with_gas(500);
                                result.gas_used = 500;
                                result
                            }
                        }
                    },
                    Err(e) => {
                        let mut result = ContractResult::failure(100);
                        let _ = result.set_return_data(&e.to_string());
                        result
                    }
                }
            }
            "get_stats" => {
                let stats = self.get_stats();
                match ContractResult::with_return_data(&stats, 300) {
                    Ok(result) => result,
                    Err(_) => ContractResult::with_gas(300)
                }
            }
            _ => {
                let mut result = ContractResult::failure(100);
                let _ = result.set_return_data(&format!("Unknown method: {}", call.method));
                result
            }
        }
    }
    
    fn get_state(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    
    fn set_state(&mut self, state: Vec<u8>) -> Result<(), String> {
        match serde_json::from_slice::<Web4Contract>(&state) {
            Ok(contract) => {
                *self = contract;
                Ok(())
            }
            Err(e) => Err(format!("Failed to deserialize state: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_metadata() -> WebsiteMetadata {
        WebsiteMetadata {
            title: "Test Web4 Site".to_string(),
            description: "A test website".to_string(),
            author: "test@example.com".to_string(),
            version: "1.0.0".to_string(),
            tags: vec!["test".to_string(), "web4".to_string()],
            language: "en".to_string(),
            created_at: 1633024800,
            updated_at: 1633024800,
            custom: HashMap::new(),
        }
    }

    fn create_test_deployment_data() -> WebsiteDeploymentData {
        WebsiteDeploymentData {
            domain: "test.zhtp".to_string(),
            metadata: create_test_metadata(),
            routes: vec![
                ContentRoute {
                    path: "/".to_string(),
                    content_hash: "QmXoYpo9YdJkX8kGd7YtT6yC2FJLzMQvE5rE7Nvh4eJnX5".to_string(),
                    content_type: "text/html".to_string(),
                    size: 1024,
                    metadata: HashMap::new(),
                    updated_at: 1633024800,
                },
            ],
            owner: "test_owner".to_string(),
            config: HashMap::new(),
        }
    }

    #[test]
    fn test_new_web4_contract() {
        let deployment_data = create_test_deployment_data();
        let contract = Web4Contract::new(
            "contract_123".to_string(),
            "test.zhtp".to_string(),
            "test_owner".to_string(),
            create_test_metadata(),
            deployment_data,
        );

        assert_eq!(contract.domain, "test.zhtp");
        assert_eq!(contract.owner, "test_owner");
        assert_eq!(contract.routes.len(), 1);
        assert!(contract.routes.contains_key("/"));
    }

    #[test]
    fn test_domain_validation() {
        assert!(Web4Contract::is_valid_domain("test.zhtp"));
        assert!(Web4Contract::is_valid_domain("my-site.zhtp"));
        assert!(!Web4Contract::is_valid_domain("test"));
        assert!(!Web4Contract::is_valid_domain("test.com"));
        assert!(!Web4Contract::is_valid_domain("-invalid.zhtp"));
        assert!(!Web4Contract::is_valid_domain("invalid-.zhtp"));
    }

    #[test]
    fn test_content_hash_validation() {
        assert!(Web4Contract::is_valid_content_hash("QmXoYpo9YdJkX8kGd7YtT6yC2FJLzMQvE5rE7Nvh4eJnX5"));
        assert!(Web4Contract::is_valid_content_hash("dht:content_hash_123"));
        assert!(Web4Contract::is_valid_content_hash(":QmXoYpo9YdJkX8kGd7YtT6yC2FJL"));
        assert!(!Web4Contract::is_valid_content_hash("invalid_hash"));
        assert!(!Web4Contract::is_valid_content_hash("Qm123")); // Too short
    }

    #[test]
    fn test_update_content() {
        let deployment_data = create_test_deployment_data();
        let mut contract = Web4Contract::new(
            "contract_123".to_string(),
            "test.zhtp".to_string(),
            "test_owner".to_string(),
            create_test_metadata(),
            deployment_data,
        );

        let result = contract.update_content(
            "/about".to_string(),
            "QmNewContentHash123456789012345678901234567890".to_string(),
            "text/html".to_string(),
            2048,
        );

        assert!(result.is_ok());
        assert!(contract.routes.contains_key("/about"));
        assert_eq!(contract.routes["/about"].size, 2048);
    }

    #[test]
    fn test_add_remove_route() {
        let deployment_data = create_test_deployment_data();
        let mut contract = Web4Contract::new(
            "contract_123".to_string(),
            "test.zhtp".to_string(),
            "test_owner".to_string(),
            create_test_metadata(),
            deployment_data,
        );

        // Add route
        let route = ContentRoute {
            path: "/contact".to_string(),
            content_hash: "QmContactHash1234567890123456789012345678901".to_string(),
            content_type: "text/html".to_string(),
            size: 512,
            metadata: HashMap::new(),
            updated_at: 1633024800,
        };

        let add_result = contract.add_route(route);
        assert!(add_result.is_ok());
        assert!(contract.routes.contains_key("/contact"));

        // Remove route
        let remove_result = contract.remove_route("/contact".to_string());
        assert!(remove_result.is_ok());
        assert!(!contract.routes.contains_key("/contact"));
    }
}
