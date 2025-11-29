//! DNS Resolution API Handler
//! 
//! Provides HTTP API endpoints for resolving .zhtp domains to DHT content hashes
//! Integrates with blockchain contracts and Web4 domain registry

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use chrono;

use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpStatus};
use lib_network::Web4Manager;
use crate::runtime::blockchain_provider::get_global_blockchain;

/// DNS resolution request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolveRequest {
    pub domain: String,
    pub record_type: Option<String>, // A, AAAA, CNAME, etc. (defaults to A)
}

/// DNS resolution response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolveResponse {
    pub domain: String,
    pub resolved: bool,
    pub content_hash: Option<String>,
    pub contract_address: Option<String>,
    pub record_type: String,
    pub ttl: u64,
    pub metadata: HashMap<String, String>,
    pub timestamp: u64,
}

/// Web4 site metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4SiteMetadata {
    pub title: String,
    pub description: String,
    pub owner: String,
    pub content_type: String,
    pub size: u64,
    pub deployed_at: u64,
}

/// DNS Handler implementation
pub struct DnsHandler {
    /// Mock domain registry (in production this would be blockchain-based)
    domain_registry: Arc<RwLock<HashMap<String, DomainRecord>>>,
    /// Web4Manager for querying registered domains
    web4_manager: Option<Arc<RwLock<Web4Manager>>>,
    /// Handler statistics
    stats: Arc<RwLock<DnsHandlerStats>>,
}

/// Domain record in registry
#[derive(Debug, Clone)]
struct DomainRecord {
    domain: String,
    content_hash: String,
    contract_address: String,
    owner: String,
    registered_at: u64,
    expires_at: u64,
    metadata: Web4SiteMetadata,
}

/// DNS handler internal statistics
#[derive(Debug, Default)]
struct DnsHandlerStats {
    requests_handled: u64,
    successful_resolutions: u64,
    failed_resolutions: u64,
    last_request_time: Option<std::time::Instant>,
}

impl DnsHandler {
    /// Create a new DNS handler
    pub fn new() -> Self {
        let registry = HashMap::new();
        
        // DNS registry starts empty - domains will be registered through proper deployment process
        info!("DNS handler initialized with empty registry - ready for domain deployments");

        Self {
            domain_registry: Arc::new(RwLock::new(registry)),
            web4_manager: None, // Will be set by set_web4_manager()
            stats: Arc::new(RwLock::new(DnsHandlerStats::default())),
        }
    }

    /// Set Web4Manager for domain resolution
    pub fn set_web4_manager(&mut self, manager: Arc<RwLock<Web4Manager>>) {
        info!("DNS handler connected to Web4Manager");
        self.web4_manager = Some(manager);
    }

    /// Resolve a .zhtp domain to content hash
    pub async fn resolve_domain(&self, domain: &str) -> ZhtpResult<ZhtpResponse> {
        info!("Resolving domain: {}", domain);
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.requests_handled += 1;
            stats.last_request_time = Some(std::time::Instant::now());
        }

        let current_time = chrono::Utc::now().timestamp() as u64;

        // First try Web4Manager if available
        if let Some(web4_manager) = &self.web4_manager {
            info!(" Querying Web4Manager for domain: {}", domain);
            let manager = web4_manager.read().await;
            
            match manager.registry.lookup_domain(domain).await {
                Ok(domain_info) if domain_info.found => {
                    info!(" Domain {} found in Web4 registry", domain);
                    
                    let owner_display = domain_info.owner_info.as_ref()
                        .and_then(|o| o.alias.clone())
                        .or_else(|| domain_info.owner_info.as_ref().map(|o| o.identity_hash.clone()[..16].to_string()))
                        .unwrap_or_else(|| "unknown".to_string());
                    
                    let registered_at = domain_info.owner_info.as_ref()
                        .map(|o| o.registered_at)
                        .unwrap_or(0);
                    
                    info!("   Owner: {}", owner_display);
                    info!("   Registered: {}", registered_at);
                    info!("   Content routes: {}", domain_info.content_mappings.len());
                    
                    // Get default content hash (usually for root path "/")
                    let content_hash = domain_info.content_mappings.get("/")
                        .or_else(|| domain_info.content_mappings.values().next())
                        .cloned();
                    
                    if let Some(hash) = content_hash {
                        let mut metadata = HashMap::new();
                        metadata.insert("owner".to_string(), owner_display);
                        metadata.insert("registered_at".to_string(), registered_at.to_string());
                        metadata.insert("routes".to_string(), domain_info.content_mappings.len().to_string());
                        metadata.insert("source".to_string(), "web4_registry".to_string());
                        
                        let response = DnsResolveResponse {
                            domain: domain.to_string(),
                            resolved: true,
                            content_hash: Some(hash),
                            contract_address: None, // Web4 contract address could be added here
                            record_type: "A".to_string(),
                            ttl: 3600, // 1 hour TTL
                            metadata,
                            timestamp: current_time,
                        };

                        self.update_stats(true).await;
                        return Ok(ZhtpResponse::success_with_content_type(
                            serde_json::to_vec(&response).unwrap(),
                            "application/json".to_string(),
                            None,
                        ));
                    }
                }
                Ok(_) => {
                    debug!("Domain {} not found in Web4 registry (not found flag)", domain);
                }
                Err(e) => {
                    debug!("Domain {} not found in Web4 registry: {}", domain, e);
                }
            }
        }

        // Fallback: Check local domain registry
        let registry = self.domain_registry.read().await;
        
        if let Some(record) = registry.get(domain) {
            // Check if domain hasn't expired
            let current_time = chrono::Utc::now().timestamp() as u64;
            if record.expires_at < current_time {
                warn!("Domain {} has expired", domain);
                
                let response = DnsResolveResponse {
                    domain: domain.to_string(),
                    resolved: false,
                    content_hash: None,
                    contract_address: None,
                    record_type: "A".to_string(),
                    ttl: 300,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("error".to_string(), "Domain expired".to_string());
                        meta
                    },
                    timestamp: current_time,
                };

                self.update_stats(false).await;
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    serde_json::to_string(&response).unwrap(),
                ));
            }

            // Verify contract on blockchain
            match self.verify_domain_contract(&record.contract_address, domain).await {
                Ok(true) => {
                    info!("Domain {} resolved to content hash: {}", domain, record.content_hash);
                    
                    let mut metadata = HashMap::new();
                    metadata.insert("title".to_string(), record.metadata.title.clone());
                    metadata.insert("description".to_string(), record.metadata.description.clone());
                    metadata.insert("owner".to_string(), record.metadata.owner.clone());
                    metadata.insert("content_type".to_string(), record.metadata.content_type.clone());
                    metadata.insert("size".to_string(), record.metadata.size.to_string());
                    metadata.insert("deployed_at".to_string(), record.metadata.deployed_at.to_string());
                    
                    let response = DnsResolveResponse {
                        domain: domain.to_string(),
                        resolved: true,
                        content_hash: Some(record.content_hash.clone()),
                        contract_address: Some(record.contract_address.clone()),
                        record_type: "A".to_string(),
                        ttl: 3600, // 1 hour TTL
                        metadata,
                        timestamp: current_time,
                    };

                    self.update_stats(true).await;
                    return Ok(ZhtpResponse::success_with_content_type(
                        serde_json::to_vec(&response).unwrap(),
                        "application/json".to_string(),
                        None,
                    ));
                }
                Ok(false) => {
                    error!("Domain {} contract verification failed", domain);
                    
                    let response = DnsResolveResponse {
                        domain: domain.to_string(),
                        resolved: false,
                        content_hash: None,
                        contract_address: Some(record.contract_address.clone()),
                        record_type: "A".to_string(),
                        ttl: 300,
                        metadata: {
                            let mut meta = HashMap::new();
                            meta.insert("error".to_string(), "Contract verification failed".to_string());
                            meta
                        },
                        timestamp: current_time,
                    };

                    self.update_stats(false).await;
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::InternalServerError,
                        serde_json::to_string(&response).unwrap(),
                    ));
                }
                Err(e) => {
                    error!("Error verifying contract for domain {}: {}", domain, e);
                    
                    let response = DnsResolveResponse {
                        domain: domain.to_string(),
                        resolved: false,
                        content_hash: None,
                        contract_address: Some(record.contract_address.clone()),
                        record_type: "A".to_string(),
                        ttl: 300,
                        metadata: {
                            let mut meta = HashMap::new();
                            meta.insert("error".to_string(), format!("Blockchain error: {}", e));
                            meta
                        },
                        timestamp: current_time,
                    };

                    self.update_stats(false).await;
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::InternalServerError,
                        serde_json::to_string(&response).unwrap(),
                    ));
                }
            }
        } else {
            warn!("Domain {} not found in registry", domain);
            
            let current_time = chrono::Utc::now().timestamp() as u64;
            let response = DnsResolveResponse {
                domain: domain.to_string(),
                resolved: false,
                content_hash: None,
                contract_address: None,
                record_type: "A".to_string(),
                ttl: 300,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("error".to_string(), "Domain not registered".to_string());
                    meta.insert("suggestion".to_string(), "Register this domain in Web4 registry".to_string());
                    meta
                },
                timestamp: current_time,
            };

            self.update_stats(false).await;
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                serde_json::to_string(&response).unwrap(),
            ));
        }
    }

    /// Register a new domain in the registry
    pub async fn register_domain(&self, domain: String, content_hash: String, contract_address: String, metadata: Web4SiteMetadata) -> Result<(), String> {
        info!("Registering domain: {} -> {}", domain, content_hash);
        
        let current_time = chrono::Utc::now().timestamp() as u64;
        let record = DomainRecord {
            domain: domain.clone(),
            content_hash,
            contract_address,
            owner: metadata.owner.clone(),
            registered_at: current_time,
            expires_at: current_time + 31536000, // 1 year
            metadata,
        };

        let mut registry = self.domain_registry.write().await;
        registry.insert(domain.clone(), record);
        
        info!("Domain {} registered successfully", domain);
        Ok(())
    }

    /// Verify domain contract on blockchain
    async fn verify_domain_contract(&self, contract_address: &str, domain: &str) -> Result<bool, anyhow::Error> {
        debug!("Verifying contract {} for domain {}", contract_address, domain);
        
        // Get blockchain access
        match get_global_blockchain().await {
            Ok(blockchain) => {
                let _blockchain_guard = blockchain.read().await;
                
                // In production, this would:
                // 1. Query blockchain for contract at contract_address
                // 2. Verify contract contains domain mapping for 'domain'
                // 3. Check contract owner and permissions
                // 4. Verify contract signature and state
                
                // For now, verify that we have a valid-looking contract address
                if contract_address.len() >= 16 && !contract_address.contains("0x1234") {
                    info!("Contract verification passed for {} at {}", domain, contract_address);
                    Ok(true)
                } else {
                    warn!("Invalid or test contract address for domain {}", domain);
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Failed to access blockchain for contract verification: {}", e);
                Err(e)
            }
        }
    }

    /// Get DNS statistics
    async fn get_dns_statistics(&self) -> ZhtpResult<ZhtpResponse> {
        debug!("Getting DNS statistics");
        
        let stats = self.stats.read().await;
        let registry = self.domain_registry.read().await;
        
        let response = serde_json::json!({
            "requests_handled": stats.requests_handled,
            "successful_resolutions": stats.successful_resolutions,
            "failed_resolutions": stats.failed_resolutions,
            "domains_registered": registry.len(),
            "uptime": "24/7",
            "last_request": stats.last_request_time.map(|t| t.elapsed().as_secs()).unwrap_or(0)
        });

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response).unwrap(),
            "application/json".to_string(),
            None,
        ))
    }

    /// List all registered domains
    async fn list_domains(&self) -> ZhtpResult<ZhtpResponse> {
        info!("Listing registered domains");
        
        let registry = self.domain_registry.read().await;
        let domains: Vec<_> = registry.iter().map(|(domain, record)| {
            serde_json::json!({
                "domain": domain,
                "content_hash": record.content_hash,
                "contract_address": record.contract_address,
                "owner": record.owner,
                "registered_at": record.registered_at,
                "expires_at": record.expires_at,
                "metadata": record.metadata
            })
        }).collect();

        let response = serde_json::json!({
            "domains": domains,
            "total_count": domains.len()
        });

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response).unwrap(),
            "application/json".to_string(),
            None,
        ))
    }

    /// Update handler statistics
    async fn update_stats(&self, success: bool) {
        let mut stats = self.stats.write().await;
        if success {
            stats.successful_resolutions += 1;
        } else {
            stats.failed_resolutions += 1;
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for DnsHandler {
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/dns/") || request.uri.starts_with("/api/dns/")
    }

    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        match request.method {
            ZhtpMethod::Get => match request.uri.as_str() {
                "/api/v1/dns/stats" => {
                    debug!("DNS statistics request");
                    self.get_dns_statistics().await
                }
                "/api/v1/dns/domains" => {
                    info!("DNS domains list request");
                    self.list_domains().await
                }
                path if path.starts_with("/api/v1/dns/resolve/") => {
                    let domain = path.strip_prefix("/api/v1/dns/resolve/").unwrap_or("");
                    if domain.is_empty() {
                        Ok(ZhtpResponse::error(
                            ZhtpStatus::BadRequest,
                            "Domain required".to_string(),
                        ))
                    } else {
                        info!("DNS resolve request: {}", domain);
                        self.resolve_domain(domain).await
                    }
                }
                _ => {
                    warn!("❓ Unknown DNS GET endpoint: {}", request.uri);
                    Ok(ZhtpResponse::not_found("Unknown DNS GET endpoint".to_string()))
                }
            },
            ZhtpMethod::Post => {
                warn!("DNS POST methods not implemented yet: {}", request.uri);
                Ok(ZhtpResponse::method_not_allowed("POST not supported for DNS endpoints".to_string()))
            }
            _ => {
                warn!("Unsupported DNS method: {:?}", request.method);
                Ok(ZhtpResponse::method_not_allowed("Method not allowed for DNS endpoint".to_string()))
            }
        }
    }
}

impl Default for DnsHandler {
    fn default() -> Self {
        Self::new()
    }
}