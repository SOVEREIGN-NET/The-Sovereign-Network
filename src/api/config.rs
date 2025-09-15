//! ZHTP API Configuration
//! 
//! Configuration types for the orchestrator API layer

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// API configuration for ZHTP orchestrator
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Server port
    pub port: Option<u16>,
    /// Enable API authentication
    pub require_auth: bool,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Default rate limit per minute
    pub default_rate_limit: u32,
    /// Enable API analytics
    pub enable_analytics: bool,
    /// Enable economic fees for API calls
    pub enable_economic_fees: bool,
    /// Economic fee configuration
    pub economic_config: ApiEconomicConfig,
    /// CORS configuration
    pub cors_config: CorsConfig,
    /// API versioning
    pub api_version: String,
    /// Level 2 component endpoints
    pub component_endpoints: ComponentEndpoints,
}

/// Economic configuration for API calls
#[derive(Debug, Clone)]
pub struct ApiEconomicConfig {
    /// Base fee per API call (in wei)
    pub base_fee_per_call: u64,
    /// Premium endpoint multiplier
    pub premium_endpoint_multiplier: f64,
    /// DAO fee percentage
    pub dao_fee_percentage: f64,
    /// UBI contribution percentage
    pub ubi_contribution_percentage: f64,
    /// Economic tier multipliers
    pub tier_multipliers: HashMap<ApiTier, f64>,
}

/// API access tiers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ApiTier {
    /// Free tier (limited requests)
    Free,
    /// Basic paid tier
    Basic,
    /// Professional tier
    Professional,
    /// Enterprise tier
    Enterprise,
    /// DAO member tier
    DaoMember,
    /// Premium unlimited tier
    Premium,
}

/// CORS configuration
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Enable credentials
    pub allow_credentials: bool,
    /// Max age for preflight cache
    pub max_age: u32,
}

/// Level 2 component endpoint configuration
#[derive(Debug, Clone)]
pub struct ComponentEndpoints {
    /// lib-protocols server endpoint
    pub protocols_endpoint: String,
    /// lib-blockchain server endpoint  
    pub blockchain_endpoint: String,
    /// lib-network server endpoint
    pub network_endpoint: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        let mut tier_multipliers = HashMap::new();
        tier_multipliers.insert(ApiTier::Free, 1.0);
        tier_multipliers.insert(ApiTier::Basic, 0.8);
        tier_multipliers.insert(ApiTier::Professional, 0.6);
        tier_multipliers.insert(ApiTier::Enterprise, 0.4);
        tier_multipliers.insert(ApiTier::DaoMember, 0.5);
        tier_multipliers.insert(ApiTier::Premium, 0.0);

        Self {
            port: None,
            require_auth: false,
            enable_rate_limiting: true,
            default_rate_limit: 1000,
            enable_analytics: true,
            enable_economic_fees: true,
            economic_config: ApiEconomicConfig {
                base_fee_per_call: 1000,
                premium_endpoint_multiplier: 2.0,
                dao_fee_percentage: 0.02,
                ubi_contribution_percentage: 0.01,
                tier_multipliers,
            },
            cors_config: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allowed_methods: vec![
                    "GET".to_string(),
                    "POST".to_string(), 
                    "PUT".to_string(),
                    "DELETE".to_string(),
                    "OPTIONS".to_string(),
                ],
                allowed_headers: vec![
                    "Content-Type".to_string(),
                    "Authorization".to_string(),
                    "X-API-Key".to_string(),
                    "X-User-ID".to_string(),
                ],
                allow_credentials: true,
                max_age: 3600,
            },
            api_version: "1.0".to_string(),
            component_endpoints: ComponentEndpoints {
                protocols_endpoint: "http://localhost:9334".to_string(),
                blockchain_endpoint: "http://localhost:9335".to_string(), 
                network_endpoint: "http://localhost:9336".to_string(),
            },
        }
    }
}
