//! ZHTP Request Routing System
//! 
//! Advanced routing system with pattern matching, parameter extraction,
//! middleware integration, and economic route prioritization based on
//! DAO fees and network incentives.

use crate::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use crate::zhtp::{ZhtpRequestHandler, ZhtpResult};

use std::collections::HashMap;
use std::sync::Arc;
use regex::Regex;

/// Route pattern matching types
#[derive(Debug, Clone)]
pub enum RoutePattern {
    /// Exact path match
    Exact(String),
    /// Regex pattern match
    Regex(Regex),
    /// Parameterized path (e.g., "/user/{id}/profile")
    Parameterized(String, Vec<String>),
    /// Wildcard match (e.g., "/api/*")
    Wildcard(String),
    /// Economic priority route (higher DAO fees get priority)
    EconomicPriority(String, u64),
}

/// Route definition
#[derive(Clone)]
pub struct Route {
    /// Route pattern
    pub pattern: RoutePattern,
    /// HTTP methods this route handles
    pub methods: Vec<ZhtpMethod>,
    /// Route handler
    pub handler: Arc<dyn ZhtpRequestHandler>,
    /// Route priority (higher = more priority)
    pub priority: u32,
    /// Economic requirements
    pub economic_requirements: EconomicRequirements,
    /// Access requirements
    pub access_requirements: AccessRequirements,
    /// Route metadata
    pub metadata: RouteMetadata,
    /// Middleware for this specific route
    pub middleware: Vec<String>,
}

/// Economic requirements for routes
#[derive(Debug, Clone)]
pub struct EconomicRequirements {
    /// Minimum DAO fee required (in wei)
    pub min_dao_fee: u64,
    /// Maximum DAO fee allowed (in wei)
    pub max_dao_fee: u64,
    /// Required payment methods
    pub required_payment_methods: Vec<String>,
    /// Economic incentive multiplier
    pub incentive_multiplier: f64,
    /// UBI contribution requirement
    pub ubi_contribution_required: bool,
    /// Fee tier (affects routing priority)
    pub fee_tier: FeeTier,
}

/// Fee tiers for economic routing
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeeTier {
    /// Free tier (no fees required)
    Free = 0,
    /// Basic tier (minimal fees)
    Basic = 1,
    /// Standard tier (moderate fees)
    Standard = 2,
    /// Premium tier (high fees, priority routing)
    Premium = 3,
    /// Enterprise tier (maximum fees, guaranteed routing)
    Enterprise = 4,
}

/// Access requirements for routes
#[derive(Debug, Clone)]
pub struct AccessRequirements {
    /// Required authentication methods
    pub auth_methods: Vec<String>,
    /// Required roles
    pub required_roles: Vec<String>,
    /// Required permissions
    pub required_permissions: Vec<String>,
    /// Minimum reputation score
    pub min_reputation: u32,
    /// Geographic restrictions
    pub geographic_restrictions: Option<GeographicRestrictions>,
    /// Time-based access
    pub time_restrictions: Option<TimeRestrictions>,
}

/// Geographic restrictions
#[derive(Debug, Clone)]
pub struct GeographicRestrictions {
    /// Allowed countries (ISO 3166-1 alpha-2)
    pub allowed_countries: Vec<String>,
    /// Blocked countries (ISO 3166-1 alpha-2)
    pub blocked_countries: Vec<String>,
    /// Allowed regions
    pub allowed_regions: Vec<String>,
    /// IP whitelist
    pub ip_whitelist: Vec<String>,
    /// IP blacklist
    pub ip_blacklist: Vec<String>,
}

/// Time-based access restrictions
#[derive(Debug, Clone)]
pub struct TimeRestrictions {
    /// Allowed hours (0-23)
    pub allowed_hours: Vec<u8>,
    /// Allowed days of week (0=Sunday, 1=Monday, etc.)
    pub allowed_days: Vec<u8>,
    /// Timezone
    pub timezone: String,
    /// Maintenance windows (when route is unavailable)
    pub maintenance_windows: Vec<MaintenanceWindow>,
}

/// Maintenance window definition
#[derive(Debug, Clone)]
pub struct MaintenanceWindow {
    /// Start time (Unix timestamp)
    pub start_time: u64,
    /// End time (Unix timestamp)
    pub end_time: u64,
    /// Description
    pub description: String,
    /// Recurring (weekly, monthly, etc.)
    pub recurring: Option<RecurringPattern>,
}

/// Recurring maintenance patterns
#[derive(Debug, Clone)]
pub enum RecurringPattern {
    /// Weekly on specific day and time
    Weekly { day: u8, hour: u8, duration_hours: u8 },
    /// Monthly on specific date and time
    Monthly { day: u8, hour: u8, duration_hours: u8 },
    /// Custom cron-like pattern
    Cron(String),
}

/// Route metadata
#[derive(Debug, Clone)]
pub struct RouteMetadata {
    /// Route name
    pub name: String,
    /// Route description
    pub description: String,
    /// Route version
    pub version: String,
    /// Route tags
    pub tags: Vec<String>,
    /// Rate limiting configuration
    pub rate_limit: Option<RouteLimitConfig>,
    /// Caching configuration
    pub cache_config: Option<CacheConfig>,
    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
}

/// Route-specific rate limiting
#[derive(Debug, Clone)]
pub struct RouteLimitConfig {
    /// Requests per minute
    pub requests_per_minute: u32,
    /// Burst size
    pub burst_size: u32,
    /// Rate limit by client type
    pub limit_by_client_type: bool,
    /// Rate limit by DAO account
    pub limit_by_dao_account: bool,
}

/// Route-specific caching
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Cache TTL in seconds
    pub ttl_seconds: u64,
    /// Cache key strategy
    pub key_strategy: CacheKeyStrategy,
    /// Cache invalidation rules
    pub invalidation_rules: Vec<String>,
    /// Cache compression
    pub enable_compression: bool,
}

/// Cache key generation strategies
#[derive(Debug, Clone)]
pub enum CacheKeyStrategy {
    /// Use full URL as key
    FullUrl,
    /// Use URL + query parameters
    UrlWithParams,
    /// Use URL + headers
    UrlWithHeaders(Vec<String>),
    /// Custom key generation
    Custom(String),
}

/// Route monitoring configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Enable request/response logging
    pub enable_logging: bool,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable tracing
    pub enable_tracing: bool,
    /// Custom metrics
    pub custom_metrics: Vec<String>,
}

/// Route matching result
#[derive(Clone)]
pub struct RouteMatch {
    /// Matched route
    pub route: Arc<Route>,
    /// Extracted parameters
    pub params: HashMap<String, String>,
    /// Query parameters
    pub query_params: HashMap<String, String>,
    /// Match score (higher = better match)
    pub match_score: u32,
    /// Economic score (based on DAO fees)
    pub economic_score: u32,
}

/// Route handler trait for specific route implementations
#[async_trait::async_trait]
pub trait RouteHandler: Send + Sync {
    /// Handle the request for this specific route
    async fn handle(&self, request: ZhtpRequest, params: HashMap<String, String>) -> ZhtpResult<ZhtpResponse>;
    
    /// Get handler name
    fn name(&self) -> &str;
    
    /// Get handler description
    fn description(&self) -> &str;
    
    /// Check if handler can process the request
    fn can_handle(&self, request: &ZhtpRequest) -> bool;
    
    /// Get economic requirements for this handler
    fn economic_requirements(&self) -> EconomicRequirements {
        EconomicRequirements::default()
    }
    
    /// Get access requirements for this handler
    fn access_requirements(&self) -> AccessRequirements {
        AccessRequirements::default()
    }
}

/// ZHTP Router implementation
pub struct Router {
    /// Registered routes
    routes: Vec<Arc<Route>>,
    /// Route lookup cache
    route_cache: HashMap<String, Vec<Arc<Route>>>,
    /// Default handler (404)
    default_handler: Option<Arc<dyn ZhtpRequestHandler>>,
    /// Router configuration
    config: RouterConfig,
    /// Route statistics
    stats: RouteStats,
}

/// Router configuration
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Enable route caching
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
    /// Enable economic routing
    pub enable_economic_routing: bool,
    /// Economic routing weight (0.0 - 1.0)
    pub economic_weight: f64,
    /// Enable fuzzy matching
    pub enable_fuzzy_matching: bool,
    /// Maximum fuzzy distance
    pub max_fuzzy_distance: u32,
    /// Case sensitive routing
    pub case_sensitive: bool,
    /// Strip trailing slashes
    pub strip_trailing_slash: bool,
}

/// Route statistics
#[derive(Debug, Clone, Default)]
pub struct RouteStats {
    /// Total requests routed
    pub total_requests: u64,
    /// Successful routes
    pub successful_routes: u64,
    /// Failed routes (404s)
    pub failed_routes: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Economic routing decisions
    pub economic_routes: u64,
    /// Route performance metrics
    pub route_performance: HashMap<String, RoutePerformance>,
}

/// Performance metrics per route
#[derive(Debug, Clone, Default)]
pub struct RoutePerformance {
    /// Request count
    pub request_count: u64,
    /// Average response time (ms)
    pub avg_response_time_ms: f64,
    /// Error count
    pub error_count: u64,
    /// Total DAO fees collected
    pub total_dao_fees: u64,
    /// Average DAO fee
    pub avg_dao_fee: f64,
}

impl Router {
    /// Create new router
    pub fn new(config: RouterConfig) -> Self {
        Self {
            routes: Vec::new(),
            route_cache: HashMap::new(),
            default_handler: None,
            config,
            stats: RouteStats::default(),
        }
    }
    
    /// Add route to router
    pub fn add_route(&mut self, route: Route) -> ZhtpResult<()> {
        let route_arc = Arc::new(route);
        self.routes.push(route_arc.clone());
        
        // Sort routes by priority (highest first)
        self.routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Clear cache since routes changed
        self.route_cache.clear();
        
        tracing::info!("🛣️  Added route: {} (priority: {})", 
                      route_arc.metadata.name, route_arc.priority);
        
        Ok(())
    }
    
    /// Add multiple routes
    pub fn add_routes(&mut self, routes: Vec<Route>) -> ZhtpResult<()> {
        for route in routes {
            self.add_route(route)?;
        }
        Ok(())
    }
    
    /// Set default handler for 404 responses
    pub fn set_default_handler(&mut self, handler: Arc<dyn ZhtpRequestHandler>) {
        self.default_handler = Some(handler);
    }
    
    /// Find matching route for request
    pub async fn find_route(&mut self, request: &ZhtpRequest) -> ZhtpResult<Option<RouteMatch>> {
        let start_time = std::time::Instant::now();
        
        // Check cache first
        let cache_key = self.generate_cache_key(request);
        if self.config.enable_caching {
            if let Some(cached_routes) = self.route_cache.get(&cache_key) {
                self.stats.cache_hits += 1;
                if let Some(route_match) = self.find_best_match_from_routes(request, cached_routes).await? {
                    return Ok(Some(route_match));
                }
            } else {
                self.stats.cache_misses += 1;
            }
        }
        
        // Find matching routes
        let mut matching_routes = Vec::new();
        for route in &self.routes {
            if self.route_matches(request, route).await? {
                matching_routes.push(route.clone());
            }
        }
        
        // Cache the matching routes
        if self.config.enable_caching && !matching_routes.is_empty() {
            self.route_cache.insert(cache_key, matching_routes.clone());
        }
        
        // Find best match
        let route_match = self.find_best_match_from_routes(request, &matching_routes).await?;
        
        // Update statistics
        self.stats.total_requests += 1;
        if route_match.is_some() {
            self.stats.successful_routes += 1;
        } else {
            self.stats.failed_routes += 1;
        }
        
        let routing_time = start_time.elapsed();
        tracing::debug!("Route matching took {:?}", routing_time);
        
        Ok(route_match)
    }
    
    /// Route request to appropriate handler
    pub async fn route_request(&mut self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let route_match = self.find_route(&request).await?;
        
        match route_match {
            Some(route_match) => {
                // Update route performance metrics
                self.update_route_performance(&route_match.route.metadata.name);
                
                // Handle economic routing decision
                if self.config.enable_economic_routing {
                    self.stats.economic_routes += 1;
                    self.record_economic_routing(&request, &route_match)?;
                }
                
                // Execute the route handler
                let start_time = std::time::Instant::now();
                let response = route_match.route.handler.handle_request(request).await?;
                let response_time = start_time.elapsed().as_millis() as f64;
                
                // Update performance metrics
                self.update_response_time(&route_match.route.metadata.name, response_time);
                
                Ok(response)
            }
            None => {
                // No matching route found, use default handler or return 404
                if let Some(default_handler) = &self.default_handler {
                    default_handler.handle_request(request).await
                } else {
                    Ok(ZhtpResponse::error(
                        ZhtpStatus::NotFound,
                        "No matching route found".to_string(),
                    ))
                }
            }
        }
    }
    
    /// Check if route matches request
    async fn route_matches(&self, request: &ZhtpRequest, route: &Route) -> ZhtpResult<bool> {
        // Check HTTP method
        if !route.methods.is_empty() && !route.methods.contains(&request.method) {
            return Ok(false);
        }
        
        // Check pattern match
        if !self.pattern_matches(&route.pattern, &request.uri) {
            return Ok(false);
        }
        
        // Check economic requirements
        if !self.economic_requirements_met(request, &route.economic_requirements).await? {
            return Ok(false);
        }
        
        // Check access requirements
        if !self.access_requirements_met(request, &route.access_requirements).await? {
            return Ok(false);
        }
        
        // Check time restrictions
        if !self.time_restrictions_met(&route.access_requirements.time_restrictions).await? {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Check if pattern matches URI
    fn pattern_matches(&self, pattern: &RoutePattern, uri: &str) -> bool {
        let normalized_uri = if self.config.strip_trailing_slash {
            uri.trim_end_matches('/')
        } else {
            uri
        };
        
        let uri_to_match = if self.config.case_sensitive {
            normalized_uri
        } else {
            &normalized_uri.to_lowercase()
        };
        
        match pattern {
            RoutePattern::Exact(path) => {
                let pattern_path = if self.config.case_sensitive {
                    path.as_str()
                } else {
                    &path.to_lowercase()
                };
                uri_to_match == pattern_path
            }
            RoutePattern::Regex(regex) => {
                regex.is_match(uri_to_match)
            }
            RoutePattern::Parameterized(path, _params) => {
                self.parameterized_match(path, uri_to_match)
            }
            RoutePattern::Wildcard(prefix) => {
                let pattern_prefix = if self.config.case_sensitive {
                    prefix.as_str()
                } else {
                    &prefix.to_lowercase()
                };
                uri_to_match.starts_with(pattern_prefix)
            }
            RoutePattern::EconomicPriority(path, _min_fee) => {
                self.pattern_matches(&RoutePattern::Exact(path.clone()), uri)
            }
        }
    }
    
    /// Check parameterized pattern match
    fn parameterized_match(&self, pattern: &str, uri: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('/').collect();
        let uri_parts: Vec<&str> = uri.split('/').collect();
        
        if pattern_parts.len() != uri_parts.len() {
            return false;
        }
        
        for (pattern_part, uri_part) in pattern_parts.iter().zip(uri_parts.iter()) {
            if pattern_part.starts_with('{') && pattern_part.ends_with('}') {
                // This is a parameter, skip validation
                continue;
            } else if pattern_part != uri_part {
                return false;
            }
        }
        
        true
    }
    
    /// Extract parameters from parameterized route
    fn extract_parameters(&self, pattern: &RoutePattern, uri: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        
        match pattern {
            RoutePattern::Parameterized(path, param_names) => {
                let pattern_parts: Vec<&str> = path.split('/').collect();
                let uri_parts: Vec<&str> = uri.split('/').collect();
                
                let mut param_index = 0;
                for (pattern_part, uri_part) in pattern_parts.iter().zip(uri_parts.iter()) {
                    if pattern_part.starts_with('{') && pattern_part.ends_with('}') {
                        if param_index < param_names.len() {
                            params.insert(
                                param_names[param_index].clone(),
                                uri_part.to_string(),
                            );
                            param_index += 1;
                        }
                    }
                }
            }
            _ => {}
        }
        
        params
    }
    
    /// Check if economic requirements are met
    async fn economic_requirements_met(
        &self,
        request: &ZhtpRequest,
        requirements: &EconomicRequirements,
    ) -> ZhtpResult<bool> {
        // Extract DAO fee from request
        let dao_fee = if let Some(fee_str) = request.headers.get("X-DAO-Fee") {
            fee_str.parse::<u64>().unwrap_or(0)
        } else {
            0
        };
        
        // Check minimum fee requirement
        if dao_fee < requirements.min_dao_fee {
            return Ok(false);
        }
        
        // Check maximum fee requirement
        if dao_fee > requirements.max_dao_fee {
            return Ok(false);
        }
        
        // Check payment method requirement
        if !requirements.required_payment_methods.is_empty() {
            let payment_method = request.headers.get("X-Payment-Method")
                .unwrap_or("unknown".to_string());
            
            if !requirements.required_payment_methods.contains(&payment_method.to_string()) {
                return Ok(false);
            }
        }
        
        // Check UBI contribution requirement
        if requirements.ubi_contribution_required {
            let ubi_contribution = request.headers.get("X-UBI-Contribution")
                .and_then(|s| s.parse::<bool>().ok())
                .unwrap_or(false);
            
            if !ubi_contribution {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Check if access requirements are met
    async fn access_requirements_met(
        &self,
        request: &ZhtpRequest,
        requirements: &AccessRequirements,
    ) -> ZhtpResult<bool> {
        // Check authentication methods
        if !requirements.auth_methods.is_empty() {
            let auth_method = request.headers.get("X-Auth-Method")
                .unwrap_or("none".to_string());
            
            if !requirements.auth_methods.contains(&auth_method.to_string()) {
                return Ok(false);
            }
        }
        
        // Check required roles
        if !requirements.required_roles.is_empty() {
            let user_roles = request.headers.get("X-User-Roles")
                .unwrap_or("".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<String>>();
            
            for required_role in &requirements.required_roles {
                if !user_roles.contains(required_role) {
                    return Ok(false);
                }
            }
        }
        
        // Check required permissions
        if !requirements.required_permissions.is_empty() {
            let user_permissions = request.headers.get("X-User-Permissions")
                .unwrap_or("".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<String>>();
            
            for required_permission in &requirements.required_permissions {
                if !user_permissions.contains(required_permission) {
                    return Ok(false);
                }
            }
        }
        
        // Check minimum reputation
        if requirements.min_reputation > 0 {
            let reputation = request.headers.get("X-User-Reputation")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            
            if reputation < requirements.min_reputation {
                return Ok(false);
            }
        }
        
        // Check geographic restrictions
        if let Some(geo_restrictions) = &requirements.geographic_restrictions {
            if !self.geographic_restrictions_met(request, geo_restrictions).await? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Check geographic restrictions
    async fn geographic_restrictions_met(
        &self,
        request: &ZhtpRequest,
        restrictions: &GeographicRestrictions,
    ) -> ZhtpResult<bool> {
        let client_ip_raw = request.headers.get("X-Real-IP")
            .or_else(|| request.headers.get("X-Forwarded-For"))
            .unwrap_or("unknown".to_string());
        let client_ip = client_ip_raw
            .split(',')
            .next()
            .unwrap_or("unknown")
            .trim();
        
        // Check IP whitelist
        if !restrictions.ip_whitelist.is_empty() {
            if !restrictions.ip_whitelist.contains(&client_ip.to_string()) {
                return Ok(false);
            }
        }
        
        // Check IP blacklist
        if restrictions.ip_blacklist.contains(&client_ip.to_string()) {
            return Ok(false);
        }
        
        // For country/region checks, we'd need a GeoIP service
        // This is a simplified implementation
        let country_code = request.headers.get("X-Country-Code")
            .unwrap_or("unknown".to_string());
        
        // Check allowed countries
        if !restrictions.allowed_countries.is_empty() {
            if !restrictions.allowed_countries.contains(&country_code.to_string()) {
                return Ok(false);
            }
        }
        
        // Check blocked countries
        if restrictions.blocked_countries.contains(&country_code.to_string()) {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Check time restrictions
    async fn time_restrictions_met(&self, restrictions: &Option<TimeRestrictions>) -> ZhtpResult<bool> {
        if let Some(time_restrictions) = restrictions {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            // Convert to the specified timezone (simplified - would use chrono in production)
            let current_hour = ((now / 3600) % 24) as u8;
            let current_day = ((now / 86400 + 4) % 7) as u8; // Unix epoch was Thursday
            
            // Check allowed hours
            if !time_restrictions.allowed_hours.is_empty() {
                if !time_restrictions.allowed_hours.contains(&current_hour) {
                    return Ok(false);
                }
            }
            
            // Check allowed days
            if !time_restrictions.allowed_days.is_empty() {
                if !time_restrictions.allowed_days.contains(&current_day) {
                    return Ok(false);
                }
            }
            
            // Check maintenance windows
            for window in &time_restrictions.maintenance_windows {
                if now >= window.start_time && now <= window.end_time {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    /// Find best match from candidate routes
    async fn find_best_match_from_routes(
        &self,
        request: &ZhtpRequest,
        routes: &[Arc<Route>],
    ) -> ZhtpResult<Option<RouteMatch>> {
        if routes.is_empty() {
            return Ok(None);
        }
        
        let mut best_match: Option<RouteMatch> = None;
        
        for route in routes {
            let params = self.extract_parameters(&route.pattern, &request.uri);
            let query_params = self.extract_query_parameters(&request.uri);
            
            let match_score = self.calculate_match_score(request, route).await?;
            let economic_score = self.calculate_economic_score(request, route).await?;
            
            let route_match = RouteMatch {
                route: route.clone(),
                params,
                query_params,
                match_score,
                economic_score,
            };
            
            if let Some(ref current_best) = best_match {
                // Prioritize by economic score if economic routing is enabled
                if self.config.enable_economic_routing {
                    let economic_weight = self.config.economic_weight;
                    let combined_score = (route_match.match_score as f64 * (1.0 - economic_weight)) +
                                       (route_match.economic_score as f64 * economic_weight);
                    let current_combined = (current_best.match_score as f64 * (1.0 - economic_weight)) +
                                         (current_best.economic_score as f64 * economic_weight);
                    
                    if combined_score > current_combined {
                        best_match = Some(route_match);
                    }
                } else if route_match.match_score > current_best.match_score {
                    best_match = Some(route_match);
                }
            } else {
                best_match = Some(route_match);
            }
        }
        
        Ok(best_match)
    }
    
    /// Calculate match score for route
    async fn calculate_match_score(&self, request: &ZhtpRequest, route: &Route) -> ZhtpResult<u32> {
        let mut score = route.priority;
        
        // Exact pattern matches get higher scores
        match &route.pattern {
            RoutePattern::Exact(_) => score += 100,
            RoutePattern::Parameterized(_, _) => score += 80,
            RoutePattern::Regex(_) => score += 60,
            RoutePattern::Wildcard(_) => score += 40,
            RoutePattern::EconomicPriority(_, _) => score += 120,
        }
        
        // Method-specific routes get higher scores
        if route.methods.len() == 1 && route.methods.contains(&request.method) {
            score += 50;
        }
        
        Ok(score)
    }
    
    /// Calculate economic score for route
    async fn calculate_economic_score(&self, request: &ZhtpRequest, route: &Route) -> ZhtpResult<u32> {
        let dao_fee = request.headers.get("X-DAO-Fee")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        
        let mut score = 0u32;
        
        // Higher fees get higher scores
        match route.economic_requirements.fee_tier {
            FeeTier::Free => score += 10,
            FeeTier::Basic => score += 25,
            FeeTier::Standard => score += 50,
            FeeTier::Premium => score += 75,
            FeeTier::Enterprise => score += 100,
        }
        
        // Bonus for exceeding minimum fee
        if dao_fee > route.economic_requirements.min_dao_fee {
            let fee_ratio = dao_fee as f64 / route.economic_requirements.min_dao_fee as f64;
            score += (fee_ratio * 20.0) as u32;
        }
        
        // Incentive multiplier affects score
        score = (score as f64 * route.economic_requirements.incentive_multiplier) as u32;
        
        Ok(score)
    }
    
    /// Extract query parameters from URI
    fn extract_query_parameters(&self, uri: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        
        if let Some(query_start) = uri.find('?') {
            let query_string = &uri[query_start + 1..];
            
            for pair in query_string.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let key = &pair[..eq_pos];
                    let value = &pair[eq_pos + 1..];
                    params.insert(
                        urlencoding::decode(key).unwrap_or_default().to_string(),
                        urlencoding::decode(value).unwrap_or_default().to_string(),
                    );
                } else {
                    params.insert(
                        urlencoding::decode(pair).unwrap_or_default().to_string(),
                        "".to_string(),
                    );
                }
            }
        }
        
        params
    }
    
    /// Generate cache key for request
    fn generate_cache_key(&self, request: &ZhtpRequest) -> String {
        format!("{}:{}", request.method as u8, request.uri)
    }
    
    /// Update route performance metrics
    fn update_route_performance(&mut self, route_name: &str) {
        let performance = self.stats.route_performance
            .entry(route_name.to_string())
            .or_default();
        performance.request_count += 1;
    }
    
    /// Update response time metrics
    fn update_response_time(&mut self, route_name: &str, response_time_ms: f64) {
        let performance = self.stats.route_performance
            .entry(route_name.to_string())
            .or_default();
        
        // Calculate rolling average
        let total_time = performance.avg_response_time_ms * (performance.request_count - 1) as f64;
        performance.avg_response_time_ms = (total_time + response_time_ms) / performance.request_count as f64;
    }
    
    /// Record economic routing decision
    fn record_economic_routing(&mut self, request: &ZhtpRequest, route_match: &RouteMatch) -> ZhtpResult<()> {
        let dao_fee = request.headers.get("X-DAO-Fee")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        
        let performance = self.stats.route_performance
            .entry(route_match.route.metadata.name.clone())
            .or_default();
        
        performance.total_dao_fees += dao_fee;
        performance.avg_dao_fee = performance.total_dao_fees as f64 / performance.request_count as f64;
        
        tracing::info!("Economic routing: {} -> {} (fee: {} wei, score: {})",
                      request.uri,
                      route_match.route.metadata.name,
                      dao_fee,
                      route_match.economic_score);
        
        Ok(())
    }
    
    /// Get router statistics
    pub fn get_stats(&self) -> &RouteStats {
        &self.stats
    }
    
    /// Clear route cache
    pub fn clear_cache(&mut self) {
        self.route_cache.clear();
        tracing::info!(" Route cache cleared");
    }
}

impl Default for EconomicRequirements {
    fn default() -> Self {
        Self {
            min_dao_fee: 0,
            max_dao_fee: u64::MAX,
            required_payment_methods: vec![],
            incentive_multiplier: 1.0,
            ubi_contribution_required: false,
            fee_tier: FeeTier::Free,
        }
    }
}

impl Default for AccessRequirements {
    fn default() -> Self {
        Self {
            auth_methods: vec![],
            required_roles: vec![],
            required_permissions: vec![],
            min_reputation: 0,
            geographic_restrictions: None,
            time_restrictions: None,
        }
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_ttl: 300, // 5 minutes
            enable_economic_routing: true,
            economic_weight: 0.3, // 30% weight to economic factors
            enable_fuzzy_matching: false,
            max_fuzzy_distance: 2,
            case_sensitive: false,
            strip_trailing_slash: true,
        }
    }
}

/// Create a basic route
pub fn create_route(
    pattern: RoutePattern,
    methods: Vec<ZhtpMethod>,
    handler: Arc<dyn ZhtpRequestHandler>,
    name: &str,
) -> Route {
    Route {
        pattern,
        methods,
        handler,
        priority: 100,
        economic_requirements: EconomicRequirements::default(),
        access_requirements: AccessRequirements::default(),
        metadata: RouteMetadata {
            name: name.to_string(),
            description: format!("Route for {}", name),
            version: "1.0".to_string(),
            tags: vec![],
            rate_limit: None,
            cache_config: None,
            monitoring: MonitoringConfig {
                enable_logging: true,
                enable_metrics: true,
                enable_tracing: false,
                custom_metrics: vec![],
            },
        },
        middleware: vec![],
    }
}

/// Create an economic priority route
pub fn create_economic_route(
    path: &str,
    min_fee: u64,
    fee_tier: FeeTier,
    methods: Vec<ZhtpMethod>,
    handler: Arc<dyn ZhtpRequestHandler>,
    name: &str,
) -> Route {
    Route {
        pattern: RoutePattern::EconomicPriority(path.to_string(), min_fee),
        methods,
        handler,
        priority: 200, // Higher priority for economic routes
        economic_requirements: EconomicRequirements {
            min_dao_fee: min_fee,
            max_dao_fee: u64::MAX,
            required_payment_methods: vec![],
            incentive_multiplier: match fee_tier {
                FeeTier::Free => 1.0,
                FeeTier::Basic => 1.2,
                FeeTier::Standard => 1.5,
                FeeTier::Premium => 2.0,
                FeeTier::Enterprise => 3.0,
            },
            ubi_contribution_required: true,
            fee_tier: fee_tier.clone(),
        },
        access_requirements: AccessRequirements::default(),
        metadata: RouteMetadata {
            name: name.to_string(),
            description: format!("Economic route for {} (tier: {:?})", name, fee_tier),
            version: "1.0".to_string(),
            tags: vec!["economic".to_string(), format!("{:?}", fee_tier).to_lowercase()],
            rate_limit: None,
            cache_config: None,
            monitoring: MonitoringConfig {
                enable_logging: true,
                enable_metrics: true,
                enable_tracing: true,
                custom_metrics: vec!["dao_fees".to_string(), "ubi_distribution".to_string()],
            },
        },
        middleware: vec!["economic_validator".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_route_pattern_matching() {
        let router = Router::new(RouterConfig::default());
        
        // Test exact match
        let exact_pattern = RoutePattern::Exact("/api/users".to_string());
        assert!(router.pattern_matches(&exact_pattern, "/api/users"));
        assert!(!router.pattern_matches(&exact_pattern, "/api/users/123"));
        
        // Test wildcard match
        let wildcard_pattern = RoutePattern::Wildcard("/api/".to_string());
        assert!(router.pattern_matches(&wildcard_pattern, "/api/users"));
        assert!(router.pattern_matches(&wildcard_pattern, "/api/posts/123"));
        assert!(!router.pattern_matches(&wildcard_pattern, "/auth/login"));
    }

    #[test]
    fn test_parameter_extraction() {
        let router = Router::new(RouterConfig::default());
        let pattern = RoutePattern::Parameterized(
            "/users/{id}/posts/{post_id}".to_string(),
            vec!["id".to_string(), "post_id".to_string()],
        );
        
        let params = router.extract_parameters(&pattern, "/users/123/posts/456");
        assert_eq!(params.get("id"), Some(&"123".to_string()));
        assert_eq!(params.get("post_id"), Some(&"456".to_string()));
    }

    #[test]
    fn test_query_parameter_extraction() {
        let router = Router::new(RouterConfig::default());
        let params = router.extract_query_parameters("/api/search?q=test&limit=10&sort=desc");
        
        assert_eq!(params.get("q"), Some(&"test".to_string()));
        assert_eq!(params.get("limit"), Some(&"10".to_string()));
        assert_eq!(params.get("sort"), Some(&"desc".to_string()));
    }

    #[test]
    fn test_fee_tier_ordering() {
        assert!(FeeTier::Enterprise > FeeTier::Premium);
        assert!(FeeTier::Premium > FeeTier::Standard);
        assert!(FeeTier::Standard > FeeTier::Basic);
        assert!(FeeTier::Basic > FeeTier::Free);
    }

    #[tokio::test]
    async fn test_economic_requirements() {
        use lib_economy::{EconomicModel, Priority};
        
        let router = Router::new(RouterConfig::default());
        
        // Create a test economic model
        let economic_model = EconomicModel::new();
        
        let mut request = ZhtpRequest::new(
            ZhtpMethod::Get,
            "/test".to_string(),
            vec![],
            None, // requester
            Priority::Normal,
            &economic_model,
        ).unwrap();
        
        // Set the required headers after creating the request
        request.headers.set("X-DAO-Fee", "5000".to_string());
        request.headers.set("X-Payment-Method", "ethereum".to_string());
        
        let requirements = EconomicRequirements {
            min_dao_fee: 1000,
            max_dao_fee: 10000,
            required_payment_methods: vec!["ethereum".to_string()],
            incentive_multiplier: 1.5,
            ubi_contribution_required: false,
            fee_tier: FeeTier::Standard,
        };
        
        let result = router.economic_requirements_met(&request, &requirements).await.unwrap();
        assert!(result);
    }
}
