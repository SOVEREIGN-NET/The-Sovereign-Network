//! ZDNS Resolver with LRU caching
//!
//! Provides high-performance domain resolution with caching at the resolver boundary.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use lru::LruCache;
use tracing::{debug, info, warn};

use crate::web4::{DomainRegistry, DomainRecord, ContentMode, Web4Capability};
use super::config::ZdnsConfig;
use super::error::ZdnsError;

/// Resolved Web4 domain record with content configuration
#[derive(Debug, Clone)]
pub struct Web4Record {
    /// Domain name
    pub domain: String,
    /// Owner identity (hex-encoded hash for privacy)
    pub owner: String,
    /// Content mappings (path -> content_hash)
    pub content_mappings: HashMap<String, String>,
    /// Content serving mode (Static or SPA)
    pub content_mode: Option<ContentMode>,
    /// SPA entry point (e.g., "index.html")
    pub spa_entry: Option<String>,
    /// Asset prefixes that should not fallback to SPA entry
    pub asset_prefixes: Option<Vec<String>>,
    /// Web4 capability level
    pub capability: Option<Web4Capability>,
    /// Record TTL in seconds
    pub ttl: u64,
    /// Registration timestamp
    pub registered_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
}

impl Web4Record {
    /// Check if the domain has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at < now
    }

    /// Check if domain has content mappings
    pub fn has_content(&self) -> bool {
        !self.content_mappings.is_empty()
    }

    /// Get effective content mode (defaults to SPA)
    pub fn effective_content_mode(&self) -> ContentMode {
        self.content_mode.unwrap_or(ContentMode::Spa)
    }

    /// Get effective capability (defaults to SpaServe)
    pub fn effective_capability(&self) -> Web4Capability {
        self.capability.unwrap_or(Web4Capability::SpaServe)
    }
}

/// Cached record wrapper with expiration tracking
#[derive(Debug, Clone)]
pub struct CachedRecord {
    /// The resolved Web4 record (None for negative cache entries)
    pub record: Option<Web4Record>,
    /// When this entry was cached
    pub cached_at: Instant,
    /// Cache TTL for this entry
    pub ttl: Duration,
}

impl CachedRecord {
    /// Check if the cached entry has expired
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() >= self.ttl
    }

    /// Create a positive cache entry
    pub fn positive(record: Web4Record, ttl: Duration) -> Self {
        Self {
            record: Some(record),
            cached_at: Instant::now(),
            ttl,
        }
    }

    /// Create a negative cache entry (domain not found)
    pub fn negative(ttl: Duration) -> Self {
        Self {
            record: None,
            cached_at: Instant::now(),
            ttl,
        }
    }
}

/// Resolver metrics for monitoring
#[derive(Debug, Default, Clone)]
pub struct ResolverMetrics {
    /// Total cache hits
    pub cache_hits: u64,
    /// Total cache misses
    pub cache_misses: u64,
    /// Total negative cache hits (cached not-found)
    pub negative_hits: u64,
    /// Total registry lookups performed
    pub registry_lookups: u64,
    /// Total expired entries encountered
    pub expired_entries: u64,
    /// Total invalidations performed
    pub invalidations: u64,
}

impl ResolverMetrics {
    /// Calculate cache hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

/// ZDNS Resolver with LRU caching
///
/// Provides efficient domain resolution with:
/// - LRU cache for bounded memory usage
/// - TTL-based expiration
/// - Negative caching for not-found domains
/// - Thread-safe concurrent access
pub struct ZdnsResolver {
    /// Domain registry for lookups
    domain_registry: Arc<DomainRegistry>,
    /// LRU cache for resolved records
    cache: Arc<RwLock<LruCache<String, CachedRecord>>>,
    /// Resolver configuration
    config: ZdnsConfig,
    /// Metrics for monitoring
    metrics: Arc<RwLock<ResolverMetrics>>,
}

impl ZdnsResolver {
    /// Create a new ZDNS resolver
    pub fn new(domain_registry: Arc<DomainRegistry>, config: ZdnsConfig) -> Self {
        info!(
            cache_size = config.cache_size,
            default_ttl_secs = config.default_ttl.as_secs(),
            "ZDNS resolver initialized"
        );

        Self {
            domain_registry,
            cache: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(config.cache_size).unwrap_or(
                    std::num::NonZeroUsize::new(1).unwrap()
                )
            ))),
            config,
            metrics: Arc::new(RwLock::new(ResolverMetrics::default())),
        }
    }

    /// Resolve a Web4 domain with caching
    ///
    /// Returns the resolved Web4 record, using cache when available.
    /// Cache misses trigger a registry lookup and cache the result.
    pub async fn resolve_web4(&self, domain: &str) -> Result<Web4Record, ZdnsError> {
        // Validate domain format
        if !Self::is_valid_domain(domain) {
            return Err(ZdnsError::InvalidDomain(domain.to_string()));
        }

        // Normalize domain (lowercase, trim whitespace)
        let domain = domain.to_lowercase().trim().to_string();

        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get(&domain) {
                if !cached.is_expired() {
                    // Update metrics
                    if self.config.enable_metrics {
                        let mut metrics = self.metrics.write().await;
                        if cached.record.is_some() {
                            metrics.cache_hits += 1;
                        } else {
                            metrics.negative_hits += 1;
                        }
                    }

                    if self.config.debug_cache {
                        debug!(
                            domain = %domain,
                            is_negative = cached.record.is_none(),
                            age_ms = cached.cached_at.elapsed().as_millis(),
                            "Cache hit"
                        );
                    }

                    // Return cached result
                    return match &cached.record {
                        Some(record) => Ok(record.clone()),
                        None => Err(ZdnsError::DomainNotFound(domain)),
                    };
                } else {
                    // Expired entry - will be replaced
                    if self.config.enable_metrics {
                        let mut metrics = self.metrics.write().await;
                        metrics.expired_entries += 1;
                    }

                    if self.config.debug_cache {
                        debug!(domain = %domain, "Cache entry expired");
                    }
                }
            }
        }

        // Cache miss - resolve from registry
        if self.config.enable_metrics {
            let mut metrics = self.metrics.write().await;
            metrics.cache_misses += 1;
            metrics.registry_lookups += 1;
        }

        let result = self.resolve_from_registry(&domain).await;

        // Cache the result
        {
            let mut cache = self.cache.write().await;
            match &result {
                Ok(record) => {
                    let ttl = if record.ttl > 0 {
                        Duration::from_secs(record.ttl)
                    } else {
                        self.config.default_ttl
                    };
                    cache.put(domain.clone(), CachedRecord::positive(record.clone(), ttl));

                    if self.config.debug_cache {
                        debug!(
                            domain = %domain,
                            ttl_secs = ttl.as_secs(),
                            "Cached positive result"
                        );
                    }
                }
                Err(ZdnsError::DomainNotFound(_)) => {
                    // Cache negative result
                    cache.put(domain.clone(), CachedRecord::negative(self.config.negative_ttl));

                    if self.config.debug_cache {
                        debug!(
                            domain = %domain,
                            ttl_secs = self.config.negative_ttl.as_secs(),
                            "Cached negative result"
                        );
                    }
                }
                Err(_) => {
                    // Don't cache errors other than not-found
                }
            }
        }

        result
    }

    /// Invalidate cache entry for a domain
    ///
    /// Call this when a domain is registered, updated, or content is published.
    pub async fn invalidate(&self, domain: &str) {
        let domain = domain.to_lowercase().trim().to_string();

        let mut cache = self.cache.write().await;
        if cache.pop(&domain).is_some() {
            if self.config.enable_metrics {
                drop(cache); // Release cache lock before acquiring metrics lock
                let mut metrics = self.metrics.write().await;
                metrics.invalidations += 1;
            }

            info!(domain = %domain, "Cache entry invalidated");
        }
    }

    /// Invalidate all cache entries (for maintenance/testing)
    pub async fn invalidate_all(&self) {
        let mut cache = self.cache.write().await;
        let count = cache.len();
        cache.clear();

        info!(entries_cleared = count, "All cache entries invalidated");
    }

    /// Get current resolver metrics
    pub async fn get_metrics(&self) -> ResolverMetrics {
        self.metrics.read().await.clone()
    }

    /// Get current cache size
    pub async fn cache_size(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Resolve domain from registry (no caching)
    async fn resolve_from_registry(&self, domain: &str) -> Result<Web4Record, ZdnsError> {
        match self.domain_registry.lookup_domain(domain).await {
            Ok(lookup) if lookup.found => {
                if let Some(record) = lookup.record {
                    // Check if domain has expired
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    if record.expires_at < now {
                        return Err(ZdnsError::DomainExpired(domain.to_string()));
                    }

                    // Convert DomainRecord to Web4Record
                    let web4_record = Self::domain_record_to_web4(record);
                    Ok(web4_record)
                } else {
                    Err(ZdnsError::DomainNotFound(domain.to_string()))
                }
            }
            Ok(_) => {
                Err(ZdnsError::DomainNotFound(domain.to_string()))
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "Registry lookup failed");
                Err(ZdnsError::RegistryError(e.to_string()))
            }
        }
    }

    /// Convert DomainRecord to Web4Record
    fn domain_record_to_web4(record: DomainRecord) -> Web4Record {
        // Extract owner as hex-encoded hash for privacy
        let owner = hex::encode(&record.owner.0[..16]);

        // Default TTL of 5 minutes (300 seconds)
        let ttl = 300u64;

        Web4Record {
            domain: record.domain,
            owner,
            content_mappings: record.content_mappings,
            content_mode: Some(ContentMode::Spa), // Default to SPA mode
            spa_entry: Some("index.html".to_string()),
            asset_prefixes: Some(vec![
                "/assets/".to_string(),
                "/static/".to_string(),
                "/js/".to_string(),
                "/css/".to_string(),
                "/images/".to_string(),
            ]),
            capability: Some(Web4Capability::SpaServe),
            ttl,
            registered_at: record.registered_at,
            expires_at: record.expires_at,
        }
    }

    /// Validate domain name format
    fn is_valid_domain(domain: &str) -> bool {
        // Must not be empty
        if domain.is_empty() {
            return false;
        }

        // Must not exceed 253 characters (DNS limit)
        if domain.len() > 253 {
            return false;
        }

        // Must contain only valid characters
        for c in domain.chars() {
            if !c.is_alphanumeric() && c != '-' && c != '.' && c != '_' {
                return false;
            }
        }

        // Must not start or end with hyphen or dot
        if domain.starts_with('-') || domain.starts_with('.')
            || domain.ends_with('-') || domain.ends_with('.') {
            return false;
        }

        // Must not have consecutive dots
        if domain.contains("..") {
            return false;
        }

        // Each label must not start or end with hyphen
        for label in domain.split('.') {
            if label.is_empty() {
                return false;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
            // Label must not exceed 63 characters
            if label.len() > 63 {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_domain() {
        // Valid domains
        assert!(ZdnsResolver::is_valid_domain("myapp.zhtp"));
        assert!(ZdnsResolver::is_valid_domain("my-app.zhtp"));
        assert!(ZdnsResolver::is_valid_domain("my_app.zhtp"));
        assert!(ZdnsResolver::is_valid_domain("app123.test.zhtp"));
        assert!(ZdnsResolver::is_valid_domain("a"));

        // Invalid domains
        assert!(!ZdnsResolver::is_valid_domain(""));
        assert!(!ZdnsResolver::is_valid_domain("-myapp.zhtp"));
        assert!(!ZdnsResolver::is_valid_domain("myapp-.zhtp"));
        assert!(!ZdnsResolver::is_valid_domain(".myapp.zhtp"));
        assert!(!ZdnsResolver::is_valid_domain("myapp.zhtp."));
        assert!(!ZdnsResolver::is_valid_domain("my..app.zhtp"));
        assert!(!ZdnsResolver::is_valid_domain("my app.zhtp")); // space
        assert!(!ZdnsResolver::is_valid_domain("myapp@zhtp")); // invalid char
    }

    #[test]
    fn test_cached_record_expiration() {
        // Create a cached record with 100ms TTL
        let cached = CachedRecord::negative(Duration::from_millis(100));
        assert!(!cached.is_expired());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));
        assert!(cached.is_expired());
    }

    #[test]
    fn test_resolver_metrics() {
        let mut metrics = ResolverMetrics::default();
        assert_eq!(metrics.hit_ratio(), 0.0);

        metrics.cache_hits = 80;
        metrics.cache_misses = 20;
        assert!((metrics.hit_ratio() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_web4_record_methods() {
        let record = Web4Record {
            domain: "test.zhtp".to_string(),
            owner: "abc123".to_string(),
            content_mappings: HashMap::new(),
            content_mode: None,
            spa_entry: None,
            asset_prefixes: None,
            capability: None,
            ttl: 300,
            registered_at: 0,
            expires_at: u64::MAX, // Far future
        };

        assert!(!record.has_content());
        assert!(!record.is_expired());
        assert_eq!(record.effective_content_mode(), ContentMode::Spa);
        assert_eq!(record.effective_capability(), Web4Capability::SpaServe);
    }
}
