//! Verification cache for identity verification results

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, Instant};

/// Verification cache for storing and retrieving verification results
#[derive(Debug, Clone)]
pub struct VerificationCache {
    /// Cached verification results
    cache: HashMap<String, CachedVerificationEntry>,
    /// Cache statistics
    stats: CacheStatistics,
    /// Cache configuration
    config: CacheConfig,
}

/// Cached verification entry
#[derive(Debug, Clone)]
pub struct CachedVerificationEntry {
    pub cache_key: String,
    pub verification_result: CachedVerificationResult,
    pub cached_at: Instant,
    pub expires_at: Instant,
    pub access_count: u32,
    pub last_accessed: Instant,
    pub verification_type: String,
    pub identity_id: String,
}

/// Cached verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVerificationResult {
    pub verified: bool,
    pub verification_level: String,
    pub trust_score: f64,
    pub verification_methods: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub verified_at: u64,
    pub expires_at: u64,
    pub issuer: String,
    pub confidence: f64,
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStatistics {
    pub total_entries: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
    pub total_lookups: u64,
    pub hit_rate: f64,
    pub average_access_time_ms: f64,
    pub last_cleanup: Instant,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub default_ttl_minutes: u32,
    pub cleanup_interval_minutes: u32,
    pub enable_lru_eviction: bool,
    pub enable_metrics: bool,
    pub compress_entries: bool,
}

/// Cache lookup result
#[derive(Debug, Clone)]
pub enum CacheLookupResult {
    Hit(CachedVerificationResult),
    Miss,
    Expired(CachedVerificationResult),
}

impl VerificationCache {
    /// Create new verification cache
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            stats: CacheStatistics {
                total_entries: 0,
                cache_hits: 0,
                cache_misses: 0,
                evictions: 0,
                total_lookups: 0,
                hit_rate: 0.0,
                average_access_time_ms: 0.0,
                last_cleanup: Instant::now(),
            },
            config: CacheConfig::default(),
        }
    }

    /// Create new cache with custom configuration
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            cache: HashMap::new(),
            stats: CacheStatistics {
                total_entries: 0,
                cache_hits: 0,
                cache_misses: 0,
                evictions: 0,
                total_lookups: 0,
                hit_rate: 0.0,
                average_access_time_ms: 0.0,
                last_cleanup: Instant::now(),
            },
            config,
        }
    }

    /// Store verification result in cache
    pub fn store(
        &mut self,
        identity_id: &str,
        verification_type: &str,
        result: CachedVerificationResult,
        ttl_minutes: Option<u32>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Generate cache key
        let cache_key = self.generate_cache_key(identity_id, verification_type, &result);
        
        // Check if cache is full and evict if necessary
        if self.cache.len() >= self.config.max_entries {
            self.evict_entries()?;
        }

        // Calculate expiration time
        let ttl = ttl_minutes.unwrap_or(self.config.default_ttl_minutes);
        let expires_at = Instant::now() + Duration::from_secs(ttl as u64 * 60);

        // Create cache entry
        let entry = CachedVerificationEntry {
            cache_key: cache_key.clone(),
            verification_result: result,
            cached_at: Instant::now(),
            expires_at,
            access_count: 0,
            last_accessed: Instant::now(),
            verification_type: verification_type.to_string(),
            identity_id: identity_id.to_string(),
        };

        // Store in cache
        self.cache.insert(cache_key.clone(), entry);
        self.stats.total_entries = self.cache.len();

        println!(" Stored verification result in cache: {} (expires in {} minutes)", cache_key, ttl);
        Ok(cache_key)
    }

    /// Retrieve verification result from cache
    pub fn get(
        &mut self,
        identity_id: &str,
        verification_type: &str,
    ) -> CacheLookupResult {
        let start_time = Instant::now();
        self.stats.total_lookups += 1;

        // Generate lookup key (simplified - would use more sophisticated matching)
        let _lookup_key = format!("{}:{}", identity_id, verification_type);
        
        // Find matching cache entry
        let mut matching_key = None;
        for (key, entry) in &self.cache {
            if entry.identity_id == identity_id && entry.verification_type == verification_type {
                matching_key = Some(key.clone());
                break;
            }
        }

        let result = if let Some(key) = matching_key {
            if let Some(entry) = self.cache.get_mut(&key) {
                // Check if entry is expired
                if Instant::now() > entry.expires_at {
                    let expired_result = entry.verification_result.clone();
                    self.cache.remove(&key);
                    self.stats.total_entries = self.cache.len();
                    CacheLookupResult::Expired(expired_result)
                } else {
                    // Update access statistics
                    entry.access_count += 1;
                    entry.last_accessed = Instant::now();
                    
                    self.stats.cache_hits += 1;
                    CacheLookupResult::Hit(entry.verification_result.clone())
                }
            } else {
                self.stats.cache_misses += 1;
                CacheLookupResult::Miss
            }
        } else {
            self.stats.cache_misses += 1;
            CacheLookupResult::Miss
        };

        // Update metrics
        let access_time = start_time.elapsed().as_millis() as f64;
        self.update_access_metrics(access_time);

        result
    }

    /// Generate cache key for verification result
    fn generate_cache_key(
        &self,
        identity_id: &str,
        verification_type: &str,
        result: &CachedVerificationResult,
    ) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(identity_id.as_bytes());
        hasher.update(verification_type.as_bytes());
        hasher.update(result.verification_level.as_bytes());
        hasher.update(result.verified_at.to_string().as_bytes());
        
        // Include verification methods in key
        for method in &result.verification_methods {
            hasher.update(method.as_bytes());
        }
        
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// Evict entries from cache when full
    fn evict_entries(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.enable_lru_eviction {
            return Err("Cache full and LRU eviction disabled".into());
        }

        // Find oldest entries to evict (evict 25% of cache)
        let evict_count = self.config.max_entries / 4;
        let mut entries_by_access: Vec<_> = self.cache.iter()
            .map(|(key, entry)| (key.clone(), entry.last_accessed))
            .collect();
        
        // Sort by last accessed time (oldest first)
        entries_by_access.sort_by_key(|(_, last_accessed)| *last_accessed);
        
        // Evict oldest entries
        for (key, _) in entries_by_access.iter().take(evict_count) {
            self.cache.remove(key);
            self.stats.evictions += 1;
        }

        self.stats.total_entries = self.cache.len();
        println!(" Evicted {} cache entries", evict_count);
        
        Ok(())
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) -> usize {
        let current_time = Instant::now();
        let mut expired_keys = Vec::new();
        
        for (key, entry) in &self.cache {
            if current_time > entry.expires_at {
                expired_keys.push(key.clone());
            }
        }
        
        let expired_count = expired_keys.len();
        for key in expired_keys {
            self.cache.remove(&key);
        }
        
        self.stats.total_entries = self.cache.len();
        self.stats.last_cleanup = current_time;
        
        if expired_count > 0 {
            println!(" Cleaned up {} expired cache entries", expired_count);
        }
        
        expired_count
    }

    /// Clear all cache entries
    pub fn clear(&mut self) {
        let cleared_count = self.cache.len();
        self.cache.clear();
        self.stats.total_entries = 0;
        println!(" Cleared {} cache entries", cleared_count);
    }

    /// Get cache statistics
    pub fn get_statistics(&mut self) -> CacheStatistics {
        // Update hit rate
        if self.stats.total_lookups > 0 {
            self.stats.hit_rate = self.stats.cache_hits as f64 / self.stats.total_lookups as f64;
        }
        
        self.stats.clone()
    }

    /// Update access time metrics
    fn update_access_metrics(&mut self, access_time_ms: f64) {
        if self.config.enable_metrics {
            let total_lookups = self.stats.total_lookups as f64;
            self.stats.average_access_time_ms = 
                (self.stats.average_access_time_ms * (total_lookups - 1.0) + access_time_ms) / total_lookups;
        }
    }

    /// Get cache configuration
    pub fn get_config(&self) -> &CacheConfig {
        &self.config
    }

    /// Update cache configuration
    pub fn update_config(&mut self, new_config: CacheConfig) {
        self.config = new_config;
        
        // If max entries reduced, evict excess entries
        if self.cache.len() > self.config.max_entries {
            let _ = self.evict_entries();
        }
    }

    /// Get entries by identity
    pub fn get_entries_for_identity(&self, identity_id: &str) -> Vec<&CachedVerificationEntry> {
        self.cache.values()
            .filter(|entry| entry.identity_id == identity_id)
            .collect()
    }

    /// Get entries by verification type
    pub fn get_entries_by_type(&self, verification_type: &str) -> Vec<&CachedVerificationEntry> {
        self.cache.values()
            .filter(|entry| entry.verification_type == verification_type)
            .collect()
    }

    /// Remove entries for specific identity
    pub fn remove_identity_entries(&mut self, identity_id: &str) -> usize {
        let keys_to_remove: Vec<_> = self.cache.iter()
            .filter(|(_, entry)| entry.identity_id == identity_id)
            .map(|(key, _)| key.clone())
            .collect();
        
        let removed_count = keys_to_remove.len();
        for key in keys_to_remove {
            self.cache.remove(&key);
        }
        
        self.stats.total_entries = self.cache.len();
        
        if removed_count > 0 {
            println!(" Removed {} cache entries for identity {}", removed_count, identity_id);
        }
        
        removed_count
    }

    /// Get cache memory usage estimate
    pub fn get_memory_usage_estimate(&self) -> usize {
        // Rough estimate of memory usage
        let mut total_size = 0;
        
        for (key, entry) in &self.cache {
            total_size += key.len();
            total_size += entry.cache_key.len();
            total_size += entry.verification_type.len();
            total_size += entry.identity_id.len();
            total_size += std::mem::size_of::<CachedVerificationEntry>();
            
            // Estimate verification result size
            total_size += serde_json::to_string(&entry.verification_result)
                .unwrap_or_default().len();
        }
        
        total_size
    }

    /// Check if automatic cleanup is needed
    pub fn should_cleanup(&self) -> bool {
        let cleanup_interval = Duration::from_secs(self.config.cleanup_interval_minutes as u64 * 60);
        Instant::now() - self.stats.last_cleanup > cleanup_interval
    }

    /// Perform automatic maintenance
    pub async fn perform_maintenance(&mut self) {
        if self.should_cleanup() {
            self.cleanup_expired();
        }
        
        // Additional maintenance tasks could be added here
        // e.g., compacting cache, updating statistics, etc.
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            default_ttl_minutes: 60,
            cleanup_interval_minutes: 15,
            enable_lru_eviction: true,
            enable_metrics: true,
            compress_entries: false,
        }
    }
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new()
    }
}
