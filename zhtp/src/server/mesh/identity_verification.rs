//! Identity Verification Module (MEDIUM-3 Security Fix)
//!
//! Implements blockchain identity verification before allowing message routing.
//! Ensures that only verified blockchain identities can route messages through the network.
//!
//! # Security Features
//!
//! 1. **Blockchain Identity Lookup**: Verify DIDs exist on-chain before routing
//! 2. **Cache with TTL**: Reduce blockchain lookups with verified identity cache
//! 3. **Bootstrap Mode Handling**: Allow limited routing for bootstrap peers
//! 4. **Audit Logging**: Track all verification attempts for security monitoring

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use lib_network::identity::unified_peer::UnifiedPeerId;

/// Global counter for identity verification attempts
static VERIFICATION_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
/// Global counter for verification cache hits
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
/// Global counter for verification failures
static VERIFICATION_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Get total verification attempts for monitoring
pub fn get_verification_attempt_count() -> u64 {
    VERIFICATION_ATTEMPTS.load(Ordering::Relaxed)
}

/// Get cache hit count for monitoring
pub fn get_cache_hit_count() -> u64 {
    CACHE_HITS.load(Ordering::Relaxed)
}

/// Get verification failure count for monitoring
pub fn get_verification_failure_count() -> u64 {
    VERIFICATION_FAILURES.load(Ordering::Relaxed)
}

/// Cached identity verification result
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// DID of the verified identity
    pub did: String,
    /// Whether identity exists on blockchain
    pub is_verified: bool,
    /// Whether identity is in bootstrap mode (limited access)
    pub is_bootstrap: bool,
    /// Trust score from blockchain (0.0 - 1.0)
    pub trust_score: f64,
    /// Time when verification was performed
    pub verified_at: u64,
    /// Time when cache entry expires
    pub expires_at: u64,
}

impl VerifiedIdentity {
    /// Check if cache entry is expired
    pub fn is_expired(&self) -> bool {
        current_timestamp() > self.expires_at
    }
}

/// Configuration for identity verification
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Cache TTL for verified identities (in seconds)
    pub cache_ttl_secs: u64,
    /// Cache TTL for unverified identities (in seconds) - shorter to re-check
    pub unverified_cache_ttl_secs: u64,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Allow routing for bootstrap peers (limited)
    pub allow_bootstrap_routing: bool,
    /// Minimum trust score required for full routing
    pub min_trust_score: f64,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: 300,            // 5 minutes for verified
            unverified_cache_ttl_secs: 60,  // 1 minute for unverified (re-check sooner)
            max_cache_size: 10_000,
            allow_bootstrap_routing: true,   // Allow limited bootstrap routing
            min_trust_score: 0.3,           // Minimum trust for full routing
        }
    }
}

/// Identity verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Identity verified on blockchain - full routing allowed
    Verified,
    /// Identity in bootstrap mode - limited routing only
    Bootstrap,
    /// Identity not found on blockchain - routing denied
    NotFound,
    /// Identity has insufficient trust score - routing denied
    InsufficientTrust,
    /// Identity is explicitly blocked
    Blocked,
}

impl VerificationResult {
    /// Check if routing should be allowed
    pub fn allows_routing(&self) -> bool {
        matches!(self, VerificationResult::Verified | VerificationResult::Bootstrap)
    }

    /// Check if this is full access (not bootstrap)
    pub fn is_full_access(&self) -> bool {
        matches!(self, VerificationResult::Verified)
    }
}

/// Identity verification cache for MEDIUM-3 fix
pub struct IdentityVerificationCache {
    /// Cached verification results by DID
    cache: RwLock<HashMap<String, VerifiedIdentity>>,
    /// Configuration
    config: VerificationConfig,
}

impl IdentityVerificationCache {
    /// Create a new verification cache with default configuration
    pub fn new() -> Self {
        Self::with_config(VerificationConfig::default())
    }

    /// Create a new verification cache with custom configuration
    pub fn with_config(config: VerificationConfig) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Verify an identity for routing
    ///
    /// # Security (MEDIUM-3 Fix)
    ///
    /// This method:
    /// 1. Checks cache first (O(1) lookup)
    /// 2. If not cached, performs blockchain lookup
    /// 3. Caches result with appropriate TTL
    /// 4. Returns verification result for routing decision
    pub async fn verify_identity(
        &self,
        peer: &UnifiedPeerId,
        blockchain_lookup: impl FnOnce(&str) -> Option<f64>,
    ) -> VerificationResult {
        VERIFICATION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        let did = peer.did();

        debug!("🔍 Verifying identity for routing: {}", did);

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(did) {
                if !cached.is_expired() {
                    CACHE_HITS.fetch_add(1, Ordering::Relaxed);
                    debug!("✅ Cache hit for {}: verified={}, bootstrap={}",
                           did, cached.is_verified, cached.is_bootstrap);
                    return self.cached_to_result(cached);
                }
            }
        }

        // MEDIUM-3 FIX: Check if using unverified DID marker from CRITICAL-1 fix
        if did.contains(":unverified:") {
            warn!("⚠️ Peer {} has unverified DID marker - bootstrap mode only", did);

            // Cache as bootstrap mode
            let verified = VerifiedIdentity {
                did: did.to_string(),
                is_verified: false,
                is_bootstrap: true,
                trust_score: 0.5,
                verified_at: current_timestamp(),
                expires_at: current_timestamp() + self.config.unverified_cache_ttl_secs,
            };
            self.cache_entry(verified.clone()).await;

            if self.config.allow_bootstrap_routing {
                return VerificationResult::Bootstrap;
            } else {
                VERIFICATION_FAILURES.fetch_add(1, Ordering::Relaxed);
                return VerificationResult::NotFound;
            }
        }

        // Perform blockchain lookup
        let trust_score = blockchain_lookup(did);

        let result = match trust_score {
            Some(score) if score >= self.config.min_trust_score => {
                info!("✅ Identity {} verified on blockchain (trust: {:.2})", did, score);

                let verified = VerifiedIdentity {
                    did: did.to_string(),
                    is_verified: true,
                    is_bootstrap: false,
                    trust_score: score,
                    verified_at: current_timestamp(),
                    expires_at: current_timestamp() + self.config.cache_ttl_secs,
                };
                self.cache_entry(verified).await;

                VerificationResult::Verified
            }
            Some(score) => {
                warn!("⚠️ Identity {} has insufficient trust score: {:.2} < {:.2}",
                      did, score, self.config.min_trust_score);

                let verified = VerifiedIdentity {
                    did: did.to_string(),
                    is_verified: true,
                    is_bootstrap: true,
                    trust_score: score,
                    verified_at: current_timestamp(),
                    expires_at: current_timestamp() + self.config.unverified_cache_ttl_secs,
                };
                self.cache_entry(verified).await;

                VERIFICATION_FAILURES.fetch_add(1, Ordering::Relaxed);
                VerificationResult::InsufficientTrust
            }
            None => {
                warn!("❌ Identity {} not found on blockchain", did);

                let verified = VerifiedIdentity {
                    did: did.to_string(),
                    is_verified: false,
                    is_bootstrap: peer.is_bootstrap_mode(),
                    trust_score: 0.0,
                    verified_at: current_timestamp(),
                    expires_at: current_timestamp() + self.config.unverified_cache_ttl_secs,
                };
                self.cache_entry(verified).await;

                // Allow bootstrap routing if enabled
                if peer.is_bootstrap_mode() && self.config.allow_bootstrap_routing {
                    VerificationResult::Bootstrap
                } else {
                    VERIFICATION_FAILURES.fetch_add(1, Ordering::Relaxed);
                    VerificationResult::NotFound
                }
            }
        };

        result
    }

    /// Check if identity is verified (cache-only, no blockchain lookup)
    pub async fn is_cached_verified(&self, did: &str) -> Option<bool> {
        let cache = self.cache.read().await;
        cache.get(did)
            .filter(|c| !c.is_expired())
            .map(|c| c.is_verified)
    }

    /// Get verification stats
    pub async fn get_stats(&self) -> VerificationStats {
        let cache = self.cache.read().await;
        let now = current_timestamp();
        let expired = cache.values().filter(|v| v.is_expired()).count();

        VerificationStats {
            cached_identities: cache.len(),
            expired_entries: expired,
            total_verifications: get_verification_attempt_count(),
            cache_hits: get_cache_hit_count(),
            verification_failures: get_verification_failure_count(),
        }
    }

    /// Cleanup expired entries
    pub async fn cleanup(&self) {
        let now = current_timestamp();
        let mut cache = self.cache.write().await;
        let before = cache.len();
        cache.retain(|_, entry| entry.expires_at > now);
        let removed = before - cache.len();
        if removed > 0 {
            info!("🧹 Verification cache cleanup: removed {} expired entries", removed);
        }
    }

    /// Invalidate a specific identity (force re-verification)
    pub async fn invalidate(&self, did: &str) {
        let mut cache = self.cache.write().await;
        if cache.remove(did).is_some() {
            info!("🔄 Invalidated cache entry for {}", did);
        }
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        let count = cache.len();
        cache.clear();
        info!("🧹 Cleared {} verification cache entries", count);
    }

    // Helper: Convert cached entry to result
    fn cached_to_result(&self, cached: &VerifiedIdentity) -> VerificationResult {
        if !cached.is_verified && !cached.is_bootstrap {
            return VerificationResult::NotFound;
        }

        if cached.is_bootstrap {
            if self.config.allow_bootstrap_routing {
                return VerificationResult::Bootstrap;
            } else {
                return VerificationResult::NotFound;
            }
        }

        if cached.trust_score < self.config.min_trust_score {
            return VerificationResult::InsufficientTrust;
        }

        VerificationResult::Verified
    }

    // Helper: Cache an entry
    async fn cache_entry(&self, entry: VerifiedIdentity) {
        let mut cache = self.cache.write().await;

        // Enforce max cache size
        if cache.len() >= self.config.max_cache_size {
            // Remove oldest entry
            let oldest_did = cache.iter()
                .min_by_key(|(_, e)| e.verified_at)
                .map(|(did, _)| did.clone());
            if let Some(did) = oldest_did {
                cache.remove(&did);
            }
        }

        cache.insert(entry.did.clone(), entry);
    }
}

/// Verification statistics
#[derive(Debug, Clone)]
pub struct VerificationStats {
    pub cached_identities: usize,
    pub expired_entries: usize,
    pub total_verifications: u64,
    pub cache_hits: u64,
    pub verification_failures: u64,
}

/// Helper function to get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::PublicKey;

    fn create_test_peer(did_suffix: &str, bootstrap: bool) -> UnifiedPeerId {
        // Create a test peer with known DID
        let pk = PublicKey::new(vec![0u8; 32]);
        let mut peer = UnifiedPeerId::from_public_key_legacy(pk);
        // Note: In real code, you'd set the DID properly
        peer
    }

    #[tokio::test]
    async fn test_verification_cache_hit() {
        let cache = IdentityVerificationCache::new();

        // Pre-populate cache
        let entry = VerifiedIdentity {
            did: "did:zhtp:test123".to_string(),
            is_verified: true,
            is_bootstrap: false,
            trust_score: 0.9,
            verified_at: current_timestamp(),
            expires_at: current_timestamp() + 300,
        };
        cache.cache_entry(entry).await;

        // Check cache
        let result = cache.is_cached_verified("did:zhtp:test123").await;
        assert_eq!(result, Some(true));
    }

    #[tokio::test]
    async fn test_verification_cache_miss() {
        let cache = IdentityVerificationCache::new();

        let result = cache.is_cached_verified("did:zhtp:nonexistent").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_verification_expired() {
        let cache = IdentityVerificationCache::new();

        // Add expired entry
        let entry = VerifiedIdentity {
            did: "did:zhtp:expired".to_string(),
            is_verified: true,
            is_bootstrap: false,
            trust_score: 0.9,
            verified_at: current_timestamp() - 1000,
            expires_at: current_timestamp() - 500, // Already expired
        };
        cache.cache_entry(entry).await;

        // Should not return expired entry
        let result = cache.is_cached_verified("did:zhtp:expired").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_verification_result_allows_routing() {
        assert!(VerificationResult::Verified.allows_routing());
        assert!(VerificationResult::Bootstrap.allows_routing());
        assert!(!VerificationResult::NotFound.allows_routing());
        assert!(!VerificationResult::InsufficientTrust.allows_routing());
        assert!(!VerificationResult::Blocked.allows_routing());
    }

    #[tokio::test]
    async fn test_verification_result_full_access() {
        assert!(VerificationResult::Verified.is_full_access());
        assert!(!VerificationResult::Bootstrap.is_full_access());
        assert!(!VerificationResult::NotFound.is_full_access());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let cache = IdentityVerificationCache::new();

        // Add valid entry
        cache.cache_entry(VerifiedIdentity {
            did: "did:zhtp:valid".to_string(),
            is_verified: true,
            is_bootstrap: false,
            trust_score: 0.9,
            verified_at: current_timestamp(),
            expires_at: current_timestamp() + 300,
        }).await;

        // Add expired entry
        cache.cache_entry(VerifiedIdentity {
            did: "did:zhtp:expired".to_string(),
            is_verified: true,
            is_bootstrap: false,
            trust_score: 0.9,
            verified_at: current_timestamp() - 1000,
            expires_at: current_timestamp() - 500,
        }).await;

        // Cleanup
        cache.cleanup().await;

        // Valid should remain, expired should be gone
        assert!(cache.is_cached_verified("did:zhtp:valid").await.is_some());
        assert!(cache.is_cached_verified("did:zhtp:expired").await.is_none());
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = IdentityVerificationCache::new();

        // Add entry
        cache.cache_entry(VerifiedIdentity {
            did: "did:zhtp:toremove".to_string(),
            is_verified: true,
            is_bootstrap: false,
            trust_score: 0.9,
            verified_at: current_timestamp(),
            expires_at: current_timestamp() + 300,
        }).await;

        // Verify it exists
        assert!(cache.is_cached_verified("did:zhtp:toremove").await.is_some());

        // Invalidate
        cache.invalidate("did:zhtp:toremove").await;

        // Should be gone
        assert!(cache.is_cached_verified("did:zhtp:toremove").await.is_none());
    }
}
