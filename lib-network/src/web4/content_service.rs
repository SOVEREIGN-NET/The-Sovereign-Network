//! Web4 Content Service
//!
//! Single canonical internal API for retrieving and serving Web4 content.
//! This service handles:
//! - Path normalization (security-critical)
//! - SPA routing policy
//! - MIME type resolution
//! - Cache header generation
//!
//! # Security Model
//!
//! Path normalization MUST happen BEFORE:
//! 1. Asset detection (hashed filenames)
//! 2. Registry/DHT lookup
//! 3. Any file system operations
//!
//! This prevents path traversal attacks like `/../../../etc/passwd`.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::domain_registry::DomainRegistry;

// ZDNS types - available when storage-integration is enabled
#[cfg(feature = "storage-integration")]
use crate::zdns::{ZdnsResolver, Web4Record};

// Stub types when ZDNS is not available
#[cfg(not(feature = "storage-integration"))]
struct ZdnsResolver;

#[cfg(not(feature = "storage-integration"))]
impl ZdnsResolver {
    /// Stub method - ZDNS not available
    pub async fn resolve_web4(&self, _domain: &str) -> Result<Web4Record, std::fmt::Error> {
        Err(std::fmt::Error::default())
    }

    /// Stub method - ZDNS not available
    pub async fn invalidate(&self, _domain: &str) {
        // No-op
    }
}
#[cfg(not(feature = "storage-integration"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4Record {
    pub domain: String,
    pub owner: String,
    pub content_mappings: HashMap<String, String>,
    pub content_mode: Option<ContentMode>,
    pub spa_entry: Option<String>,
    pub asset_prefixes: Option<Vec<String>>,
    pub capability: Option<Web4Capability>,
    pub ttl: u32,
    pub registered_at: u64,
    pub expires_at: u64,
}

/// Content serving mode for a domain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ContentMode {
    /// Static file serving - 404 for missing files
    Static,
    /// SPA mode - fallback to index.html for navigation routes
    #[default]
    Spa,
}

/// Web4 capability level - determines what content types can be served
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Web4Capability {
    /// Full HTTP serving (HTML, JS, CSS, images, etc.)
    HttpServe,
    /// SPA serving with client-side routing support (default)
    #[default]
    SpaServe,
    /// Download only - no browser rendering (for data/binary content)
    DownloadOnly,
}

/// Service-level defaults for content serving
#[derive(Debug, Clone)]
pub struct Web4ContentDefaults {
    /// Default content mode
    pub content_mode: ContentMode,
    /// Default index document
    pub index_document: String,
    /// Default 404 document
    pub not_found_document: Option<String>,
    /// Default capability level
    pub capability: Web4Capability,
}

impl Default for Web4ContentDefaults {
    fn default() -> Self {
        Self {
            content_mode: ContentMode::Spa,
            index_document: "index.html".to_string(),
            not_found_document: Some("404.html".to_string()),
            capability: Web4Capability::SpaServe,
        }
    }
}

/// Domain-specific content configuration (overrides service defaults)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainContentConfig {
    /// Content mode override
    pub content_mode: Option<ContentMode>,
    /// Index document override
    pub index_document: Option<String>,
    /// Not found document override
    pub not_found_document: Option<String>,
    /// Capability override
    pub capability: Option<Web4Capability>,
    /// Custom headers for this domain
    pub custom_headers: HashMap<String, String>,
}

impl Default for DomainContentConfig {
    fn default() -> Self {
        Self {
            content_mode: None,
            index_document: None,
            not_found_document: None,
            capability: None,
            custom_headers: HashMap::new(),
        }
    }
}

/// Result of content retrieval
#[derive(Debug, Clone)]
pub struct ContentResult {
    /// The content bytes
    pub content: Vec<u8>,
    /// MIME type
    pub mime_type: String,
    /// Cache control header value
    pub cache_control: String,
    /// ETag header value (content hash)
    pub etag: Option<String>,
    /// Additional headers
    pub headers: HashMap<String, String>,
    /// Whether this is a fallback (SPA routing)
    pub is_fallback: bool,
}

/// Web4 Content Service - single canonical API for content retrieval
pub struct Web4ContentService {
    /// Domain registry for lookups
    registry: Arc<DomainRegistry>,
    /// Optional ZDNS resolver for cached domain lookups
    zdns_resolver: Option<Arc<ZdnsResolver>>,
    /// Service-level defaults
    defaults: Web4ContentDefaults,
    /// Domain-specific configurations (domain -> config)
    domain_configs: Arc<RwLock<HashMap<String, DomainContentConfig>>>,
}

impl Web4ContentService {
    /// Create a new content service with default configuration
    pub fn new(registry: Arc<DomainRegistry>) -> Self {
        Self {
            registry,
            zdns_resolver: None,
            defaults: Web4ContentDefaults::default(),
            domain_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with custom defaults
    pub fn with_defaults(registry: Arc<DomainRegistry>, defaults: Web4ContentDefaults) -> Self {
        Self {
            registry,
            zdns_resolver: None,
            defaults,
            domain_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with ZDNS resolver for cached domain lookups
    #[cfg(feature = "storage-integration")]
    pub fn with_zdns(
        registry: Arc<DomainRegistry>,
        zdns_resolver: Arc<ZdnsResolver>,
    ) -> Self {
        Self {
            registry,
            zdns_resolver: Some(zdns_resolver),
            defaults: Web4ContentDefaults::default(),
            domain_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with ZDNS resolver and custom defaults
    #[cfg(feature = "storage-integration")]
    pub fn with_zdns_and_defaults(
        registry: Arc<DomainRegistry>,
        zdns_resolver: Arc<ZdnsResolver>,
        defaults: Web4ContentDefaults,
    ) -> Self {
        Self {
            registry,
            zdns_resolver: Some(zdns_resolver),
            defaults,
            domain_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Disabled without storage-integration feature
    #[cfg(not(feature = "storage-integration"))]
    pub fn with_zdns(
        registry: Arc<DomainRegistry>,
        _zdns_resolver: Arc<ZdnsResolver>,
    ) -> Self {
        Self::new(registry)
    }

    /// Disabled without storage-integration feature
    #[cfg(not(feature = "storage-integration"))]
    pub fn with_zdns_and_defaults(
        registry: Arc<DomainRegistry>,
        _zdns_resolver: Arc<ZdnsResolver>,
        defaults: Web4ContentDefaults,
    ) -> Self {
        Self::with_defaults(registry, defaults)
    }

    /// Get reference to ZDNS resolver (if configured)
    pub fn zdns_resolver(&self) -> Option<&Arc<ZdnsResolver>> {
        self.zdns_resolver.as_ref()
    }

    /// Resolve domain metadata using ZDNS (cached) or registry (direct)
    ///
    /// Prefers ZDNS resolver if available for caching benefits.
    pub async fn resolve_domain(&self, domain: &str) -> Result<Web4Record> {
        if let Some(resolver) = &self.zdns_resolver {
            // Use ZDNS resolver for cached lookup
            resolver.resolve_web4(domain).await.map_err(|e| anyhow!("{}", e))
        } else {
            // Fall back to direct registry lookup
            let lookup = self.registry.lookup_domain(domain).await?;
            if lookup.found {
                if let Some(record) = lookup.record {
                    Ok(Web4Record {
                        domain: record.domain,
                        owner: hex::encode(&record.owner.0[..16]),
                        content_mappings: record.content_mappings,
                        content_mode: Some(ContentMode::Spa),
                        spa_entry: Some("index.html".to_string()),
                        asset_prefixes: Some(vec![
                            "/assets/".to_string(),
                            "/static/".to_string(),
                            "/js/".to_string(),
                            "/css/".to_string(),
                            "/images/".to_string(),
                        ]),
                        capability: Some(Web4Capability::SpaServe),
                        ttl: 300,
                        registered_at: record.registered_at,
                        expires_at: record.expires_at,
                    })
                } else {
                    Err(anyhow!("Domain not found: {}", domain))
                }
            } else {
                Err(anyhow!("Domain not found: {}", domain))
            }
        }
    }

    /// Invalidate ZDNS cache for a domain (call after publish/update)
    pub async fn invalidate_domain_cache(&self, domain: &str) {
        if let Some(resolver) = &self.zdns_resolver {
            resolver.invalidate(domain).await;
        }
    }

    /// Set domain-specific configuration
    pub async fn set_domain_config(&self, domain: &str, config: DomainContentConfig) {
        let mut configs = self.domain_configs.write().await;
        configs.insert(domain.to_string(), config);
    }

    /// Get effective content mode for a domain
    async fn get_content_mode(&self, domain: &str) -> ContentMode {
        let configs = self.domain_configs.read().await;
        configs
            .get(domain)
            .and_then(|c| c.content_mode)
            .unwrap_or(self.defaults.content_mode)
    }

    /// Get effective index document for a domain
    async fn get_index_document(&self, domain: &str) -> String {
        let configs = self.domain_configs.read().await;
        configs
            .get(domain)
            .and_then(|c| c.index_document.clone())
            .unwrap_or_else(|| self.defaults.index_document.clone())
    }

    /// Get effective capability for a domain
    async fn get_capability(&self, domain: &str) -> Web4Capability {
        let configs = self.domain_configs.read().await;
        configs
            .get(domain)
            .and_then(|c| c.capability)
            .unwrap_or(self.defaults.capability)
    }

    /// Normalize a path for security
    ///
    /// CRITICAL: This MUST be called BEFORE any asset detection or lookup.
    ///
    /// Rules:
    /// 1. Collapse multiple slashes: `//` -> `/`
    /// 2. Remove `.` segments: `/./` -> `/`
    /// 3. Resolve `..` segments safely (cannot escape root)
    /// 4. Ensure path starts with `/`
    /// 5. Remove trailing slash (except for root `/`)
    ///
    /// Returns `Err` if the path attempts to escape the root.
    pub fn normalize_path(path: &str) -> Result<String> {
        // Handle empty path
        if path.is_empty() {
            return Ok("/".to_string());
        }

        // Split into segments
        let mut segments: Vec<&str> = Vec::new();

        for segment in path.split('/') {
            match segment {
                "" | "." => {
                    // Skip empty segments (from // or .)
                    continue;
                }
                ".." => {
                    // Go up one level, but REJECT if trying to escape root
                    if segments.pop().is_none() {
                        // Attempting to go above root - this is a security violation
                        warn!(
                            "Path traversal attack blocked: attempted to escape root in path '{}'",
                            path
                        );
                        return Err(anyhow!(
                            "Path traversal rejected: cannot navigate above root"
                        ));
                    }
                }
                s => {
                    // URL decode the segment for safety check
                    let decoded = urlencoding::decode(s).unwrap_or_else(|_| s.into());

                    // Check for encoded traversal attempts
                    if decoded.contains("..") {
                        return Err(anyhow!("Path traversal attempt detected"));
                    }

                    segments.push(s);
                }
            }
        }

        // Build normalized path
        if segments.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(format!("/{}", segments.join("/")))
        }
    }

    /// Check if a path looks like a hashed asset (immutable)
    ///
    /// Hashed assets are files with content hashes in their names, e.g.:
    /// - `main.a1b2c3d4.js`
    /// - `styles.f5e6d7c8.css`
    /// - `chunk-abc123def456.js`
    pub fn is_hashed_asset(path: &str) -> bool {
        // Extract filename from path (handle empty segments from trailing /)
        let filename = path
            .rsplit('/')
            .find(|s| !s.is_empty())
            .unwrap_or(path);

        // Check for chunk-style names first: chunk-abc123def456.js or chunk-abc12345.js
        // These are common bundler output patterns (webpack, vite, etc.)
        if filename.starts_with("chunk-") || filename.starts_with("vendor-") {
            // Extract the part after the prefix and before the extension
            let without_prefix = if filename.starts_with("chunk-") {
                &filename[6..]
            } else {
                &filename[7..] // "vendor-" is 7 chars
            };

            // Get the hash part (before the extension)
            if let Some(hash_part) = without_prefix.split('.').next() {
                if hash_part.len() >= 8 && hash_part.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return true;
                }
            }
        }

        // Split by dots for standard name.hash.ext pattern
        let parts: Vec<&str> = filename.split('.').collect();

        // Need at least 3 parts: name.hash.ext
        if parts.len() < 3 {
            return false;
        }

        // Check for hash-like patterns in the parts
        // Common patterns:
        // - 8+ hex chars: a1b2c3d4
        // - base64-ish: abc123DEF
        for i in 1..parts.len() - 1 {
            let part = parts[i];
            // Check if this looks like a hash (8+ alphanumeric chars)
            if part.len() >= 8 && part.chars().all(|c| c.is_ascii_alphanumeric()) {
                return true;
            }
        }

        false
    }

    /// Determine MIME type from path
    ///
    /// Uses file extension to determine content type.
    /// Falls back to `application/octet-stream` for unknown types.
    pub fn mime_for_path(path: &str) -> String {
        let extension = path
            .rsplit('.')
            .next()
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        match extension.as_str() {
            // HTML
            "html" | "htm" => "text/html; charset=utf-8".to_string(),

            // JavaScript - using application/javascript per plan
            "js" | "mjs" => "application/javascript; charset=utf-8".to_string(),

            // CSS
            "css" => "text/css; charset=utf-8".to_string(),

            // JSON
            "json" => "application/json; charset=utf-8".to_string(),

            // Images
            "png" => "image/png".to_string(),
            "jpg" | "jpeg" => "image/jpeg".to_string(),
            "gif" => "image/gif".to_string(),
            "webp" => "image/webp".to_string(),
            "svg" => "image/svg+xml".to_string(),
            "ico" => "image/x-icon".to_string(),
            "avif" => "image/avif".to_string(),

            // Fonts
            "woff" => "font/woff".to_string(),
            "woff2" => "font/woff2".to_string(),
            "ttf" => "font/ttf".to_string(),
            "otf" => "font/otf".to_string(),
            "eot" => "application/vnd.ms-fontobject".to_string(),

            // Documents
            "pdf" => "application/pdf".to_string(),
            "xml" => "application/xml; charset=utf-8".to_string(),
            "txt" => "text/plain; charset=utf-8".to_string(),
            "md" => "text/markdown; charset=utf-8".to_string(),

            // Media
            "mp3" => "audio/mpeg".to_string(),
            "mp4" => "video/mp4".to_string(),
            "webm" => "video/webm".to_string(),
            "ogg" => "audio/ogg".to_string(),
            "wav" => "audio/wav".to_string(),

            // Data
            "wasm" => "application/wasm".to_string(),
            "map" => "application/json".to_string(), // Source maps

            // Web manifest
            "webmanifest" => "application/manifest+json".to_string(),

            // Default
            _ => "application/octet-stream".to_string(),
        }
    }

    /// Generate cache control header based on content type and path
    ///
    /// Rules:
    /// - Hashed assets: `public, max-age=31536000, immutable`
    /// - HTML/index: `no-store` (for SPA, always fetch fresh)
    /// - Other static: `public, max-age=3600`
    pub fn cache_control_for(path: &str, mime_type: &str, is_index: bool) -> String {
        // SPA entry points should never be cached
        if is_index || mime_type.starts_with("text/html") {
            return "no-store".to_string();
        }

        // Hashed assets are immutable
        if Self::is_hashed_asset(path) {
            return "public, max-age=31536000, immutable".to_string();
        }

        // Other static assets get moderate caching
        "public, max-age=3600".to_string()
    }

    /// Check if a path looks like an asset (has file extension)
    fn has_file_extension(path: &str) -> bool {
        let filename = path.rsplit('/').next().unwrap_or(path);
        // Must have a dot and extension after it
        if let Some(dot_pos) = filename.rfind('.') {
            // Extension must be at least 1 char and not at the start
            dot_pos > 0 && dot_pos < filename.len() - 1
        } else {
            false
        }
    }

    /// Check if a path looks like a navigation route (not an asset)
    ///
    /// Navigation routes are paths that don't have file extensions,
    /// like `/about`, `/users/123`, `/settings`.
    fn is_navigation_route(path: &str) -> bool {
        !Self::has_file_extension(path)
    }

    /// Serve content for a domain and path
    ///
    /// This is the main entry point for content retrieval.
    ///
    /// Flow:
    /// 1. Normalize path (SECURITY CRITICAL - must be first!)
    /// 2. Resolve domain via ZDNS (cached) to validate and get config
    /// 3. Check if path is index/directory
    /// 4. Try to fetch content from registry
    /// 5. If not found and SPA mode, apply fallback logic
    /// 6. Return content with appropriate headers
    pub async fn serve(&self, domain: &str, path: &str) -> Result<ContentResult> {
        // STEP 1: Normalize path FIRST (security critical!)
        let normalized_path = Self::normalize_path(path)?;
        debug!("Normalized path: '{}' -> '{}'", path, normalized_path);

        // STEP 2: Resolve domain via ZDNS resolver (uses cache if available)
        // This validates the domain exists and gets its configuration
        let (content_mode, index_doc, capability) = if let Some(resolver) = &self.zdns_resolver {
            // Use ZDNS resolver for cached lookup
            match resolver.resolve_web4(domain).await {
                Ok(record) => {
                    let mode = record.content_mode.unwrap_or(self.defaults.content_mode);
                    let index = record.spa_entry.unwrap_or_else(|| self.defaults.index_document.clone());
                    let cap = record.capability.unwrap_or(self.defaults.capability);
                    (mode, index, cap)
                }
                Err(e) => {
                    warn!(domain = %domain, error = %e, "ZDNS resolution failed");
                    return Err(anyhow!("Domain not found: {}", domain));
                }
            }
        } else {
            // Fall back to domain_configs and defaults (no ZDNS resolver)
            let mode = self.get_content_mode(domain).await;
            let index = self.get_index_document(domain).await;
            let cap = self.get_capability(domain).await;
            (mode, index, cap)
        };

        // Check capability
        if capability == Web4Capability::DownloadOnly {
            // For download-only domains, we don't serve HTML
            let mime = Self::mime_for_path(&normalized_path);
            if mime.starts_with("text/html") {
                return Err(anyhow!("Domain is download-only, HTML serving disabled"));
            }
        }

        // STEP 3: Determine effective path
        let effective_path = if normalized_path == "/" {
            // Root path -> index document
            format!("/{}", index_doc)
        } else if normalized_path.ends_with('/') {
            // Directory path -> index document in that directory
            format!("{}{}", normalized_path, index_doc)
        } else {
            normalized_path.clone()
        };

        // STEP 4: Try to fetch content
        let is_index = effective_path.ends_with(&index_doc);

        match self.fetch_content(domain, &effective_path).await {
            Ok(content) => {
                // Content found
                let mime_type = Self::mime_for_path(&effective_path);
                let cache_control = Self::cache_control_for(&effective_path, &mime_type, is_index);
                let etag = Some(Self::compute_etag(&content));

                Ok(ContentResult {
                    content,
                    mime_type,
                    cache_control,
                    etag,
                    headers: HashMap::new(),
                    is_fallback: false,
                })
            }
            Err(_) => {
                // Content not found - apply SPA fallback logic
                self.handle_not_found(domain, &normalized_path, content_mode, &index_doc)
                    .await
            }
        }
    }

    /// Handle not-found case with SPA fallback logic
    async fn handle_not_found(
        &self,
        domain: &str,
        normalized_path: &str,
        content_mode: ContentMode,
        index_doc: &str,
    ) -> Result<ContentResult> {
        match content_mode {
            ContentMode::Static => {
                // Static mode: 404 for missing files
                Err(anyhow!("Content not found: {}", normalized_path))
            }
            ContentMode::Spa => {
                // SPA mode: fallback logic

                // Rule: Files with extensions return 404 (they're missing assets)
                if Self::has_file_extension(normalized_path) {
                    return Err(anyhow!(
                        "Asset not found: {} (SPA fallback only applies to navigation routes)",
                        normalized_path
                    ));
                }

                // Navigation route -> fallback to index.html
                info!(
                    "SPA fallback: '{}' -> '/{}'",
                    normalized_path, index_doc
                );

                let index_path = format!("/{}", index_doc);
                match self.fetch_content(domain, &index_path).await {
                    Ok(content) => {
                        let mime_type = Self::mime_for_path(&index_path);
                        let cache_control = Self::cache_control_for(&index_path, &mime_type, true);
                        let etag = Some(Self::compute_etag(&content));

                        Ok(ContentResult {
                            content,
                            mime_type,
                            cache_control,
                            etag,
                            headers: HashMap::new(),
                            is_fallback: true,
                        })
                    }
                    Err(e) => {
                        Err(anyhow!(
                            "SPA fallback failed: index document not found ({})",
                            e
                        ))
                    }
                }
            }
        }
    }

    /// Fetch content from the registry/DHT
    async fn fetch_content(&self, domain: &str, path: &str) -> Result<Vec<u8>> {
        // Strip leading slash for registry lookup
        let lookup_path = path.strip_prefix('/').unwrap_or(path);

        // Try to get content from domain
        self.registry.get_domain_content(domain, &format!("/{}", lookup_path)).await
    }

    /// Compute ETag from content
    fn compute_etag(content: &[u8]) -> String {
        let hash = lib_crypto::hash_blake3(content);
        format!("\"{}\"", hex::encode(&hash[..16])) // Use first 16 bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // Path Normalization Tests (Security Critical!)
    // ========================================

    #[test]
    fn test_normalize_path_basic() {
        assert_eq!(Web4ContentService::normalize_path("/").unwrap(), "/");
        assert_eq!(Web4ContentService::normalize_path("/foo").unwrap(), "/foo");
        assert_eq!(Web4ContentService::normalize_path("/foo/bar").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_normalize_path_empty() {
        assert_eq!(Web4ContentService::normalize_path("").unwrap(), "/");
    }

    #[test]
    fn test_normalize_path_double_slashes() {
        assert_eq!(Web4ContentService::normalize_path("//").unwrap(), "/");
        assert_eq!(Web4ContentService::normalize_path("/foo//bar").unwrap(), "/foo/bar");
        assert_eq!(Web4ContentService::normalize_path("///foo///bar///").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_normalize_path_dot_segments() {
        assert_eq!(Web4ContentService::normalize_path("/./foo").unwrap(), "/foo");
        assert_eq!(Web4ContentService::normalize_path("/foo/./bar").unwrap(), "/foo/bar");
        assert_eq!(Web4ContentService::normalize_path("/./").unwrap(), "/");
    }

    #[test]
    fn test_normalize_path_dotdot_safe() {
        // Should resolve .. within bounds
        assert_eq!(Web4ContentService::normalize_path("/foo/bar/../baz").unwrap(), "/foo/baz");
        assert_eq!(Web4ContentService::normalize_path("/foo/../bar").unwrap(), "/bar");
    }

    #[test]
    fn test_normalize_path_dotdot_escape_rejected() {
        // Any attempt to escape root MUST return an error
        assert!(Web4ContentService::normalize_path("/..").is_err());
        assert!(Web4ContentService::normalize_path("/../..").is_err());
        assert!(Web4ContentService::normalize_path("/../../../etc/passwd").is_err());
        assert!(Web4ContentService::normalize_path("/foo/../../bar").is_err());

        // The key security property: we reject paths that attempt to escape root
        // This prevents path traversal attacks like accessing /etc/passwd
    }

    #[test]
    fn test_normalize_path_encoded_traversal() {
        // URL-encoded .. should be detected
        assert!(Web4ContentService::normalize_path("/%2e%2e").is_err());
        assert!(Web4ContentService::normalize_path("/%2e%2e/etc/passwd").is_err());
    }

    #[test]
    fn test_normalize_path_mixed_attacks() {
        // Combined attack patterns
        assert_eq!(
            Web4ContentService::normalize_path("/foo/./bar/../baz//qux").unwrap(),
            "/foo/baz/qux"
        );
    }

    // ========================================
    // Hashed Asset Detection Tests
    // ========================================

    #[test]
    fn test_is_hashed_asset_true() {
        assert!(Web4ContentService::is_hashed_asset("/main.a1b2c3d4.js"));
        assert!(Web4ContentService::is_hashed_asset("/styles.f5e6d7c8.css"));
        assert!(Web4ContentService::is_hashed_asset("/assets/main.abcd1234.js"));
        assert!(Web4ContentService::is_hashed_asset("/chunk-abc12345.js"));
        assert!(Web4ContentService::is_hashed_asset("/vendor-xyz98765.js"));
    }

    #[test]
    fn test_is_hashed_asset_false() {
        assert!(!Web4ContentService::is_hashed_asset("/index.html"));
        assert!(!Web4ContentService::is_hashed_asset("/main.js"));
        assert!(!Web4ContentService::is_hashed_asset("/styles.css"));
        assert!(!Web4ContentService::is_hashed_asset("/about"));
        assert!(!Web4ContentService::is_hashed_asset("/"));
    }

    // ========================================
    // MIME Type Tests
    // ========================================

    #[test]
    fn test_mime_for_path() {
        assert!(Web4ContentService::mime_for_path("/index.html").starts_with("text/html"));
        assert!(Web4ContentService::mime_for_path("/main.js").starts_with("application/javascript"));
        assert!(Web4ContentService::mime_for_path("/styles.css").starts_with("text/css"));
        assert!(Web4ContentService::mime_for_path("/data.json").starts_with("application/json"));
        assert!(Web4ContentService::mime_for_path("/image.png").starts_with("image/png"));
        assert!(Web4ContentService::mime_for_path("/font.woff2").starts_with("font/woff2"));
    }

    #[test]
    fn test_mime_unknown_extension() {
        assert_eq!(
            Web4ContentService::mime_for_path("/file.xyz"),
            "application/octet-stream"
        );
    }

    // ========================================
    // Cache Control Tests
    // ========================================

    #[test]
    fn test_cache_control_index() {
        assert_eq!(
            Web4ContentService::cache_control_for("/index.html", "text/html", true),
            "no-store"
        );
    }

    #[test]
    fn test_cache_control_html() {
        assert_eq!(
            Web4ContentService::cache_control_for("/about.html", "text/html", false),
            "no-store"
        );
    }

    #[test]
    fn test_cache_control_hashed_asset() {
        assert_eq!(
            Web4ContentService::cache_control_for("/main.a1b2c3d4.js", "application/javascript", false),
            "public, max-age=31536000, immutable"
        );
    }

    #[test]
    fn test_cache_control_regular_asset() {
        assert_eq!(
            Web4ContentService::cache_control_for("/main.js", "application/javascript", false),
            "public, max-age=3600"
        );
    }

    // ========================================
    // Navigation Route Detection Tests
    // ========================================

    #[test]
    fn test_is_navigation_route() {
        // Navigation routes (no extension)
        assert!(Web4ContentService::is_navigation_route("/about"));
        assert!(Web4ContentService::is_navigation_route("/users/123"));
        assert!(Web4ContentService::is_navigation_route("/settings"));
        assert!(Web4ContentService::is_navigation_route("/"));

        // Asset paths (have extension)
        assert!(!Web4ContentService::is_navigation_route("/main.js"));
        assert!(!Web4ContentService::is_navigation_route("/styles.css"));
        assert!(!Web4ContentService::is_navigation_route("/image.png"));
    }

    #[test]
    fn test_has_file_extension() {
        assert!(Web4ContentService::has_file_extension("/main.js"));
        assert!(Web4ContentService::has_file_extension("/index.html"));
        assert!(!Web4ContentService::has_file_extension("/about"));
        assert!(!Web4ContentService::has_file_extension("/users/123"));
        assert!(!Web4ContentService::has_file_extension("/.hidden")); // Dot at start, no extension
    }
}
