# Web4 Gateway Implementation Plan

## Current State Analysis

### What EXISTS (Ready to Use)

| Component | Location | Status |
|-----------|----------|--------|
| `DomainRegistry` | `lib-network/src/web4/domain_registry.rs` | ✅ Complete |
| `DomainRecord` | `lib-network/src/web4/types.rs` | ✅ Complete |
| `ContentPublisher` | `lib-network/src/web4/content_publisher.rs` | ✅ Complete |
| `Web4Manager` | `lib-network/src/web4/domain_registry.rs` | ✅ Complete |
| `Web4Handler` (API) | `zhtp/src/api/handlers/web4/mod.rs` | ✅ Partial |
| `DnsHandler` | `zhtp/src/api/handlers/dns/mod.rs` | ✅ Resolution only |
| DHT content storage | `lib-storage` | ✅ Complete |
| Domain registration API | `/api/v1/web4/domains/*` | ✅ Complete |
| Content publish API | `/api/v1/web4/content/publish` | ✅ Complete |

### What's MISSING (Must Build)

| Component | Priority | Effort |
|-----------|----------|--------|
| `Web4ContentService` (unified retrieval API) | P0 | Medium |
| `normalize_path()` (security) | P0 | Small |
| SPA routing policy (`content_mode`) | P0 | Medium |
| `mime_for()` MIME detection | P0 | Small |
| Cache headers (immutable, no-store) | P0 | Small |
| `GET /api/v1/web4/content/{domain}/{path}` | P0 | Medium |
| Host-based gateway handler | P0 | Medium |
| ZDNS UDP/TCP transport (port 53) | P1 | Large |
| TLS strategy | P2 | Medium |

---

## Phase 0: Browser Access Model Decision

**Decision: Managed Gateway First (Phase 1)**

```
User visits: https://gateway.yourdomain.tld/myapp/
         or: Host: myapp.zhtp (with local /etc/hosts)

Gateway resolves Web4 domain → fetches content from DHT → serves to browser
```

Native `.zhtp` resolution (DNS on port 53) is Phase 3.

---

## Phase 1: Web4 HTTP Gateway Core

**Branch**: `feature/web4-http-gateway`

### 1.1 Create `Web4ContentService`

**Location**: `lib-network/src/web4/content_service.rs`

**Purpose**: Single canonical internal API for all content operations

**IMPORTANT**: The service does NOT own domain-specific config. It holds only global defaults.
Domain-specific behavior (content_mode, spa_entry, etc.) lives in `DomainRecord`.
Resolution always applies: `effective_config = domain_record overrides defaults`

```rust
/// Global defaults for domains that don't specify their own config
pub struct Web4ContentDefaults {
    pub content_mode: ContentMode,       // Default: Spa
    pub spa_entry: String,               // Default: "/index.html"
    pub asset_prefixes: Vec<String>,     // Default: ["/static/", "/assets/"]
    pub asset_extensions: Vec<String>,   // Default: ["js", "css", "png", ...]
}

impl Default for Web4ContentDefaults {
    fn default() -> Self {
        Self {
            content_mode: ContentMode::Spa,
            spa_entry: "/index.html".to_string(),
            asset_prefixes: vec!["/static/".into(), "/assets/".into()],
            asset_extensions: vec![
                "js", "css", "png", "jpg", "jpeg", "gif", "svg",
                "ico", "woff", "woff2", "ttf", "eot", "json", "map"
            ].into_iter().map(String::from).collect(),
        }
    }
}

pub struct Web4ContentService {
    domain_registry: Arc<DomainRegistry>,
    defaults: Web4ContentDefaults,  // NOT domain config - just fallback defaults
}

pub struct ContentResponse {
    pub body: Vec<u8>,
    pub content_type: String,
    pub cache_control: String,
    pub etag: Option<String>,
    pub content_encoding: Option<String>,
    pub status: u16,
}

impl Web4ContentService {
    /// Resolve and fetch content for a domain/path
    ///
    /// Resolution order:
    /// 1. Normalize path (security)
    /// 2. Lookup domain record
    /// 3. Merge domain config with defaults (domain wins)
    /// 4. Check is_static_asset AFTER normalization
    /// 5. Attempt exact path lookup
    /// 6. Apply SPA fallback if applicable
    pub async fn get_content(
        &self,
        domain: &str,
        path: &str,
        accept_encoding: Option<&str>,
    ) -> Result<ContentResponse, ContentError>;

    /// Get effective config for a domain (domain overrides defaults)
    async fn get_effective_config(&self, domain: &str) -> Result<EffectiveConfig, ContentError> {
        let domain_record = self.domain_registry.lookup_domain(domain).await?;

        Ok(EffectiveConfig {
            content_mode: domain_record.content_mode.unwrap_or(self.defaults.content_mode),
            spa_entry: domain_record.spa_entry.clone().unwrap_or(self.defaults.spa_entry.clone()),
            asset_prefixes: domain_record.asset_prefixes.clone()
                .unwrap_or(self.defaults.asset_prefixes.clone()),
            asset_extensions: domain_record.asset_extensions.clone()
                .unwrap_or(self.defaults.asset_extensions.clone()),
            capability: domain_record.capability.unwrap_or(Web4Capability::SpaServe),
        })
    }
}
```

**Implementation Tasks**:
- [ ] Create `lib-network/src/web4/content_service.rs`
- [ ] Implement `Web4ContentDefaults` with sane defaults
- [ ] Implement `get_effective_config()` with domain-overrides-defaults pattern
- [ ] Integrate with existing `DomainRegistry`
- [ ] Add path → content_hash resolution
- [ ] Add DHT content retrieval
- [ ] Add LZ4 decompression (content stored compressed)
- [ ] Add SPA fallback logic
- [ ] Add MIME type detection
- [ ] Add cache header generation
- [ ] Add ETag generation (blake3 hash)

---

### 1.2 Path Normalization

**Location**: `lib-network/src/web4/path.rs`

**CRITICAL RULE**: Normalization MUST be applied BEFORE registry lookup AND BEFORE asset detection.

```rust
pub fn normalize_path(path: &str) -> Result<String, PathError> {
    // 1. Enforce max length FIRST (4096 chars) - before any processing
    if path.len() > 4096 {
        return Err(PathError::TooLong);
    }

    // 2. URL decode (%2e → ., %2f → /)
    let decoded = percent_decode(path)?;

    // 3. Check for null bytes (after decode, before further processing)
    if decoded.contains('\0') {
        return Err(PathError::NullByte);
    }

    // 4. Validate UTF-8
    // (already valid if we got here from &str)

    // 5. Ensure leading /
    let with_leading = if decoded.starts_with('/') {
        decoded
    } else {
        format!("/{}", decoded)
    };

    // 6. Collapse // to /
    let collapsed = collapse_slashes(&with_leading);

    // 7. Resolve . and .. segments
    let resolved = resolve_dot_segments(&collapsed)?;

    // 8. REJECT if result escapes root (should never happen after proper resolution)
    if resolved.contains("..") {
        return Err(PathError::TraversalAttempt);
    }

    // 9. Convert empty result to /
    if resolved.is_empty() {
        return Ok("/".to_string());
    }

    Ok(resolved)
}

fn resolve_dot_segments(path: &str) -> Result<String, PathError> {
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                if segments.is_empty() {
                    // Attempting to go above root
                    return Err(PathError::TraversalAttempt);
                }
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    Ok(format!("/{}", segments.join("/")))
}

/// Check if path is a static asset
/// MUST be called AFTER normalize_path()
pub fn is_static_asset(normalized_path: &str, config: &EffectiveConfig) -> bool {
    // Check asset prefixes (/static/, /assets/)
    for prefix in &config.asset_prefixes {
        if normalized_path.starts_with(prefix) {
            return true;
        }
    }

    // Check file extensions
    if let Some(ext) = normalized_path.rsplit('.').next() {
        if config.asset_extensions.contains(&ext.to_lowercase()) {
            return true;
        }
    }

    false
}
```

**Security Requirements**:
- [ ] Prevent path traversal (`..`, `%2e%2e`, `%252e%252e`)
- [ ] Handle double URL encoding attacks
- [ ] No null byte injection (`%00`)
- [ ] Bounded path length (4096 chars)
- [ ] Reject invalid UTF-8
- [ ] **Normalization before asset detection** (critical)

**Tests Required**:
```rust
#[test] fn test_normalize_basic() { ... }
#[test] fn test_path_traversal_blocked() { ... }
#[test] fn test_double_encoded_traversal() { ... }
#[test] fn test_null_byte_rejected() { ... }
#[test] fn test_max_length_enforced() { ... }

// CRITICAL: This test ensures normalization happens before asset detection
#[test]
fn test_traversal_before_asset_check() {
    // These should NOT pass asset detection pre-normalization
    let malicious_paths = [
        "/static/../index.html",
        "%2fstatic%2f..%2findex.html",
        "/assets/../../../etc/passwd",
        "/static/..%2findex.html",
    ];

    for path in malicious_paths {
        // Normalize first (may error or resolve to something safe)
        let result = normalize_path(path);

        match result {
            Err(_) => {
                // Correctly rejected - pass
            }
            Ok(normalized) => {
                // If normalization succeeded, the path should NOT contain traversal
                assert!(!normalized.contains(".."),
                    "Normalized path still contains ..: {}", normalized);
                // And should NOT be treated as /static/* asset
                assert!(!normalized.starts_with("/static/../"),
                    "Traversal escaped asset prefix: {}", normalized);
            }
        }
    }
}
```

---

### 1.3 SPA Routing Policy

**Location**: `lib-network/src/web4/types.rs` (extend `DomainRecord`)

```rust
/// Content serving mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ContentMode {
    /// Static file serving - 404 for missing paths
    Static,
    /// SPA mode - fallback to spa_entry for non-assets
    #[default]
    Spa,
}

/// Domain capability - what this domain can be used for
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Web4Capability {
    /// Serve over HTTP as browseable website
    HttpServe,
    /// Serve as SPA with client-side routing (default)
    #[default]
    SpaServe,
    /// Download only - not browser-servable (APIs, blobs, datasets)
    DownloadOnly,
}

// Add to DomainRecord (all optional - fall back to service defaults)
pub struct DomainRecord {
    // ... existing fields ...

    /// Content serving mode (None = use service default)
    pub content_mode: Option<ContentMode>,
    /// SPA entry point (None = use service default "/index.html")
    pub spa_entry: Option<String>,
    /// Static asset path prefixes (None = use service default)
    pub asset_prefixes: Option<Vec<String>>,
    /// Static asset file extensions (None = use service default)
    pub asset_extensions: Option<Vec<String>>,
    /// Domain capability (None = use service default SpaServe)
    pub capability: Option<Web4Capability>,
}
```

**SPA Resolution Algorithm** (tightened edge case):

```rust
fn resolve_spa_fallback(
    normalized_path: &str,
    content_exists: bool,
    config: &EffectiveConfig,
) -> SpaResolution {
    // 1. If content exists at exact path, serve it
    if content_exists {
        return SpaResolution::ServeExact;
    }

    // 2. If static mode, always 404 for missing
    if config.content_mode == ContentMode::Static {
        return SpaResolution::NotFound;
    }

    // 3. If path is a static asset, 404 (don't mask broken asset refs)
    if is_static_asset(normalized_path, config) {
        return SpaResolution::NotFound;
    }

    // 4. TIGHTENED EDGE CASE:
    //    Only fallback if path does NOT have a file extension
    //    (unless it ends with / which is directory-like)
    //    - /images/logo.png missing → 404 (has extension)
    //    - /images/ missing → SPA fallback OK (directory-like)
    //    - /users/123 → SPA fallback OK (no extension)

    let filename = normalized_path.rsplit('/').next().unwrap_or("");
    let has_extension = filename.contains('.') && !filename.starts_with('.');
    let is_directory_like = normalized_path.ends_with('/');

    if has_extension && !is_directory_like {
        // Looks like a file request (has extension) - 404 to surface broken refs
        return SpaResolution::NotFound;
    }

    // 5. SPA fallback - serve spa_entry
    SpaResolution::FallbackToEntry(config.spa_entry.clone())
}

#[derive(Debug, PartialEq)]
enum SpaResolution {
    ServeExact,
    FallbackToEntry(String),
    NotFound,
}
```

**Test Cases**:
```rust
#[test]
fn test_spa_fallback_edge_cases() {
    let config = EffectiveConfig::default(); // SPA mode

    // Missing asset with extension → 404 (don't mask broken refs)
    assert_eq!(
        resolve_spa_fallback("/images/logo.png", false, &config),
        SpaResolution::NotFound
    );

    // Missing directory-like path → SPA fallback
    assert_eq!(
        resolve_spa_fallback("/images/", false, &config),
        SpaResolution::FallbackToEntry("/index.html".into())
    );

    // Missing route without extension → SPA fallback
    assert_eq!(
        resolve_spa_fallback("/users/123", false, &config),
        SpaResolution::FallbackToEntry("/index.html".into())
    );

    // Static asset path → 404 even without extension check
    assert_eq!(
        resolve_spa_fallback("/static/js/missing", false, &config),
        SpaResolution::NotFound
    );
}
```

---

### 1.4 MIME Type Resolution

**Location**: `lib-network/src/web4/mime.rs`

**IMPORTANT**: Use `application/javascript` for JS. Not `text/javascript`. Modern browsers are strict.

```rust
/// Get MIME type for a path based on file extension
///
/// CRITICAL: Do not change "application/javascript" to anything else.
/// Modern browsers are strict about this. This is one of the most common
/// "why does nothing load" failures.
pub fn mime_for_path(path: &str) -> &'static str {
    match path.rsplit('.').next().map(|s| s.to_lowercase()).as_deref() {
        // HTML
        Some("html") | Some("htm") => "text/html; charset=utf-8",

        // JavaScript - MUST be application/javascript
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",

        // CSS
        Some("css") => "text/css; charset=utf-8",

        // Data formats
        Some("json") => "application/json; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("csv") => "text/csv; charset=utf-8",

        // Images
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("avif") => "image/avif",

        // Fonts
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("eot") => "application/vnd.ms-fontobject",

        // Video
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("ogg") => "video/ogg",

        // Audio
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("flac") => "audio/flac",

        // Documents
        Some("pdf") => "application/pdf",

        // Source maps (treat as JSON)
        Some("map") => "application/json",

        // WebAssembly
        Some("wasm") => "application/wasm",

        // Manifest files
        Some("webmanifest") => "application/manifest+json",

        // Default binary
        _ => "application/octet-stream",
    }
}
```

---

### 1.5 Cache Headers

**Location**: `lib-network/src/web4/cache.rs`

**CHANGE**: Use `no-store` for SPA entry instead of `no-cache`.
- `no-cache` still allows storage
- `no-store` prevents intermediate caching during redeploys
- This matters for versioned publishes

```rust
pub struct CacheHeaders {
    pub cache_control: String,
    pub etag: Option<String>,
    pub vary: Option<String>,
}

pub fn cache_headers_for(
    path: &str,
    content_hash: &str,
    is_spa_entry: bool,
) -> CacheHeaders {
    if is_spa_entry {
        // index.html - NEVER cache, avoid stale during redeploys
        // Using no-store instead of no-cache to prevent intermediate caching
        CacheHeaders {
            cache_control: "no-store".to_string(),
            etag: Some(format!("\"{}\"", &content_hash[..16])),
            vary: Some("Accept-Encoding".to_string()),
        }
    } else if is_hashed_asset(path) {
        // main.abc123.js - immutable forever (content-addressed)
        CacheHeaders {
            cache_control: "public, max-age=31536000, immutable".to_string(),
            etag: None, // Not needed for immutable
            vary: Some("Accept-Encoding".to_string()),
        }
    } else {
        // Other assets - moderate caching with revalidation
        CacheHeaders {
            cache_control: "public, max-age=3600".to_string(),
            etag: Some(format!("\"{}\"", &content_hash[..16])),
            vary: Some("Accept-Encoding".to_string()),
        }
    }
}

/// Detect React/Vite/webpack hashed assets: main.abc123.js, chunk.def456.css
/// Pattern: name.hash.ext where hash is 8+ hex chars
fn is_hashed_asset(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let parts: Vec<&str> = filename.rsplitn(3, '.').collect();

    if parts.len() >= 3 {
        let hash_part = parts[1];
        // Must be 8+ chars and all hex
        hash_part.len() >= 8 && hash_part.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        false
    }
}

/// Check if request has matching ETag for 304 response
pub fn check_not_modified(
    if_none_match: Option<&str>,
    current_etag: &str,
) -> bool {
    if_none_match
        .map(|inm| inm.trim_matches('"') == current_etag.trim_matches('"'))
        .unwrap_or(false)
}
```

---

### 1.6 Content GET Endpoint

**Location**: `zhtp/src/api/handlers/web4/mod.rs` (extend existing)

```rust
// Add to handle_request match:
path if path.starts_with("/api/v1/web4/content/")
    && request.method == ZhtpMethod::Get => {
    self.get_web4_content(request).await
}

/// GET /api/v1/web4/content/{domain}/{path...}
///
/// Returns raw content bytes with correct headers.
/// This is the canonical content retrieval endpoint.
async fn get_web4_content(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
    // 1. Parse domain and path from URI
    let uri = request.uri.strip_prefix("/api/v1/web4/content/").unwrap();
    let (domain, path) = parse_domain_path(uri)?;

    // 2. Normalize path FIRST (security)
    let normalized_path = normalize_path(&path)
        .map_err(|e| anyhow!("Invalid path: {:?}", e))?;

    // 3. Check domain capability
    let config = self.content_service.get_effective_config(&domain).await?;
    if config.capability == Web4Capability::DownloadOnly {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::Forbidden,
            "Domain is download-only, not browser-servable".to_string(),
        ));
    }

    // 4. Get Accept-Encoding and If-None-Match headers
    let accept_encoding = request.headers.get("Accept-Encoding").map(|s| s.as_str());
    let if_none_match = request.headers.get("If-None-Match").map(|s| s.as_str());

    // 5. Call Web4ContentService
    let response = self.content_service
        .get_content(&domain, &normalized_path, accept_encoding)
        .await?;

    // 6. Check for 304 Not Modified
    if let (Some(inm), Some(ref etag)) = (if_none_match, &response.etag) {
        if check_not_modified(Some(inm), etag) {
            return Ok(ZhtpResponse::not_modified());
        }
    }

    // 7. Return raw bytes with headers
    Ok(ZhtpResponse::success_with_headers(
        response.body,
        response.content_type,
        vec![
            ("Cache-Control", response.cache_control),
            ("ETag", response.etag.unwrap_or_default()),
            ("Vary", "Accept-Encoding".to_string()),
        ],
    ))
}

fn parse_domain_path(uri: &str) -> Result<(String, String), anyhow::Error> {
    // URI format: {domain}/{path...}
    // Example: myapp.zhtp/static/js/main.js
    let parts: Vec<&str> = uri.splitn(2, '/').collect();
    let domain = parts.get(0).ok_or_else(|| anyhow!("Missing domain"))?;
    let path = parts.get(1).map(|s| format!("/{}", s)).unwrap_or("/".to_string());
    Ok((domain.to_string(), path))
}
```

---

### 1.7 Host-Based Gateway Handler

**Location**: `zhtp/src/server/gateway.rs` (NEW)

```rust
pub struct Web4Gateway {
    content_service: Arc<Web4ContentService>,
}

impl Web4Gateway {
    pub fn new(content_service: Arc<Web4ContentService>) -> Self {
        Self { content_service }
    }

    /// Handle request based on Host header
    pub async fn handle_request(
        &self,
        host: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> Result<GatewayResponse, GatewayError> {
        // 1. Extract domain from host (strip port, validate .zhtp)
        let domain = extract_domain(host)?;

        // 2. Normalize path FIRST (security)
        let normalized_path = normalize_path(path)
            .map_err(|e| GatewayError::InvalidPath(format!("{:?}", e)))?;

        // 3. Check capability
        let config = self.content_service.get_effective_config(&domain).await
            .map_err(|e| GatewayError::DomainNotFound(e.to_string()))?;

        if config.capability == Web4Capability::DownloadOnly {
            return Err(GatewayError::NotServable(domain));
        }

        // 4. Get Accept-Encoding
        let accept_encoding = headers.get("Accept-Encoding").map(|s| s.as_str());

        // 5. Fetch content via service
        let response = self.content_service
            .get_content(&domain, &normalized_path, accept_encoding)
            .await
            .map_err(|e| GatewayError::ContentError(e.to_string()))?;

        // 6. Return with proper headers
        Ok(GatewayResponse {
            status: response.status,
            headers: build_response_headers(&response),
            body: response.body,
        })
    }
}

fn extract_domain(host: &str) -> Result<String, GatewayError> {
    // Strip port: "myapp.zhtp:9334" -> "myapp.zhtp"
    let host_no_port = host.split(':').next().unwrap_or(host);

    // Validate .zhtp suffix
    if !host_no_port.ends_with(".zhtp") {
        return Err(GatewayError::InvalidDomain(host.to_string()));
    }

    Ok(host_no_port.to_string())
}

fn build_response_headers(response: &ContentResponse) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), response.content_type.clone());
    headers.insert("Cache-Control".to_string(), response.cache_control.clone());
    if let Some(ref etag) = response.etag {
        headers.insert("ETag".to_string(), etag.clone());
    }
    headers.insert("Vary".to_string(), "Accept-Encoding".to_string());
    headers
}

#[derive(Debug)]
pub enum GatewayError {
    InvalidDomain(String),
    InvalidPath(String),
    DomainNotFound(String),
    NotServable(String),
    ContentError(String),
}
```

**Integration in QUIC/HTTP Handler**:
```rust
// In request handler
if let Some(host) = headers.get("Host") {
    if host.ends_with(".zhtp") || host.contains(".zhtp:") {
        return gateway.handle_request(host, path, headers).await;
    }
}
```

**Fallback Route** (for testing without Host header):
```
GET /web4/{domain}/{path...}
```

---

## Phase 2: ZDNS Integration

### 2.1 Start ZDNS in ProtocolsComponent

**Location**: `zhtp/src/server/protocols.rs`

```rust
impl ProtocolsComponent {
    pub async fn start(&mut self) -> Result<()> {
        // ... existing startup ...

        // Start ZDNS resolver
        self.zdns_resolver = Some(ZdnsResolver::new(
            self.domain_registry.clone(),
            ZdnsConfig::default(),
        ));

        info!("ZDNS resolver started");
        Ok(())
    }
}
```

### 2.2 ZdnsResolver Internal API

**Location**: `lib-network/src/zdns/resolver.rs` (NEW)

```rust
pub struct ZdnsResolver {
    domain_registry: Arc<DomainRegistry>,
    cache: Arc<RwLock<LruCache<String, CachedRecord>>>,
    config: ZdnsConfig,
}

pub struct Web4Record {
    pub domain: String,
    pub owner: String,
    pub content_mappings: HashMap<String, String>,
    pub content_mode: Option<ContentMode>,
    pub spa_entry: Option<String>,
    pub asset_prefixes: Option<Vec<String>>,
    pub capability: Option<Web4Capability>,
    pub ttl: u64,
}

impl ZdnsResolver {
    /// Resolve domain to Web4 record (with caching)
    pub async fn resolve_web4(&self, domain: &str) -> Result<Web4Record, ZdnsError>;

    /// Invalidate cache for domain (on publish/register)
    pub fn invalidate(&self, domain: &str);
}
```

### 2.3 Caching at Resolver Boundary

```rust
struct CachedRecord {
    record: Web4Record,
    cached_at: Instant,
    ttl: Duration,
}

impl ZdnsResolver {
    async fn resolve_web4(&self, domain: &str) -> Result<Web4Record, ZdnsError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(domain) {
                if cached.cached_at.elapsed() < cached.ttl {
                    return Ok(cached.record.clone());
                }
            }
        }

        // Cache miss - resolve from registry
        let record = self.resolve_from_registry(domain).await?;

        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.put(domain.to_string(), CachedRecord {
                record: record.clone(),
                cached_at: Instant::now(),
                ttl: Duration::from_secs(record.ttl),
            });
        }

        Ok(record)
    }
}
```

---

## Phase 3: UDP/TCP DNS Transport

### 3.1 UDP Listener (Port 53)

**Location**: `lib-network/src/zdns/transport.rs` (NEW)

```rust
pub struct ZdnsServer {
    resolver: Arc<ZdnsResolver>,
    udp_socket: UdpSocket,
    tcp_listener: TcpListener,
    gateway_ip: IpAddr,
}

impl ZdnsServer {
    /// Start listening on port 53
    pub async fn start(&self) -> Result<()> {
        let udp_socket = UdpSocket::bind("0.0.0.0:53").await?;
        let tcp_listener = TcpListener::bind("0.0.0.0:53").await?;

        tokio::spawn(self.clone().handle_udp(udp_socket));
        tokio::spawn(self.clone().handle_tcp(tcp_listener));

        Ok(())
    }

    async fn handle_udp(self, socket: UdpSocket) {
        let mut buf = [0u8; 512];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let query = DnsPacket::parse(&buf[..len])?;

            if let Some(response) = self.resolve_dns_query(&query).await {
                socket.send_to(&response.serialize(), src).await?;
            }
        }
    }
}
```

### 3.2 DNS Response Strategy

**Model A: Gateway IP Resolution** (the correct choice)

This is the only model that works with real browsers without fantasy assumptions.
Anyone suggesting "custom RR types" or "browser plugins" at this stage is over-engineering.

```
Query:  myapp.zhtp A?
Answer: myapp.zhtp A 192.168.1.100  (gateway IP)
```

Browser connects to gateway IP, sends `Host: myapp.zhtp`, gateway serves content.

```rust
async fn resolve_dns_query(&self, query: &DnsPacket) -> Option<DnsPacket> {
    let domain = query.question.name()?;

    // Only handle .zhtp domains
    if !domain.ends_with(".zhtp") {
        return None;
    }

    // Check if domain exists in registry
    if self.resolver.resolve_web4(domain).await.is_ok() {
        // Return gateway IP
        Some(DnsPacket::a_record(domain, self.gateway_ip, 3600))
    } else {
        Some(DnsPacket::nxdomain(domain))
    }
}
```

---

## Phase 4: TLS Strategy ✅ COMPLETE

**Branch**: `feature/web4-tls-strategy-phase4`
**PR**: #397

### Implementation

Created HTTPS Gateway (`zhtp/src/server/https_gateway/`) with:
- **config.rs** - TLS configuration with multiple modes
- **server.rs** - Axum-based HTTPS server with rustls
- **handlers.rs** - HTTP request handlers for Web4 content

### TLS Modes Supported

| Mode | Use Case | Status |
|------|----------|--------|
| `SelfSigned` | Development (default) | ✅ |
| `StandardCa` | Production (Let's Encrypt) | ✅ |
| `PrivateCa` | Enterprise `.zhtp`/`.sov` | ✅ |
| `Disabled` | HTTP-only (not recommended) | ✅ |

### Configuration API

```rust
// Development (self-signed, localhost)
GatewayTlsConfig::development()

// Production with Let's Encrypt
GatewayTlsConfig::production("gateway.example.com")

// Private CA for sovereign domains
GatewayTlsConfig::private_ca(ca_cert, server_cert, server_key)

// Full gateway node (ZDNS + HTTPS)
ProtocolsComponent::new_gateway_node(env, port, gateway_ip, https_config)
```

### Integration with ProtocolsComponent

```rust
// Enable HTTPS gateway on node startup
ProtocolsComponent::new_with_https_gateway(env, port, config)

// Or full gateway mode (ZDNS transport + HTTPS)
ProtocolsComponent::new_gateway_node(env, port, gateway_ip, https_config)
```

### Features

- Self-signed certificate auto-generation for development
- Wildcard SANs for `*.zhtp`, `*.sov`, `*.zhtp.localhost`
- HTTP to HTTPS redirect (configurable)
- HSTS support with configurable max-age
- CORS configuration
- Health check and info endpoints
- Integration with ZDNS resolver for cached lookups

### Tests

23 tests covering:
- Config validation
- Builder patterns
- Path normalization
- Domain extraction
- TLD filtering

---

## Phase 5: React Deployment Pipeline

### 5.1 Publish Manifest

**Location**: `lib-network/src/web4/manifest.rs` (NEW)

```rust
pub struct Web4Manifest {
    /// List of files with hashes
    pub files: HashMap<String, FileEntry>,
    /// Entry point (default: /index.html)
    pub entry: String,
    /// Version (monotonic)
    pub version: u64,
    /// Deployed timestamp
    pub deployed_at: u64,
    /// Content mode
    pub content_mode: ContentMode,
    /// Domain capability
    pub capability: Web4Capability,
}

pub struct FileEntry {
    pub path: String,
    pub content_hash: String,
    pub size: u64,
    pub mime_type: String,
}
```

### 5.2 Publish Pipeline

```rust
pub async fn publish_react_build(
    domain: &str,
    build_dir: &Path,
    owner: &ZhtpIdentity,
) -> Result<PublishResult> {
    // 1. Walk build directory
    let files = walk_build_dir(build_dir)?;

    // 2. Upload each file to DHT (content-addressed)
    let mut content_mappings = HashMap::new();
    for file in files {
        let content = fs::read(&file.path)?;
        let hash = dht.store_content(domain, &file.relative_path, content).await?;
        content_mappings.insert(file.relative_path.clone(), hash);
    }

    // 3. Create manifest
    let manifest = Web4Manifest {
        files: content_mappings.clone(),
        entry: "/index.html".to_string(),
        version: next_version(domain).await?,
        deployed_at: now(),
        content_mode: ContentMode::Spa,
        capability: Web4Capability::SpaServe,
    };

    // 4. Update domain registry
    registry.update_content_mappings(domain, content_mappings, manifest).await?;

    Ok(PublishResult { version: manifest.version })
}
```

### 5.3 CLI Command

**Location**: `zhtp/src/cli/commands/deploy.rs` (NEW)

```bash
# Deploy React build to Web4 domain
zhtp deploy ./build --domain myapp.zhtp --mode spa

# Options:
#   --mode static|spa (default: spa)
#   --spa-entry /index.html
#   --asset-prefix /static/,/assets/
#   --capability http|spa|download (default: spa)
```

---

## Phase 6: Test Plan

### Unit Tests

| Test File | Coverage |
|-----------|----------|
| `path.rs` | Traversal attacks, encoding, null bytes, **normalization-before-asset-check** |
| `mime.rs` | All file extensions, **application/javascript for .js** |
| `cache.rs` | SPA entry (**no-store**), hashed assets, defaults |
| `content_service.rs` | SPA fallback, 404 handling, **domain-overrides-defaults** |

### Integration Tests

| Test | Description |
|------|-------------|
| Publish and retrieve | Upload file, fetch by domain/path |
| SPA deep link | Request `/users/123`, get index.html |
| Static asset | Request `/static/js/main.js`, get JS with correct MIME |
| 404 handling | Request `/images/logo.png` missing → 404 (not index) |
| ETag/304 | Request with If-None-Match, get 304 |
| Capability check | DownloadOnly domain returns 403 for HTTP serve |

### E2E Tests

| Test | Description |
|------|-------------|
| React app loads | Deploy CRA build, verify in browser |
| Client-side routing | Navigate to deep link, refresh works |
| Asset loading | JS/CSS/images load without console errors |

---

## Phase 7: Operational Hardening

- [ ] Rate limit publish endpoints (10/min per identity)
- [ ] Rate limit resolve endpoints (1000/min per IP)
- [ ] Max response size (50MB)
- [ ] Streaming responses from DHT (avoid buffering)
- [ ] Structured logging (domain, path, outcome, latency)
- [ ] Metrics: cache hit rate, DHT fetch time, 404 rate
- [ ] Health check endpoint

---

## File Structure After Implementation

```
lib-network/src/web4/
├── mod.rs              # Exports
├── content_service.rs  # NEW - Core service with defaults
├── path.rs             # NEW - Path normalization
├── mime.rs             # NEW - MIME detection
├── cache.rs            # NEW - Cache headers
├── manifest.rs         # NEW - Publish manifest
├── domain_registry.rs  # MODIFIED - Add optional config fields
├── content_publisher.rs # EXISTING
└── types.rs            # MODIFIED - Add ContentMode, Web4Capability

lib-network/src/zdns/
├── mod.rs              # NEW - Exports
├── resolver.rs         # NEW - ZDNS resolver
└── transport.rs        # NEW - UDP/TCP DNS

zhtp/src/
├── api/handlers/web4/
│   ├── mod.rs          # MODIFIED - Add GET route
│   └── content.rs      # EXISTING
├── server/
│   └── gateway.rs      # NEW - Host-based gateway
└── cli/commands/
    └── deploy.rs       # NEW - Deploy CLI
```

---

## Execution Order

### Week 1: Phase 1 Core
1. Create `path.rs` with normalization + security tests (including traversal-before-asset test)
2. Create `mime.rs` with MIME detection (keep `application/javascript`)
3. Create `cache.rs` with cache headers (`no-store` for SPA entry)
4. Add `ContentMode`, `Web4Capability` to `types.rs`
5. Add optional config fields to `DomainRecord`

### Week 2: Phase 1 Service + Integration
6. Create `content_service.rs` with defaults pattern
7. Add GET endpoint to `Web4Handler`
8. Create `gateway.rs` Host-based handler
9. Integration tests

### Week 3: Phase 2-3 DNS
10. Create `zdns/resolver.rs` with caching
11. Create `zdns/transport.rs` UDP/TCP
12. Wire up in ProtocolsComponent

### Week 4: Phase 5-7 Polish
13. Create `manifest.rs` publish manifest
14. Create `deploy.rs` CLI command
15. E2E testing with real React app
16. Operational hardening

---

## Success Criteria

Gateway is DONE when:

- [ ] `GET /api/v1/web4/content/myapp.zhtp/index.html` returns HTML
- [ ] `GET /api/v1/web4/content/myapp.zhtp/static/js/main.js` returns JS with `application/javascript`
- [ ] `GET /api/v1/web4/content/myapp.zhtp/users/123` returns index.html (SPA fallback)
- [ ] `GET /api/v1/web4/content/myapp.zhtp/images/logo.png` (missing) returns 404 (not index)
- [ ] `Host: myapp.zhtp` header routes to correct domain content
- [ ] React app loads in browser with no console errors
- [ ] Refresh on deep link (`/users/123`) works
- [ ] index.html has `Cache-Control: no-store`
- [ ] Hashed assets have `Cache-Control: immutable`
- [ ] Path traversal attacks blocked (including pre-normalization)
- [ ] Domain config overrides service defaults
- [ ] DownloadOnly domains return 403 for HTTP serve
- [ ] All unit/integration tests pass

---

## Key Design Decisions

### 1. Service defaults vs domain config

```
effective_config = domain_record overrides service_defaults
```

This avoids leaking SPA assumptions globally and allows domains to behave differently.

### 2. Normalization order

```
normalize → validate → is_static_asset → lookup → SPA fallback
```

Never check asset status on unnormalized paths.

### 3. SPA fallback guards

- Missing file with extension → 404 (surface broken refs)
- Missing directory-like path → SPA fallback
- Missing static asset path → 404

### 4. Cache strategy

- SPA entry: `no-store` (not `no-cache`)
- Hashed assets: `immutable`
- Other: moderate with ETag

### 5. DNS model

Gateway IP resolution. Browser plugins and custom RR types are over-engineering.

### 6. TLS strategy

Start with standard domains. Private CA later for controlled environments.

### 7. Domain capability

```rust
pub enum Web4Capability {
    HttpServe,    // Static browser serving
    SpaServe,     // SPA with client-side routing (default)
    DownloadOnly, // APIs, blobs, datasets - not browser-servable
}
```

Not all domains should be browser-servable. This matters sooner than expected.

---

## Dependencies

| Phase | Depends On |
|-------|------------|
| Phase 1 | DHT storage (exists), DomainRegistry (exists) |
| Phase 2 | Phase 1 complete |
| Phase 3 | Phase 2 complete, lib-dns |
| Phase 4 | Phase 3 complete |
| Phase 5 | Phase 1 complete |
| Phase 6 | All phases |
| Phase 7 | All phases |

---

## Open Questions

1. **Max file size for upload?** → 50MB per file
2. **Compression strategy?** → Store LZ4 compressed, serve as-is with Content-Encoding
3. **Streaming large files?** → Yes, chunk from DHT to response
4. **Domain validation?** → Require `.zhtp` suffix for gateway

---

---

# Appendix A: `.sov` Namespace Specification

## Overview

The `.sov` namespace is a **closed sovereign root** — a top-level domain namespace controlled by a **single RSA-based root identity**. Unlike traditional TLDs, `.sov` is not purchased or auctioned; domains are **issued** by the root or delegated registries under policy constraints.

This appendix defines:
- The hierarchical domain model
- Domain types and their semantics
- Governance models and delegation
- Policy enforcement rules
- Registry architecture requirements

---

## 1. Root Namespace Definition

### 1.1 The `.sov` Root

```rust
/// The root of the sovereign namespace
pub const SOV_ROOT: &str = ".sov";

/// Root is controlled by a single identity (RSA-based for bootstrapping)
pub struct RootAuthority {
    /// RSA identity controlling the root
    pub identity: RsaIdentity,
    /// Timestamp of root creation
    pub created_at: u64,
    /// Root policy constraints
    pub root_policy: RootPolicy,
}
```

### 1.2 Hard Constraints

1. **Closed Root**: Only the root identity can issue first-level domains (e.g., `central.sov`)
2. **Issued, Not Purchased**: Domains are granted, not sold (though fees may apply)
3. **Policy Inheritance**: Child domains inherit constraints from parents
4. **Type Enforcement**: Domain types restrict allowed activities

---

## 2. Hierarchical Domain Model

### 2.1 Domain Hierarchy

```
.sov                          (Root)
├── central.sov               (Central - governance/core services)
│   ├── registry.central.sov  (Core registry service)
│   ├── welfare.central.sov   (Welfare DAO)
│   └── identity.central.sov  (Identity services)
├── commerce.sov              (Commercial TLD)
│   ├── acme.commerce.sov     (Commercial entity)
│   └── shop.commerce.sov     (Commercial entity)
├── community.sov             (NonProfit TLD)
│   ├── education.community.sov
│   └── health.community.sov
└── dao.sov                   (DAO TLD)
    ├── builders.dao.sov      (Builder collective)
    └── artists.dao.sov       (Artist collective)
```

### 2.2 Domain Depth

```rust
/// Maximum domain depth (root = 0)
pub const MAX_DOMAIN_DEPTH: u8 = 5;

/// Calculate domain depth
pub fn domain_depth(domain: &str) -> u8 {
    domain.matches('.').count() as u8
}

// Examples:
// ".sov" → 0 (root)
// "central.sov" → 1
// "registry.central.sov" → 2
// "users.registry.central.sov" → 3
```

---

## 3. Domain Types

### 3.1 Type Enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainType {
    /// Root namespace (only .sov itself)
    Root,
    /// Central governance and core services
    Central,
    /// Commercial/for-profit activity allowed
    Commercial,
    /// Public good, no revenue extraction
    NonProfit,
    /// DAO-governed collective
    DAO,
}
```

### 3.2 Type Semantics

| Type | Revenue Allowed | DAO Approval | Open Registration | Typical Use |
|------|-----------------|--------------|-------------------|-------------|
| Root | N/A | N/A | No | .sov only |
| Central | No | Yes | No | Core services |
| Commercial | Yes | No | Yes (with fee) | Businesses |
| NonProfit | No | Optional | Optional | Public goods |
| DAO | Collective only | Required | DAO rules | Collectives |

### 3.3 Type Constraints

```rust
impl DomainType {
    /// What child types can this domain type create?
    pub fn allowed_child_types(&self) -> Vec<DomainType> {
        match self {
            DomainType::Root => vec![
                DomainType::Central,
                DomainType::Commercial,
                DomainType::NonProfit,
                DomainType::DAO,
            ],
            DomainType::Central => vec![DomainType::Central],
            DomainType::Commercial => vec![DomainType::Commercial],
            DomainType::NonProfit => vec![DomainType::NonProfit, DomainType::DAO],
            DomainType::DAO => vec![DomainType::DAO],
        }
    }

    /// Can this domain type perform commercial transactions?
    pub fn allows_commerce(&self) -> bool {
        matches!(self, DomainType::Commercial)
    }

    /// Does this domain type require DAO approval for changes?
    pub fn requires_dao_governance(&self) -> bool {
        matches!(self, DomainType::Central | DomainType::DAO)
    }
}
```

---

## 4. DomainRecord Structure

### 4.1 Complete Record

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    /// Fully qualified domain name (e.g., "acme.commerce.sov")
    pub domain: String,

    /// Parent domain (None for root)
    pub parent: Option<String>,

    /// Domain type (determines allowed activities)
    pub domain_type: DomainType,

    /// Who controls this domain
    pub owner: DomainController,

    /// Delegated identities with limited permissions
    pub delegates: Vec<DelegateRecord>,

    /// How decisions are made for this domain
    pub governance: GovernanceModel,

    /// Policy constraints for this domain and children
    pub policy: DomainPolicy,

    /// Web4 content configuration (optional)
    pub content: Option<Web4ContentConfig>,

    /// Web4 capability level
    pub capability: Web4Capability,

    /// Creation timestamp
    pub created_at: u64,

    /// Last update timestamp
    pub updated_at: u64,

    /// Expiration (None = permanent for Central/Root)
    pub expires_at: Option<u64>,
}
```

### 4.2 Domain Validation

```rust
impl DomainRecord {
    /// Validate domain record consistency
    pub fn validate(&self) -> Result<(), DomainError> {
        // 1. Check domain format
        self.validate_domain_format()?;

        // 2. Check type constraints
        self.validate_type_constraints()?;

        // 3. Check governance matches type
        self.validate_governance()?;

        // 4. Check policy inheritance
        self.validate_policy()?;

        Ok(())
    }

    fn validate_type_constraints(&self) -> Result<(), DomainError> {
        // Root type only for .sov
        if self.domain_type == DomainType::Root && self.domain != ".sov" {
            return Err(DomainError::InvalidType("Root type reserved for .sov"));
        }

        // Central requires DAO governance
        if self.domain_type == DomainType::Central {
            if !matches!(self.governance, GovernanceModel::DAOControlled { .. }) {
                return Err(DomainError::InvalidGovernance(
                    "Central domains require DAO governance"
                ));
            }
        }

        Ok(())
    }
}
```

---

## 5. Ownership and Governance

### 5.1 Domain Controller

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainController {
    /// Single identity owner
    Identity(ZhtpIdentity),

    /// Multi-signature control
    Multisig(MultisigConfig),

    /// DAO-controlled
    DAO(DAOReference),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigConfig {
    /// Required signatures
    pub threshold: u8,
    /// Total signers
    pub signers: Vec<ZhtpIdentity>,
    /// Timelock for changes (seconds)
    pub timelock: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAOReference {
    /// DAO contract address
    pub dao_address: String,
    /// Proposal type required for domain changes
    pub proposal_type: ProposalType,
    /// Minimum quorum for domain decisions
    pub quorum: Percentage,
}
```

### 5.2 Governance Model

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceModel {
    /// Owner has full control
    OwnerControlled,

    /// DAO votes on changes
    DAOControlled {
        dao: DAOReference,
        /// What actions require DAO approval
        governed_actions: Vec<GovernedAction>,
    },

    /// Hybrid: owner for ops, DAO for policy
    Hybrid {
        owner: DomainController,
        dao: DAOReference,
        /// Actions requiring DAO approval
        dao_actions: Vec<GovernedAction>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum GovernedAction {
    Transfer,
    PolicyChange,
    DelegateAdd,
    DelegateRemove,
    SubdomainCreate,
    ContentUpdate,
}
```

### 5.3 Delegation

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateRecord {
    /// Delegate identity
    pub identity: ZhtpIdentity,

    /// Permissions granted
    pub permissions: Vec<DelegatePermission>,

    /// Expiration (optional)
    pub expires_at: Option<u64>,

    /// Who granted this delegation
    pub granted_by: ZhtpIdentity,

    /// When granted
    pub granted_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DelegatePermission {
    /// Can update content
    ContentUpdate,
    /// Can create subdomains
    SubdomainCreate,
    /// Can manage other delegates (not self)
    DelegateManage,
    /// Can update DNS records
    DnsUpdate,
}
```

---

## 6. Domain Policy

### 6.1 Policy Structure

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPolicy {
    /// What child domain types are allowed
    pub allowed_child_types: Vec<DomainType>,

    /// Require DAO approval for subdomain creation
    pub require_dao_approval: bool,

    /// Require identity verification for subdomain owners
    pub require_identity_verification: bool,

    /// Allow commercial activity under this domain
    pub allow_commercial_activity: bool,

    /// Allow revenue extraction
    pub allow_revenue: bool,

    /// Allow open registration (vs. invitation only)
    pub allow_open_registration: bool,

    /// Maximum subdomain depth from this domain
    pub max_subdomain_depth: u8,

    /// Required stake for subdomain creation (0 = none)
    pub subdomain_stake: u64,

    /// Custom rules (extensible)
    pub custom_rules: Vec<PolicyRule>,
}
```

### 6.2 Policy Inheritance

```rust
impl DomainPolicy {
    /// Apply parent policy constraints (child cannot exceed parent)
    pub fn inherit_from(&mut self, parent: &DomainPolicy) {
        // Child can only allow types parent allows
        self.allowed_child_types.retain(|t| {
            parent.allowed_child_types.contains(t)
        });

        // If parent requires DAO approval, child must too
        if parent.require_dao_approval {
            self.require_dao_approval = true;
        }

        // If parent requires identity verification, child must too
        if parent.require_identity_verification {
            self.require_identity_verification = true;
        }

        // Child cannot enable commerce if parent disables it
        if !parent.allow_commercial_activity {
            self.allow_commercial_activity = false;
        }

        // Child cannot enable revenue if parent disables it
        if !parent.allow_revenue {
            self.allow_revenue = false;
        }

        // Child depth cannot exceed parent's remaining depth
        self.max_subdomain_depth = self.max_subdomain_depth
            .min(parent.max_subdomain_depth.saturating_sub(1));
    }
}
```

### 6.3 Standard Policies

```rust
impl DomainPolicy {
    /// Policy for central.sov and children
    pub fn central_policy() -> Self {
        Self {
            allowed_child_types: vec![DomainType::Central],
            require_dao_approval: true,
            require_identity_verification: true,
            allow_commercial_activity: false,
            allow_revenue: false,
            allow_open_registration: false,
            max_subdomain_depth: 3,
            subdomain_stake: 0,
            custom_rules: vec![],
        }
    }

    /// Policy for commerce.sov and children
    pub fn commercial_policy() -> Self {
        Self {
            allowed_child_types: vec![DomainType::Commercial],
            require_dao_approval: false,
            require_identity_verification: true,
            allow_commercial_activity: true,
            allow_revenue: true,
            allow_open_registration: true,
            max_subdomain_depth: 4,
            subdomain_stake: 1000, // SOV tokens
            custom_rules: vec![],
        }
    }

    /// Policy for community.sov and children
    pub fn nonprofit_policy() -> Self {
        Self {
            allowed_child_types: vec![DomainType::NonProfit, DomainType::DAO],
            require_dao_approval: false,
            require_identity_verification: false,
            allow_commercial_activity: false,
            allow_revenue: false,
            allow_open_registration: true,
            max_subdomain_depth: 4,
            subdomain_stake: 0,
            custom_rules: vec![],
        }
    }

    /// Policy for dao.sov and children
    pub fn dao_policy() -> Self {
        Self {
            allowed_child_types: vec![DomainType::DAO],
            require_dao_approval: true,
            require_identity_verification: false,
            allow_commercial_activity: false,
            allow_revenue: false, // Collective only, no extraction
            allow_open_registration: false, // DAO decides
            max_subdomain_depth: 3,
            subdomain_stake: 0, // DAO decides stake
            custom_rules: vec![],
        }
    }
}
```

---

## 7. Core Welfare DAO

### 7.1 Purpose

The **Core Welfare DAO** (`welfare.central.sov`) is the governance body for:
- Central domain management
- Policy changes to root namespaces
- Fee structures and distribution
- Emergency actions

### 7.2 Structure

```rust
pub struct CoreWelfareDAO {
    /// DAO domain
    pub domain: String, // "welfare.central.sov"

    /// Governance token
    pub token: String, // "SOV"

    /// Proposal types
    pub proposal_types: Vec<WelfareProposalType>,

    /// Quorum requirements by proposal type
    pub quorum_requirements: HashMap<WelfareProposalType, Percentage>,

    /// Timelock by proposal type (seconds)
    pub timelocks: HashMap<WelfareProposalType, u64>,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum WelfareProposalType {
    /// Create new first-level domain
    FirstLevelDomain,
    /// Change root policy
    RootPolicyChange,
    /// Emergency action (pause, revoke)
    Emergency,
    /// Fee structure change
    FeeChange,
    /// Upgrade core contracts
    CoreUpgrade,
}
```

### 7.3 Governance Parameters

| Proposal Type | Quorum | Approval | Timelock |
|---------------|--------|----------|----------|
| FirstLevelDomain | 10% | 66% | 7 days |
| RootPolicyChange | 20% | 75% | 14 days |
| Emergency | 5% | 80% | 1 day |
| FeeChange | 15% | 66% | 7 days |
| CoreUpgrade | 25% | 80% | 21 days |

---

## 8. Domain Minting Rules

### 8.1 First-Level Domains

```rust
impl RootAuthority {
    /// Create a first-level domain (requires DAO approval)
    pub async fn create_first_level_domain(
        &self,
        name: &str,
        domain_type: DomainType,
        owner: DomainController,
        policy: DomainPolicy,
        dao_approval: &DAOApproval,
    ) -> Result<DomainRecord, DomainError> {
        // 1. Validate DAO approval
        self.validate_dao_approval(dao_approval, WelfareProposalType::FirstLevelDomain)?;

        // 2. Validate name
        self.validate_first_level_name(name)?;

        // 3. Check name not taken
        if self.registry.exists(&format!("{}.sov", name)).await? {
            return Err(DomainError::AlreadyExists);
        }

        // 4. Validate type is not Root
        if domain_type == DomainType::Root {
            return Err(DomainError::InvalidType("Cannot create Root domains"));
        }

        // 5. Create record
        let record = DomainRecord {
            domain: format!("{}.sov", name),
            parent: Some(".sov".to_string()),
            domain_type,
            owner,
            delegates: vec![],
            governance: self.default_governance_for_type(domain_type),
            policy,
            content: None,
            capability: Web4Capability::SpaServe,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            expires_at: None, // First-level domains are permanent
        };

        // 6. Store and return
        self.registry.store(record.clone()).await?;
        Ok(record)
    }
}
```

### 8.2 Subdomain Creation

```rust
impl DomainRecord {
    /// Create a subdomain under this domain
    pub async fn create_subdomain(
        &self,
        name: &str,
        domain_type: DomainType,
        owner: DomainController,
        policy: DomainPolicy,
        registry: &DomainRegistry,
        requester: &ZhtpIdentity,
    ) -> Result<DomainRecord, DomainError> {
        // 1. Check requester has permission
        if !self.can_create_subdomain(requester) {
            return Err(DomainError::Unauthorized);
        }

        // 2. Check domain type is allowed
        if !self.policy.allowed_child_types.contains(&domain_type) {
            return Err(DomainError::TypeNotAllowed(domain_type));
        }

        // 3. Check depth limit
        let new_depth = domain_depth(&self.domain) + 1;
        if new_depth > self.policy.max_subdomain_depth as u8 + domain_depth(&self.domain) {
            return Err(DomainError::DepthExceeded);
        }

        // 4. Validate name
        validate_subdomain_name(name)?;

        // 5. Check name not taken
        let full_name = format!("{}.{}", name, self.domain);
        if registry.exists(&full_name).await? {
            return Err(DomainError::AlreadyExists);
        }

        // 6. Inherit and apply policy
        let mut child_policy = policy;
        child_policy.inherit_from(&self.policy);

        // 7. Create record
        let record = DomainRecord {
            domain: full_name,
            parent: Some(self.domain.clone()),
            domain_type,
            owner,
            delegates: vec![],
            governance: GovernanceModel::OwnerControlled,
            policy: child_policy,
            content: None,
            capability: Web4Capability::SpaServe,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            expires_at: Some(current_timestamp() + self.default_expiration()),
        };

        // 8. Store and return
        registry.store(record.clone()).await?;
        Ok(record)
    }
}
```

### 8.3 Name Validation

```rust
/// Validate subdomain name
pub fn validate_subdomain_name(name: &str) -> Result<(), DomainError> {
    // Length: 1-63 characters
    if name.is_empty() || name.len() > 63 {
        return Err(DomainError::InvalidName("Length must be 1-63 characters"));
    }

    // Characters: a-z, 0-9, hyphen (not at start/end)
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(DomainError::InvalidName("Only lowercase letters, digits, and hyphens allowed"));
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(DomainError::InvalidName("Cannot start or end with hyphen"));
    }

    // No consecutive hyphens (except xn-- for punycode)
    if name.contains("--") && !name.starts_with("xn--") {
        return Err(DomainError::InvalidName("No consecutive hyphens"));
    }

    // Reserved names
    const RESERVED: &[&str] = &["www", "mail", "ftp", "admin", "root", "api", "cdn"];
    if RESERVED.contains(&name) {
        return Err(DomainError::Reserved);
    }

    Ok(())
}
```

---

## 9. Web4 Content Configuration

### 9.1 Per-Domain Content Config

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4ContentConfig {
    /// Content mode (static or SPA)
    pub content_mode: ContentMode,

    /// Default document for directories
    pub index_document: String,

    /// Error document path
    pub error_document: Option<String>,

    /// Content root in DHT (optional, defaults to domain)
    pub content_root: Option<String>,

    /// Custom headers
    pub custom_headers: HashMap<String, String>,

    /// Redirects
    pub redirects: Vec<RedirectRule>,

    /// Access control
    pub access_control: AccessControl,
}

impl Default for Web4ContentConfig {
    fn default() -> Self {
        Self {
            content_mode: ContentMode::Spa,
            index_document: "index.html".to_string(),
            error_document: Some("404.html".to_string()),
            content_root: None,
            custom_headers: HashMap::new(),
            redirects: vec![],
            access_control: AccessControl::Public,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessControl {
    /// Anyone can access
    Public,
    /// Require authentication
    Authenticated,
    /// Specific identities only
    Allowlist(Vec<String>),
    /// Token-gated
    TokenGated { token: String, min_balance: u64 },
}
```

### 9.2 Domain-Content Association

```rust
impl DomainRecord {
    /// Associate content with this domain
    pub async fn set_content(
        &mut self,
        config: Web4ContentConfig,
        requester: &ZhtpIdentity,
    ) -> Result<(), DomainError> {
        // Check permission
        if !self.can_update_content(requester) {
            return Err(DomainError::Unauthorized);
        }

        // Validate config
        config.validate()?;

        // Update
        self.content = Some(config);
        self.updated_at = current_timestamp();

        Ok(())
    }
}
```

---

## 10. Registry Architecture

### 10.1 Registry Interface

```rust
#[async_trait]
pub trait DomainRegistry {
    /// Store a domain record
    async fn store(&self, record: DomainRecord) -> Result<(), RegistryError>;

    /// Lookup domain by name
    async fn lookup(&self, domain: &str) -> Result<Option<DomainRecord>, RegistryError>;

    /// Check if domain exists
    async fn exists(&self, domain: &str) -> Result<bool, RegistryError>;

    /// List subdomains of a domain
    async fn list_subdomains(&self, parent: &str) -> Result<Vec<DomainRecord>, RegistryError>;

    /// List domains by owner
    async fn list_by_owner(&self, owner: &ZhtpIdentity) -> Result<Vec<DomainRecord>, RegistryError>;

    /// Delete domain (with policy checks)
    async fn delete(&self, domain: &str, requester: &ZhtpIdentity) -> Result<(), RegistryError>;

    /// Transfer domain
    async fn transfer(
        &self,
        domain: &str,
        new_owner: DomainController,
        requester: &ZhtpIdentity,
    ) -> Result<(), RegistryError>;
}
```

### 10.2 Registry Enforcement

```rust
impl SovDomainRegistry {
    /// Enforce all policy constraints on registration
    async fn enforce_registration_policy(
        &self,
        record: &DomainRecord,
        parent: &DomainRecord,
    ) -> Result<(), RegistryError> {
        // 1. Type constraint
        if !parent.policy.allowed_child_types.contains(&record.domain_type) {
            return Err(RegistryError::TypeNotAllowed);
        }

        // 2. Depth constraint
        let depth = domain_depth(&record.domain);
        let parent_depth = domain_depth(&parent.domain);
        if depth > parent_depth + parent.policy.max_subdomain_depth as u8 {
            return Err(RegistryError::DepthExceeded);
        }

        // 3. DAO approval if required
        if parent.policy.require_dao_approval {
            // Check DAO approval exists and is valid
            // (implementation depends on DAO integration)
        }

        // 4. Identity verification if required
        if parent.policy.require_identity_verification {
            match &record.owner {
                DomainController::Identity(id) => {
                    if !id.is_verified() {
                        return Err(RegistryError::IdentityNotVerified);
                    }
                }
                _ => {} // Multisig/DAO have different verification
            }
        }

        // 5. Stake if required
        if parent.policy.subdomain_stake > 0 {
            // Check stake is deposited
            // (implementation depends on token integration)
        }

        Ok(())
    }
}
```

---

## 11. Gateway/DNS Requirements

### 11.1 `.sov` Domain Resolution

The gateway must:

1. **Parse `.sov` domains**: Recognize `*.sov` as sovereign namespace
2. **Query sovereign registry**: Use `DomainRegistry` instead of DNS
3. **Apply Web4 capability**: Check `Web4Capability` before serving
4. **Enforce access control**: Apply `AccessControl` from content config

### 11.2 Gateway Flow for `.sov`

```rust
impl Web4Gateway {
    async fn handle_sov_request(&self, host: &str, path: &str) -> Response {
        // 1. Parse domain
        let domain = host.trim_end_matches(".localhost").to_string();

        // 2. Lookup in sovereign registry
        let record = match self.sov_registry.lookup(&domain).await {
            Ok(Some(record)) => record,
            Ok(None) => return self.not_found_response(),
            Err(e) => return self.error_response(e),
        };

        // 3. Check capability
        if record.capability == Web4Capability::DownloadOnly {
            return self.download_only_response(&record, path).await;
        }

        // 4. Check access control
        if !self.check_access(&record, &self.request_identity()).await {
            return self.forbidden_response();
        }

        // 5. Serve content via Web4ContentService
        self.web4_service.serve(&domain, path, &record.content).await
    }
}
```

### 11.3 ZDNS Integration

For external DNS resolution, `.sov` domains use the **Model A** approach:

```
acme.commerce.sov. 300 IN A <gateway-ip>
                   300 IN TXT "zhtp=did:zhtp:..."
```

The gateway IP is the managed gateway, which:
1. Receives the HTTP request
2. Extracts the `Host` header
3. Resolves via sovereign registry
4. Serves Web4 content

---

## 12. Summary

The `.sov` namespace provides:

| Feature | Implementation |
|---------|----------------|
| **Closed Root** | Single RSA identity + DAO approval for first-level |
| **Type System** | DomainType enum with semantic constraints |
| **Policy Inheritance** | Child domains inherit parent constraints |
| **Governance** | Owner, Multisig, or DAO control |
| **Delegation** | Granular permissions for delegates |
| **Web4 Integration** | Per-domain content config and capability |
| **Registry Enforcement** | All constraints enforced at registration |

This creates a sovereign, policy-enforced namespace suitable for decentralized governance while maintaining compatibility with the Web4 gateway system.

---

*Last Updated: 2024-12-13*
*Status: Ready for Phase 1 Implementation*
