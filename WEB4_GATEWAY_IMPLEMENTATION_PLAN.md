# Web4 Gateway Implementation Plan

## Overview

This plan covers two phases:
1. **Phase A**: Review and fix prerequisite PRs (DHT/routing foundation)
2. **Phase B**: Implement Web4 HTTP Gateway for React SPA hosting

Target: Serve a React website via `https://gateway/myapp/` or `Host: myapp.zhtp`

---

## Phase A: Prerequisite PR Reviews

### Review Process for Each PR

1. **Checkout PR branch**
2. **Architecture Review**
   - Does it follow existing patterns?
   - Are abstractions appropriate?
   - Any circular dependencies introduced?
   - Is the API surface minimal and clean?
3. **Security Review**
   - Input validation
   - Error handling (no panics, no info leaks)
   - Authentication/authorization where needed
   - DoS protection (bounded collections, timeouts)
4. **Code Quality Review**
   - No dead code or commented-out code
   - Proper error types (not string errors)
   - Tests cover critical paths
   - Documentation for public APIs
5. **Make fixes directly on the branch**
6. **Run tests**: `cargo test --package <pkg>`
7. **Run clippy**: `cargo clippy --package <pkg>`
8. **Commit fixes with clear messages**
9. **Push updates to PR branch**
10. **Add review comment summarizing changes**

---

### PR #371: Unify DHT, Mesh, and Graph Routing

**Branch**: `153-arch-d-119-unify-dht-routing-with-mesh-routing`

**Scope**: Consolidates 3 routing implementations into `UnifiedRouter`
- Eliminates 1,585 lines of duplicate code
- Creates single routing abstraction

**Files to Review**:
| File | Lines | Focus |
|------|-------|-------|
| `lib-network/src/routing/unified_router.rs` | +1012 | Core implementation |
| `lib-storage/src/dht/routing.rs` | +60/-649 | DhtRouter trait |
| `lib-network/src/routing/message_routing.rs` | +20/-1136 | Re-export wrapper |
| `lib-network/src/routing/multi_hop.rs` | +20/-959 | Re-export wrapper |

**Architecture Checklist**:
- [ ] `UnifiedRouter` correctly implements Kademlia XOR distance
- [ ] K-bucket logic preserved from original implementation
- [ ] Mesh topology awareness maintained
- [ ] Graph/Dijkstra pathfinding works correctly
- [ ] `DhtRouter` trait is minimal and dependency-free
- [ ] No circular dependencies between lib-storage and lib-network
- [ ] Backward compatibility via re-exports

**Security Checklist**:
- [ ] Route selection doesn't leak information
- [ ] Bounded collections (no unbounded growth)
- [ ] No panics on malformed input
- [ ] Peer validation before routing decisions

**Expected Fixes**:
- Add missing input validation
- Ensure K-bucket bounds checking
- Add documentation for public API
- Fix any clippy warnings

---

### PR #370: DHT Transport Abstraction

**Branch**: `152-arch-d-118-implement-dht-transport-layer`

**Scope**: Replace hardcoded UDP socket with `DhtTransport` trait
- DHT works over UDP, QUIC, BLE, WiFi Direct
- Automatic protocol selection

**Files to Review**:
| File | Lines | Focus |
|------|-------|-------|
| `lib-network/src/dht/transport.rs` | +168 | Transport implementations |
| `lib-storage/src/dht/network.rs` | +91/-37 | Use transport abstraction |

**Architecture Checklist**:
- [ ] `DhtTransport` trait is clean and minimal
- [ ] Protocol selection logic is correct
- [ ] Fallback mechanism works properly
- [ ] `new_udp()` backward compatibility maintained
- [ ] MTU handling per protocol is correct

**Security Checklist**:
- [ ] Address parsing is safe (no panics)
- [ ] Protocol detection can't be spoofed
- [ ] Timeouts on transport operations
- [ ] No sensitive data in error messages

**Expected Fixes**:
- Add timeout parameters to transport methods
- Validate addresses before use
- Add protocol-specific MTU enforcement

---

### PR #387: Route DHT Traffic Through Mesh

**Branch**: `154-arch-d-120-route-storage-operations-through-mesh`

**Scope**: DHT messages routed through mesh network
- Removes raw UDP from DhtNetwork
- Uses `DhtMessageRouter` trait abstraction

**Files to Review**:
| File | Lines | Focus |
|------|-------|-------|
| `lib-storage/src/dht/network.rs` | +100/-77 | Router trait, send_message |
| `lib-network/src/routing/dht_router_adapter.rs` | +58 | Mesh adapter |
| `lib-network/src/types/mesh_message.rs` | +7 | DhtGenericPayload |
| `zhtp/src/server/mesh/core.rs` | +22/-15 | Wiring |

**Architecture Checklist**:
- [ ] `DhtMessageRouter` trait avoids circular deps
- [ ] `MeshDhtRouterAdapter` correctly wraps mesh routing
- [ ] `DhtGenericPayload` message type is properly defined
- [ ] Lifecycle management (start/stop) is correct
- [ ] Event-driven architecture properly implemented

**Security Checklist**:
- [ ] DHT messages validated before routing
- [ ] Message size limits enforced
- [ ] No amplification attack vectors
- [ ] Proper error handling (no panics)

**Expected Fixes**:
- Add message validation before routing
- Ensure proper cleanup on shutdown
- Add metrics/logging for debugging

---

### PR #369: Bootstrap Unified Peer Registry

**Branch**: `150-arch-d-116-migrate-bootstrap-to-use-unified-peer-registry`

**Scope**: Bootstrap process uses unified peer registry

**Files to Review**:
| File | Lines | Focus |
|------|-------|-------|
| `lib-network/src/bootstrap/*.rs` | Various | Peer registry integration |

**Architecture Checklist**:
- [ ] Bootstrap uses `PeerRegistry` correctly
- [ ] No duplicate peer storage
- [ ] Peer lifecycle (add/update/remove) is correct

**Security Checklist**:
- [ ] Bootstrap peers validated before trust
- [ ] Rate limiting on peer additions
- [ ] No hardcoded credentials/keys

**Expected Fixes**:
- Add validation for bootstrap peer addresses
- Ensure proper error handling

---

## Phase B: Web4 Gateway Implementation

**Branch**: `feature/web4-http-gateway`

**Depends on**: PRs #371, #370, #387, #369 merged

---

### B.1: Create `Web4ContentService`

**Location**: `lib-network/src/web4/content_service.rs`

**Purpose**: Single internal API for all content operations

```rust
pub struct Web4ContentService {
    domain_registry: Arc<RwLock<DomainRegistry>>,
    dht_storage: Arc<RwLock<DhtStorage>>,
    config: Web4ContentConfig,
}

impl Web4ContentService {
    /// Resolve and fetch content for a domain/path
    pub async fn get_content(
        &self,
        domain: &str,
        path: &str,
        accept_encoding: Option<&str>,
    ) -> Result<ContentResponse, ContentError>;

    /// Check if content exists without fetching
    pub async fn content_exists(
        &self,
        domain: &str,
        path: &str,
    ) -> Result<bool, ContentError>;
}

pub struct ContentResponse {
    pub body: Vec<u8>,
    pub content_type: String,
    pub cache_control: String,
    pub etag: Option<String>,
    pub content_encoding: Option<String>,
}

pub struct Web4ContentConfig {
    pub content_mode: ContentMode,  // Static or SPA
    pub spa_entry: String,          // "/index.html"
    pub asset_prefixes: Vec<String>, // ["/static/", "/assets/"]
    pub asset_extensions: Vec<String>, // ["js", "css", "png", ...]
}

pub enum ContentMode {
    Static,  // 404 for missing paths
    Spa,     // Fallback to spa_entry for non-assets
}
```

**Implementation Tasks**:
- [ ] Path normalization with security checks
- [ ] Domain lookup via registry
- [ ] Content hash lookup from domain's content_mappings
- [ ] DHT content retrieval
- [ ] Decompression (LZ4)
- [ ] SPA fallback logic
- [ ] MIME type detection
- [ ] Cache header generation
- [ ] ETag generation

---

### B.2: Path Normalization

**Location**: `lib-network/src/web4/path.rs`

```rust
pub fn normalize_path(path: &str) -> Result<String, PathError> {
    // 1. URL decode
    // 2. Ensure leading /
    // 3. Collapse // to /
    // 4. Resolve . and .. (reject if escapes root)
    // 5. Convert empty to /
    // 6. Validate no null bytes
}

pub fn is_static_asset(path: &str, config: &Web4ContentConfig) -> bool {
    // Check asset prefixes
    // Check file extensions
}
```

**Security Requirements**:
- [ ] Prevent path traversal (`..`, `%2e%2e`)
- [ ] Handle URL encoding attacks
- [ ] No null byte injection
- [ ] Bounded path length

---

### B.3: MIME Type Detection

**Location**: `lib-network/src/web4/mime.rs`

```rust
pub fn mime_for_path(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("pdf") => "application/pdf",
        Some("xml") => "application/xml",
        Some("txt") => "text/plain; charset=utf-8",
        Some("map") => "application/json", // Source maps
        _ => "application/octet-stream",
    }
}
```

---

### B.4: Cache Headers

**Location**: `lib-network/src/web4/cache.rs`

```rust
pub fn cache_headers_for(path: &str, is_spa_entry: bool) -> CacheHeaders {
    if is_spa_entry {
        // index.html - always revalidate
        CacheHeaders {
            cache_control: "no-cache".to_string(),
            ..Default::default()
        }
    } else if is_hashed_asset(path) {
        // main.abc123.js - immutable
        CacheHeaders {
            cache_control: "public, max-age=31536000, immutable".to_string(),
            ..Default::default()
        }
    } else {
        // Other assets - moderate caching
        CacheHeaders {
            cache_control: "public, max-age=3600".to_string(),
            ..Default::default()
        }
    }
}

fn is_hashed_asset(path: &str) -> bool {
    // Detect patterns like main.abc123.js, chunk.def456.css
    // React build outputs have content hashes in filenames
}
```

---

### B.5: Content GET Endpoint

**Location**: `zhtp/src/api/handlers/web4/content.rs`

```rust
// GET /api/v1/web4/content/{domain}/{path...}
async fn get_web4_content(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
    // 1. Parse domain and path from URI
    // 2. Normalize path
    // 3. Call Web4ContentService.get_content()
    // 4. Return raw bytes with headers
}
```

**Route Registration**:
```rust
path if path.starts_with("/api/v1/web4/content/")
    && request.method == ZhtpMethod::Get => {
    self.get_web4_content(request).await
}
```

---

### B.6: Host-Based Gateway Handler

**Location**: `zhtp/src/server/gateway.rs`

```rust
pub struct Web4Gateway {
    content_service: Arc<Web4ContentService>,
}

impl Web4Gateway {
    /// Handle request based on Host header
    pub async fn handle_request(
        &self,
        host: &str,
        path: &str,
        headers: &Headers,
    ) -> Result<GatewayResponse, GatewayError> {
        // 1. Extract domain from host (strip port, validate .zhtp)
        // 2. Normalize path
        // 3. Fetch content via service
        // 4. Return with proper headers
    }
}
```

**Integration in QUIC Handler**:
```rust
// In HTTP compatibility layer
if let Some(host) = headers.get("Host") {
    if host.ends_with(".zhtp") || host.ends_with(".zhtp:9334") {
        let domain = extract_domain(host);
        return gateway.handle_request(domain, path, headers).await;
    }
}
```

**Fallback Route**:
```
GET /web4/{domain}/{path...}
```
For environments where Host header routing isn't available.

---

### B.7: Domain Configuration

**Location**: Update `lib-network/src/web4/domain_registry.rs`

Add fields to `DomainRecord`:
```rust
pub struct DomainRecord {
    // Existing fields...

    /// Content serving mode
    pub content_mode: ContentMode,
    /// SPA entry point (default: "/index.html")
    pub spa_entry: String,
    /// Static asset path prefixes
    pub asset_prefixes: Vec<String>,
    /// Static asset file extensions
    pub asset_extensions: Vec<String>,
}
```

Default for React apps:
```rust
DomainRecord {
    content_mode: ContentMode::Spa,
    spa_entry: "/index.html".to_string(),
    asset_prefixes: vec!["/static/".to_string(), "/assets/".to_string()],
    asset_extensions: vec![
        "js", "css", "png", "jpg", "svg", "ico", "woff", "woff2", "json", "map"
    ].into_iter().map(String::from).collect(),
    ..
}
```

---

### B.8: React Deployment CLI (Optional)

**Location**: `zhtp/src/cli/commands/deploy.rs`

```bash
# Deploy React build to Web4 domain
zhtp deploy ./build --domain myapp.zhtp --mode spa

# Options:
#   --mode static|spa (default: spa)
#   --spa-entry /index.html
#   --asset-prefix /static/,/assets/
```

**Implementation**:
1. Walk build directory
2. Upload each file via `/api/v1/web4/content/publish`
3. Update domain registry with content mappings
4. Set domain content_mode

---

## Testing Plan

### Unit Tests

| Test | Location | Coverage |
|------|----------|----------|
| Path normalization | `lib-network/src/web4/path.rs` | Traversal attacks, encoding |
| MIME detection | `lib-network/src/web4/mime.rs` | All extensions |
| Cache headers | `lib-network/src/web4/cache.rs` | SPA entry, hashed assets |
| SPA fallback | `lib-network/src/web4/content_service.rs` | Route → index.html |
| Asset detection | `lib-network/src/web4/content_service.rs` | Prefixes, extensions |

### Integration Tests

| Test | Description |
|------|-------------|
| Publish and retrieve | Upload file, fetch by domain/path |
| SPA deep link | Request `/users/123`, get index.html |
| Static asset | Request `/static/js/main.js`, get JS with correct MIME |
| 404 handling | Request missing asset, get 404 (not index) |
| ETag/304 | Request with If-None-Match, get 304 |
| Compression | Accept-Encoding: gzip, get compressed response |

### E2E Tests

| Test | Description |
|------|-------------|
| React app loads | Deploy CRA build, verify in browser |
| Client-side routing | Navigate to deep link, refresh works |
| Asset loading | JS/CSS/images load without console errors |
| Hot reload path | Update content, verify change reflected |

---

## File Structure After Implementation

```
lib-network/src/web4/
├── mod.rs
├── content_service.rs    # NEW - Core service
├── path.rs               # NEW - Path normalization
├── mime.rs               # NEW - MIME detection
├── cache.rs              # NEW - Cache headers
├── domain_registry.rs    # MODIFIED - Add content_mode
├── content_publisher.rs  # EXISTING
└── types.rs              # MODIFIED - Add ContentMode

zhtp/src/
├── api/handlers/web4/
│   ├── mod.rs            # MODIFIED - Add GET route
│   ├── content.rs        # MODIFIED - Add get_web4_content
│   └── domains.rs        # EXISTING
├── server/
│   ├── gateway.rs        # NEW - Host-based gateway
│   └── quic_handler.rs   # MODIFIED - Gateway integration
└── cli/commands/
    └── deploy.rs         # NEW (optional) - Deploy CLI
```

---

## Execution Order

### Week 1: PR Reviews
1. Review PR #371 (Unify routing)
2. Review PR #370 (DHT transport)
3. Review PR #387 (DHT through mesh)
4. Review PR #369 (Bootstrap registry)

### Week 2: Core Gateway
5. Create feature branch
6. Implement path normalization
7. Implement MIME detection
8. Implement cache headers
9. Implement Web4ContentService

### Week 3: Integration
10. Implement GET endpoint
11. Implement Host-based gateway
12. Update domain registry schema
13. Integration tests

### Week 4: Polish
14. E2E testing with real React app
15. Deploy CLI (optional)
16. Documentation
17. PR and merge

---

## Success Criteria

Gateway is DONE when:

- [ ] `GET /api/v1/web4/content/myapp.zhtp/index.html` returns HTML
- [ ] `GET /api/v1/web4/content/myapp.zhtp/static/js/main.js` returns JS with correct MIME
- [ ] `GET /api/v1/web4/content/myapp.zhtp/users/123` returns index.html (SPA fallback)
- [ ] `Host: myapp.zhtp` header routes to correct domain content
- [ ] React app loads in browser with no console errors
- [ ] Refresh on deep link (`/users/123`) works
- [ ] Assets have correct cache headers
- [ ] All tests pass

---

## Open Questions

1. **TLS for gateway?** - Use existing QUIC TLS or separate HTTPS?
2. **Domain validation** - Require `.zhtp` suffix or allow any?
3. **Size limits** - Max file size for upload? Max response size?
4. **Compression** - Server-side gzip/brotli or rely on pre-compressed?
5. **Streaming** - Stream large files or buffer entirely?

---

## References

- Phase 0-7 plan from conversation
- DHT layer readiness review
- Open PR analysis
- React SPA serving requirements
