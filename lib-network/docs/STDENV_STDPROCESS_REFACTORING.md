# std::env and std::process Refactoring Plan

**Issue**: #482 - Audit std::env/std::process usage in lib-network
**Status**: Planning Phase
**Priority**: Medium

---

## Executive Summary

The `lib-network` crate has architecture rules forbidding `std::env` and `std::process` APIs due to sandboxing conflicts, implicit dependencies, and deployment issues. This document outlines a comprehensive refactoring strategy to eliminate non-essential usages while preserving necessary functionality.

### Current State
- **Total std::env usages**: 9 (5 distinct locations)
- **Total std::process usages**: 80+ (mostly imports and test code)
- **Architecture compliance**: ~40% (many necessary usages)

---

## Audit Results

### std::env Usage Breakdown

| Location | Usage | Type | Refactoring Priority |
|----------|-------|------|----------------------|
| `zhtp_client.rs:133, 187` | `env::var("ZHTP_ALLOW_BOOTSTRAP")` | Feature gating | HIGH |
| `web4/client.rs:179` | `env::var("ZHTP_ALLOW_BOOTSTRAP")` | Feature gating | HIGH |
| `bootstrap/handshake.rs:448` | `env::var("ZHTP_ALLOW_NET_TESTS")` | Test feature gating | MEDIUM |
| `protocols/wifi_direct_handshake.rs:547` | `env::var("ZHTP_ALLOW_NET_TESTS")` | Test feature gating | MEDIUM |
| `web4/client.rs:117` | `std::env::temp_dir()` | Cache storage | MEDIUM |
| `web4/trust.rs:387` | `env!("CARGO_PKG_VERSION")` | Compile-time macro | LOW |
| `web4/client.rs:117` | `std::process::id()` | Process ID generation | MEDIUM |

### std::process Usage Breakdown

| Category | Count | Status |
|----------|-------|--------|
| Imports | 60+ | Mostly in test modules (#[cfg(test)]) |
| Direct calls | 20+ | Hardware discovery, platform-specific utilities |
| Test gates | Multiple | Already #[cfg(test)] protected |

---

## Refactoring Strategy

### PHASE 1: High-Priority Changes (Bootstrap Mode)

#### Problem
Three instances of `env::var("ZHTP_ALLOW_BOOTSTRAP")` check environment variables at runtime to enable/disable bootstrap mode. This creates:
- Implicit dependency on environment configuration
- Non-portable behavior across containerized environments
- WASM incompatibility

#### Solution: Dependency Injection via Configuration Struct

**Before:**
```rust
// zhtp_client.rs line 133
let allowed = env::var("ZHTP_ALLOW_BOOTSTRAP")
    .ok()
    .map(|v| v == "1")
    .unwrap_or(false);
```

**After:**
Create a `ZhtpClientConfig` struct that encapsulates bootstrap settings:

```rust
pub struct ZhtpClientConfig {
    /// Allow bootstrap mode for initial peer discovery
    pub allow_bootstrap: bool,
    /// Custom bootstrap peers (replaces environment dependency)
    pub bootstrap_peers: Vec<String>,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
}

impl Default for ZhtpClientConfig {
    fn default() -> Self {
        Self {
            allow_bootstrap: false,  // Safe default
            bootstrap_peers: vec![],
            connection_timeout_ms: 30000,
        }
    }
}

impl ZhtpClient {
    /// Create with explicit configuration
    pub async fn with_config(config: ZhtpClientConfig) -> Result<Self> {
        // Use config.allow_bootstrap instead of env var
        let allowed = config.allow_bootstrap;
        // ... rest of initialization
    }
}
```

**Files to modify:**
1. `src/client/zhtp_client.rs` - Add ZhtpClientConfig struct, update constructor
2. `src/web4/client.rs` - Use ZhtpClientConfig in Web4Client initialization
3. Tests/examples - Pass config instead of relying on env vars

**Benefits:**
- ✅ Explicit configuration makes bootstrap behavior visible
- ✅ Works in containerized/WASM environments
- ✅ Easier testing (no env var mocking)
- ✅ Type-safe configuration

---

### PHASE 2: Medium-Priority Changes (Temp Directory & Process ID)

#### Problem
`web4/client.rs:117` uses both `std::env::temp_dir()` and `std::process::id()` to create a unique temporary directory:

```rust
let temp_dir = std::env::temp_dir().join(format!("web4_client_{}", std::process::id()));
```

Issues:
- Environment-dependent temp directory location
- Process ID-based uniqueness not reliable across restarts
- WASM incompatible

#### Solution 1: Dependency Injection (Preferred)

```rust
pub struct Web4ClientConfig {
    /// Custom cache directory. If None, uses system temp + UUID
    pub cache_dir: Option<PathBuf>,
    /// Unique session identifier (UUID by default)
    pub session_id: String,
}

impl Default for Web4ClientConfig {
    fn default() -> Self {
        Self {
            cache_dir: None,
            session_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

impl Web4Client {
    pub async fn with_config(config: Web4ClientConfig) -> Result<Self> {
        let cache_dir = if let Some(dir) = config.cache_dir {
            dir
        } else {
            // Only as fallback: use standard directories crate
            let project_dirs = directories::ProjectDirs::from("", "", "web4_client")
                .ok_or(Error::NoCacheDir)?;
            project_dirs.cache_dir().to_path_buf()
        };

        let session_cache = cache_dir.join(&config.session_id);
        // ... rest of initialization
    }
}
```

#### Solution 2: Use `uuid` Crate Instead of Process ID

For the nonce cache file naming, replace `std::process::id()` with a UUID:

```rust
use uuid::Uuid;

let session_id = Uuid::new_v4().to_string();
let cache_file = format!("web4_client_{}.cache", session_id);
```

**Files to modify:**
1. `src/web4/client.rs` - Add Web4ClientConfig, use UUID for uniqueness
2. `Cargo.toml` - Add `uuid` and `directories` dependencies (if not present)
3. Tests - Pass custom cache dir config

**Benefits:**
- ✅ Explicit cache directory configuration
- ✅ UUID-based uniqueness (more reliable than PID)
- ✅ Works across restarts and containerized envs
- ✅ Optional environment use only as fallback

---

### PHASE 3: Test Feature Gating (Bootstrap/Network Tests)

#### Problem
Two instances of `env::var("ZHTP_ALLOW_NET_TESTS")` check for test authorization:

```rust
// bootstrap/handshake.rs:448
std::env::var("ZHTP_ALLOW_NET_TESTS")
```

#### Solution: Use Existing Test Feature Flag System

Rather than environment variables, use Rust's `#[cfg(test)]` and feature flags:

```rust
// Cargo.toml
[features]
default = []
allow-net-tests = []  # Only enabled in testing profiles

// Code
#[cfg(all(test, feature = "allow-net-tests"))]
fn test_network_operation() {
    // Test code only compiles with feature
}

// Or use build.rs to detect test environment
#[cfg(test)]
const ALLOW_NET_TESTS: bool = cfg!(feature = "allow-net-tests");
```

**Alternative**: If env var checking is required for integration tests, create a builder with explicit opt-in:

```rust
pub struct HandshakeBuilder {
    pub allow_net_tests: bool,
}

impl Default for HandshakeBuilder {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            allow_net_tests: cfg!(feature = "allow-net-tests"),
            #[cfg(not(test))]
            allow_net_tests: false,
        }
    }
}
```

**Files to modify:**
1. `Cargo.toml` - Add `allow-net-tests` feature
2. `src/bootstrap/handshake.rs` - Replace env var with feature flag
3. `src/protocols/wifi_direct_handshake.rs` - Same change
4. Test configuration files - Enable feature in test profiles

**Benefits:**
- ✅ Compile-time safety (tests can't accidentally enable in production)
- ✅ No runtime environment variable lookups
- ✅ Works in all deployment scenarios
- ✅ Explicit in Cargo.toml what's enabled

---

### PHASE 4: std::process::Command Usages

#### Current State
The 20+ `std::process::Command` usages are LEGITIMATE and NECESSARY for:

1. **Hardware Discovery**
   - `airport`, `wpa_cli`, `iwlist` - WiFi hardware detection
   - `lsusb`, `lsmod` - USB/device enumeration
   - `bluetoothctl`, `sdptool` - Bluetooth capability detection
   - `system_profiler` - macOS hardware info

2. **Platform-Specific Operations**
   - `ip`, `ifconfig`, `ipconfig` - Network interface enumeration
   - `sudo`, `networksetup` - Platform-specific configuration
   - `ping`, `wmic` - Connectivity and system info

3. **Test Modules**
   - Most usages are in `#[cfg(test)]` sections
   - Protected by platform-specific `#[cfg(target_os = "...")]` gates

#### Recommendation: NO REFACTORING REQUIRED

These are architecture-justified exceptions:

**Rationale:**
1. **Unavoidable**: Hardware discovery requires platform APIs, no Rust library provides uniform abstraction
2. **Protected**: Test modules and platform-specific code is isolated
3. **Isolated**: Not in hot paths or core routing logic
4. **Documented**: Clear comments explain why these are necessary

**Action**: Document in architecture rules that `std::process::Command` for hardware discovery is an approved exception.

---

### PHASE 5: Compile-Time Safe Uses (env! macro)

#### Current Usage
`web4/trust.rs:387` uses `env!("CARGO_PKG_VERSION")` compile-time macro:

```rust
tool_version: env!("CARGO_PKG_VERSION").to_string(),
```

#### Status: NO REFACTORING REQUIRED

**Rationale:**
- ✅ Compile-time macro, not runtime dependency
- ✅ Evaluated at build time, not affected by environment
- ✅ Safe in containerized/WASM environments
- ✅ Common Rust idiom for version embedding

---

## Implementation Priority & Timeline

### Phase 1: Bootstrap Configuration (HIGH - 2-3 files)
**Impact**: Removes 3 env var usages
**Effort**: 1-2 hours
**Files**: zhtp_client.rs, web4/client.rs, tests

### Phase 2: Temp Directory & UUID (MEDIUM - 1 file)
**Impact**: Removes std::env::temp_dir() and std::process::id()
**Effort**: 1-2 hours
**Files**: web4/client.rs, Cargo.toml

### Phase 3: Test Feature Gates (MEDIUM - 2 files)
**Impact**: Removes 2 test-related env var usages
**Effort**: 1 hour
**Files**: bootstrap/handshake.rs, wifi_direct_handshake.rs, Cargo.toml

### Phase 4: Document std::process Exceptions (LOW - 30 min)
**Impact**: Clarifies architecture compliance
**Effort**: 30 minutes
**Files**: ARCHITECTURE.md (this document)

---

## Migration Path for Consumers

### Breaking Changes
The refactoring introduces these breaking changes for consumers:

1. **ZhtpClient initialization** requires configuration struct
2. **Web4Client initialization** requires configuration struct
3. **Handshake tests** require feature flag enablement

### Migration Guide for Users

**Before:**
```rust
// Old: Environment-dependent
std::env::set_var("ZHTP_ALLOW_BOOTSTRAP", "1");
let client = ZhtpClient::new().await?;
```

**After:**
```rust
// New: Explicit configuration
let config = ZhtpClientConfig {
    allow_bootstrap: true,
    bootstrap_peers: vec!["peer1.example.com".to_string()],
    ..Default::default()
};
let client = ZhtpClient::with_config(config).await?;
```

### Version Strategy
- Implement changes on new branch
- Bump minor version (1.x.0 → 1.(x+1).0)
- Provide migration guide in CHANGELOG
- Maintain example code in documentation

---

## Validation Checklist

- [ ] All Phase 1 configuration structs created
- [ ] ZhtpClient updated with dependency injection
- [ ] Web4Client updated with custom cache dir + UUID
- [ ] Test feature gates working correctly
- [ ] All existing tests pass with new config
- [ ] Documentation updated with examples
- [ ] No remaining std::env::var() calls (except tests)
- [ ] No remaining std::process::id() calls
- [ ] std::env::temp_dir() only used as fallback
- [ ] std::process::Command usages documented as necessary
- [ ] ARCHITECTURE.md updated with compliance notes
- [ ] PR created with migration guide

---

## Architecture Compliance Summary

### Violations Eliminated
- ✅ env::var("ZHTP_ALLOW_BOOTSTRAP") → ZhtpClientConfig
- ✅ env::var("ZHTP_ALLOW_NET_TESTS") → Feature flags
- ✅ std::env::temp_dir() → Dependency injection + UUID
- ✅ std::process::id() → UUID generation

### Justified Exceptions (Documented)
- ✅ std::process::Command for hardware discovery (unavoidable)
- ✅ env!() compile-time macros (safe)
- ✅ std::env::consts in documentation (not production)

### Final Status
After implementation: **100% compliance** with architecture rules.

---

## References

- **Original Issue**: https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/482
- **Architecture Document**: ./ARCHITECTURE.md
- **Related Issues**: #512 (Ubuntu compatibility), #516 (ZHTP encryption)
