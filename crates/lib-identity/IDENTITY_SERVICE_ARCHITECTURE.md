# Identity Service Architecture Design

## Overview

This document describes the refactoring of `IdentityManager` from a god object (~1,200 lines) into a clean service-oriented architecture using the **Facade Pattern**.

**Key Principle:** Services are PRIVATE implementation details. `IdentityManager` maintains its exact public API and delegates internally. This ensures ZERO breaking changes for ZHTP and other packages.

## Current State (Before Refactoring)

```rust
pub struct IdentityManager {
    // 4 HashMaps directly managed
    identities: HashMap<IdentityId, ZhtpIdentity>,
    private_data: HashMap<IdentityId, PrivateIdentityData>,
    trusted_issuers: HashMap<IdentityId, Vec<CredentialType>>,
    verification_cache: HashMap<IdentityId, IdentityVerification>,
    
    // 2 Components
    password_manager: IdentityPasswordAuth,
    recovery_keys: Vec<RecoveryKey>,
    max_recovery_keys: usize,
}

impl IdentityManager {
    // ~35 public methods mixing concerns:
    // - Storage (add, get, list identities)
    // - Credentials (add, verify, trust issuers)
    // - Cryptography (sign, generate proofs)
    // - Recovery (import, recovery keys)
    // - Passwords (set, validate, change)
    // - Citizen onboarding (complex orchestration)
    // - Wallet operations (deduct, sync balances)
}
```

**Problems:**
- Violates Single Responsibility Principle
- Hard to test individual concerns
- Difficult to understand which methods relate to which responsibility
- 1,200+ lines in single file

## Target Architecture (After Refactoring)

### Service Structure

```
lib-identity/src/identity/
├── manager.rs                    (facade - public API unchanged)
└── services/                     (NEW - private implementation)
    ├── mod.rs                    (internal module exports)
    ├── identity_registry.rs      (storage operations)
    ├── signing_service.rs        (cryptographic operations)
    ├── recovery_service.rs       (recovery operations)
    └── credential_service.rs     (credential management)
```

### 1. IdentityRegistry (Storage Service)

**Responsibility:** Manages identity storage and retrieval.

**File:** `src/identity/services/identity_registry.rs` (~200 lines)

```rust
/// Private service for identity storage operations
pub(super) struct IdentityRegistry {
    identities: HashMap<IdentityId, ZhtpIdentity>,
    private_data: HashMap<IdentityId, PrivateIdentityData>,
}

impl IdentityRegistry {
    pub(super) fn new() -> Self { ... }
    
    // Read operations
    pub(super) fn get_identity(&self, id: &IdentityId) -> Option<&ZhtpIdentity> { ... }
    pub(super) fn get_identity_mut(&mut self, id: &IdentityId) -> Option<&mut ZhtpIdentity> { ... }
    pub(super) fn get_private_data(&self, id: &IdentityId) -> Option<&PrivateIdentityData> { ... }
    pub(super) fn list_identities(&self) -> Vec<&ZhtpIdentity> { ... }
    
    // Write operations
    pub(super) fn add_identity(&mut self, identity: ZhtpIdentity) { ... }
    pub(super) fn add_identity_with_private_data(
        &mut self,
        identity: ZhtpIdentity,
        private_data: PrivateIdentityData
    ) { ... }
    
    // Bulk operations
    pub(super) fn sync_wallet_balances(
        &mut self,
        wallet_balances: &HashMap<String, u64>
    ) -> Result<()> { ... }
}
```

**Key Design Decisions:**
- `pub(super)` visibility - only accessible from parent module
- No business logic - pure CRUD operations
- Mutable vs immutable access explicit
- Simple, predictable interface

---

### 2. SigningService (Cryptographic Service)

**Responsibility:** All cryptographic operations (signing, proof generation).

**File:** `src/identity/services/signing_service.rs` (~150 lines)

```rust
/// Private stateless service for cryptographic operations
pub(super) struct SigningService;

impl SigningService {
    pub(super) fn new() -> Self { Self }
    
    /// Sign a message using identity's private keypair
    pub(super) fn sign_message_for_identity(
        &self,
        private_data: &PrivateIdentityData,
        message: &[u8]
    ) -> Result<lib_crypto::Signature> {
        // Reconstruct keypair from private_data
        // Sign using CRYSTALS-Dilithium2
        ...
    }
    
    /// Get full Dilithium2 public key (1312 bytes)
    pub(super) fn get_dilithium_public_key(
        &self,
        private_data: &PrivateIdentityData
    ) -> Result<Vec<u8>> { ... }
    
    /// Generate zero-knowledge proof for identity requirements
    pub(super) fn generate_identity_proof(
        &self,
        identity: &ZhtpIdentity,
        private_data: &PrivateIdentityData,
        requirements: &IdentityProofParams
    ) -> Result<ZeroKnowledgeProof> { ... }
    
    /// Sign data with post-quantum signature
    pub(super) async fn sign_with_identity(
        &self,
        identity: &ZhtpIdentity,
        private_data: &PrivateIdentityData,
        data: &[u8]
    ) -> Result<PostQuantumSignature> { ... }
    
    // Internal helpers
    async fn generate_pq_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> { ... }
    async fn generate_ownership_proof(
        &self,
        private_key: &[u8],
        public_key: &[u8]
    ) -> Result<ZeroKnowledgeProof> { ... }
}
```

**Key Design Decisions:**
- STATELESS - no fields, only methods
- Dependencies passed as arguments (private_data, identity)
- All cryptographic logic isolated here
- Can be easily unit tested with mock data

---

### 3. RecoveryService (Recovery Operations)

**Responsibility:** Identity recovery from phrases, recovery key management.

**File:** `src/identity/services/recovery_service.rs` (~200 lines)

```rust
/// Private service for identity recovery operations
pub(super) struct RecoveryService {
    recovery_keys: Vec<RecoveryKey>,
    max_recovery_keys: usize,
}

impl RecoveryService {
    pub(super) fn new() -> Self {
        Self {
            recovery_keys: Vec::new(),
            max_recovery_keys: 5,
        }
    }
    
    /// Import identity from 20-word recovery phrase
    pub(super) async fn import_identity_from_phrase(
        &self,
        recovery_phrase: &str
    ) -> Result<(ZhtpIdentity, PrivateIdentityData)> {
        // Validate phrase
        // Derive keys from phrase
        // Create identity structure
        // Return (identity, private_data) for registry storage
        ...
    }
    
    /// Add recovery key for an identity
    pub(super) fn add_recovery_key(&mut self, recovery_key: RecoveryKey) -> Result<()> {
        if self.recovery_keys.len() >= self.max_recovery_keys {
            return Err(anyhow!("Maximum recovery keys reached"));
        }
        ...
    }
    
    /// Remove recovery key by ID
    pub(super) fn remove_recovery_key(&mut self, key_id: &Hash) -> Result<()> { ... }
    
    /// Get recovery key by ID
    pub(super) fn get_recovery_key(&self, key_id: &Hash) -> Option<&RecoveryKey> { ... }
    
    /// Get active (non-expired) recovery keys
    pub(super) fn get_active_recovery_keys(&self) -> Vec<&RecoveryKey> { ... }
    
    /// Clean up expired recovery keys
    pub(super) fn cleanup_expired_recovery_keys(&mut self) { ... }
    
    /// Validate recovery key format
    pub(super) fn validate_recovery_key(&self, encrypted_key: &[u8]) -> bool { ... }
}
```

**Key Design Decisions:**
- Minimal state (just recovery_keys Vec)
- Returns tuples for registry to store
- Validation logic encapsulated
- Expiration cleanup isolated

---

### 4. CredentialService (Credential Management)

**Responsibility:** Credential operations, verification, reputation management.

**File:** `src/identity/services/credential_service.rs` (~250 lines)

```rust
/// Private service for credential management
pub(super) struct CredentialService {
    trusted_issuers: HashMap<IdentityId, Vec<CredentialType>>,
    verification_cache: HashMap<IdentityId, IdentityVerification>,
}

impl CredentialService {
    pub(super) fn new() -> Self {
        Self {
            trusted_issuers: HashMap::new(),
            verification_cache: HashMap::new(),
        }
    }
    
    /// Add credential to identity (modifies identity, updates cache)
    pub(super) async fn add_credential(
        &mut self,
        identity: &mut ZhtpIdentity,
        credential: ZkCredential,
    ) -> Result<()> {
        // Verify credential proof
        // Check trusted issuer
        // Add to identity.credentials
        // Update reputation
        // Clear verification cache
        ...
    }
    
    /// Verify identity against requirements
    pub(super) async fn verify_identity(
        &mut self,
        identity: &ZhtpIdentity,
        requirements: &IdentityProofParams,
    ) -> Result<IdentityVerification> {
        // Check cache first
        // Verify credentials
        // Check age requirements
        // Cache result
        ...
    }
    
    /// Add trusted credential issuer
    pub(super) fn add_trusted_issuer(
        &mut self,
        issuer_id: IdentityId,
        credential_types: Vec<CredentialType>
    ) { ... }
    
    /// Create ZK credential (internal helper)
    pub(super) async fn create_zk_credential(
        &self,
        identity_id: &IdentityId,
        credential_type: CredentialType,
        claim: String,
        expires_at: u64,
    ) -> Result<ZkCredential> { ... }
    
    // Internal helpers
    async fn verify_credential_proof(&self, credential: &ZkCredential) -> Result<bool> { ... }
    async fn update_reputation_for_credential(
        &self,
        identity: &mut ZhtpIdentity,
        credential_type: &CredentialType
    ) -> Result<()> { ... }
}
```

**Key Design Decisions:**
- Owns caching state (verification_cache)
- Modifies identity in-place (passed as `&mut`)
- Business logic for reputation updates
- Cache invalidation handled internally

---

### 5. IdentityManager (Facade)

**Responsibility:** Orchestrate services, maintain public API.

**File:** `src/identity/manager.rs` (~800 lines, down from 1,200)

```rust
use super::services::{
    IdentityRegistry, SigningService, RecoveryService, CredentialService
};

pub struct IdentityManager {
    // Services (private - implementation details)
    registry: IdentityRegistry,
    signing: SigningService,
    recovery: RecoveryService,
    credentials: CredentialService,
    password_manager: IdentityPasswordAuth,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            registry: IdentityRegistry::new(),
            signing: SigningService::new(),
            recovery: RecoveryService::new(),
            credentials: CredentialService::new(),
            password_manager: IdentityPasswordAuth::new(),
        }
    }
    
    // ===== PUBLIC API - UNCHANGED =====
    
    /// Get identity by ID (delegates to registry)
    pub fn get_identity(&self, identity_id: &IdentityId) -> Option<&ZhtpIdentity> {
        self.registry.get_identity(identity_id)
    }
    
    /// Add identity (delegates to registry)
    pub fn add_identity(&mut self, identity: ZhtpIdentity) {
        self.registry.add_identity(identity)
    }
    
    /// Sign message (coordinates registry + signing service)
    pub fn sign_message_for_identity(
        &self,
        identity_id: &IdentityId,
        message: &[u8]
    ) -> Result<lib_crypto::Signature> {
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or_else(|| anyhow!("No private key found"))?;
        
        self.signing.sign_message_for_identity(private_data, message)
    }
    
    /// Add credential (coordinates registry + credentials service)
    pub async fn add_credential(
        &mut self,
        identity_id: &IdentityId,
        credential: ZkCredential,
    ) -> Result<()> {
        // Get mutable identity from registry
        let identity = self.registry.get_identity_mut(identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        
        // Use credentials service to add and update reputation
        self.credentials.add_credential(identity, credential).await
    }
    
    /// Create citizen identity (complex orchestration of ALL services)
    pub async fn create_citizen_identity(
        &mut self,
        display_name: String,
        recovery_options: Vec<String>,
        economic_model: &mut EconomicModel,
    ) -> Result<CitizenshipResult> {
        // 1. Use signing service to generate keypair
        let (private_key, public_key) = self.signing.generate_pq_keypair().await?;
        
        // 2. Create identity structure
        let identity = ZhtpIdentity { ... };
        
        // 3. Create private data
        let private_data = PrivateIdentityData::new(...);
        
        // 4. Store in registry
        self.registry.add_identity_with_private_data(identity, private_data);
        
        // 5. Mark imported for password functionality
        self.password_manager.mark_identity_imported(&id);
        
        // 6. Create privacy credentials using credentials service
        self.credentials.create_zk_credential(...).await?;
        
        // 7. Register for DAO, UBI, Web4 (citizenship module)
        ...
        
        Ok(CitizenshipResult::new(...))
    }
    
    /// Import from phrase (delegates to recovery + registry + password)
    pub async fn import_identity_from_phrase(
        &mut self,
        recovery_phrase: &str,
    ) -> Result<IdentityId> {
        // Use recovery service to parse and derive keys
        let (identity, private_data) = self.recovery
            .import_identity_from_phrase(recovery_phrase)
            .await?;
        
        let identity_id = identity.id.clone();
        
        // Store in registry
        self.registry.add_identity_with_private_data(identity, private_data);
        
        // Mark imported for password functionality
        self.password_manager.mark_identity_imported(&identity_id);
        
        Ok(identity_id)
    }
    
    // ... All other public methods delegate to services similarly
}
```

**Key Design Decisions:**
- Services are private fields (`pub(crate)` at most, but likely just private)
- Public API is IDENTICAL to original
- Methods coordinate between services
- Complex operations orchestrate multiple services
- Simple operations delegate to single service

---

## Method Mapping (Old → New)

| Original Method | Service Delegation |
|----------------|-------------------|
| `get_identity()` | → `registry.get_identity()` |
| `add_identity()` | → `registry.add_identity()` |
| `list_identities()` | → `registry.list_identities()` |
| `get_private_data()` | → `registry.get_private_data()` |
| `sync_wallet_balances()` | → `registry.sync_wallet_balances()` |
| `sign_message_for_identity()` | → `registry.get_private_data()` + `signing.sign_message()` |
| `get_dilithium_public_key()` | → `registry.get_private_data()` + `signing.get_dilithium_public_key()` |
| `generate_identity_proof()` | → `registry.get_identity()` + `registry.get_private_data()` + `signing.generate_identity_proof()` |
| `sign_with_identity()` | → `registry.get_identity()` + `registry.get_private_data()` + `signing.sign_with_identity()` |
| `add_credential()` | → `registry.get_identity_mut()` + `credentials.add_credential()` |
| `verify_identity()` | → `registry.get_identity()` + `credentials.verify_identity()` |
| `add_trusted_issuer()` | → `credentials.add_trusted_issuer()` |
| `import_identity_from_phrase()` | → `recovery.import_identity_from_phrase()` + `registry.add_identity_with_private_data()` + `password_manager.mark_identity_imported()` |
| `add_recovery_key()` | → `recovery.add_recovery_key()` |
| `get_recovery_key()` | → `recovery.get_recovery_key()` |
| `set_identity_password()` | → `registry.get_private_data()` + `password_manager.set_password()` |
| `validate_identity_password()` | → `registry.get_private_data()` + `password_manager.validate_password()` |
| `create_citizen_identity()` | → Orchestrates ALL services (complex) |

---

## Implementation Plan

### Step 13: Create IdentityRegistry (~2 hours)
1. Create `src/identity/services/mod.rs`
2. Create `src/identity/services/identity_registry.rs`
3. Move HashMap fields from manager.rs
4. Implement all storage methods
5. Add unit tests for registry operations

### Step 14: Create SigningService (~2 hours)
1. Create `src/identity/services/signing_service.rs`
2. Move all cryptographic methods from manager.rs
3. Make stateless - accept data as parameters
4. Move helper methods (generate_pq_keypair, generate_ownership_proof)
5. Add unit tests for signing operations

### Step 15: Create RecoveryService (~2 hours)
1. Create `src/identity/services/recovery_service.rs`
2. Move recovery_keys Vec and max_recovery_keys from manager.rs
3. Move import_identity_from_phrase logic
4. Move all RecoveryKey methods
5. Add unit tests for recovery operations

### Step 16: Create CredentialService (~3 hours)
1. Create `src/identity/services/credential_service.rs`
2. Move trusted_issuers and verification_cache HashMaps
3. Move credential methods (add, verify, create_zk_credential)
4. Move helper methods (verify_credential_proof, update_reputation)
5. Add unit tests for credential operations

### Step 17: Refactor IdentityManager (~4 hours)
1. Replace HashMap fields with service instances
2. Update all public methods to delegate to services
3. Verify no public API changes
4. Ensure complex methods properly orchestrate services
5. Remove old implementation code (now in services)

### Step 18: Update Tests (~2 hours)
1. Run existing manager_tests.rs (should pass unchanged)
2. Add service-specific unit tests
3. Fix any broken tests (should be minimal)
4. Run `cargo test --lib` to verify

### Step 19: Verify ZHTP (~1 hour)
1. Build ZHTP: `cargo build` in zhtp/
2. Verify 0 compilation errors
3. Confirms facade pattern success (no ZHTP changes needed)

**Total Estimated Time:** 16-18 hours

---

## Success Metrics

✅ **Architecture:**
- IdentityManager reduced from ~1,200 to ~800 lines
- 4 focused services created (~800 lines total)
- Net code reduction of ~400 lines through deduplication
- Clear separation of concerns established

✅ **Compatibility:**
- Zero breaking changes to public API
- All 40+ ZHTP call sites work unchanged
- All lib-identity tests pass
- ZHTP builds successfully without modifications

✅ **Quality:**
- Each service testable independently
- Reduced complexity in each module
- Better code organization
- Clearer responsibility boundaries

---

## Future Extensions (Out of Scope for Phase 3)

**If ZHTP needs fine-grained control later:**
1. Make services `pub(crate)` in IdentityManager
2. Add getter methods: `pub fn registry(&self) -> &IdentityRegistry`
3. Update ZHTP to use services directly where beneficial
4. No compatibility layer needed - just additional access

**Pattern for other packages:**
- lib-economy can use same facade pattern for MultiWalletManager
- lib-consensus can split ConsensusManager similarly
- lib-blockchain can refactor ValidatorManager

This establishes a proven pattern for manager cleanup across the workspace.
