# lib-economy Module Index

Complete listing of all files, modules, and components in the lib-economy library.

## Core Entry Point

### `src/lib.rs`
Main library entry point defining module structure and economic constants.

**Exports:**
- All public types, models, and functions
- Economic constants (DAO fees, ISP rates, allocation percentages)
- Module organization

**Key Constants:**
```rust
DEFAULT_DAO_FEE_RATE = 200 (2%)
ISP_BYPASS_CONNECTIVITY_RATE = 100 SOV/GB
ISP_BYPASS_MESH_RATE = 1 SOV/MB
ISP_BYPASS_UPTIME_BONUS = 10 SOV/hour
MESH_CONNECTIVITY_THRESHOLD = 3 peers
MIN_STAKING_AMOUNT = 1000 SOV
UBI_ALLOCATION_PERCENTAGE = 40%
WELFARE_ALLOCATION_PERCENTAGE = 30%
DEVELOPMENT_ALLOCATION_PERCENTAGE = 30%
```

## Module Structure

### 1. Models (`src/models/`)
Core economic models and calculations.

**Files:**
- `mod.rs` - Module organization and fee calculation functions
- `economic_model.rs` - Main economic model with fee processing (197 lines) 
- `token_reward.rs` - Token reward calculations for infrastructure (216 lines) 
- `dao_treasury.rs` - DAO treasury management and fund allocation (Full) 

**Status:** Fully implemented

### 2. Wallets (`src/wallets/`)
Multi-wallet system for diverse economic activities.

**Files:**
- `mod.rs` - Module organization
- `multi_wallet.rs` - Comprehensive multi-wallet manager (896 lines) 

**Key Types:**
- `WalletType` - 10 specialized wallet types
- `Wallet` - Individual wallet structure
- `MultiWalletManager` - Manages all wallets for an identity

**Status:** Fully implemented

### 3. Treasury Economics (`src/treasury_economics/`)
DAO treasury operations and fund allocation.

**Files:**
- `mod.rs` - Module organization and DaoTreasury export
- `treasury_calculations.rs` - Treasury calculation algorithms (157 lines) 

**Key Functions:**
- `calculate_optimal_ubi_per_citizen()`
- `calculate_welfare_efficiency()`
- `calculate_ubi_efficiency()`
- `calculate_treasury_sustainability()`
- `calculate_ubi_funding_gap()`

**Status:** Fully implemented

### 4. Transactions (`src/transactions/`)
Transaction creation, validation, and fee processing.

**Files:**
- `mod.rs` - Module organization
- `transaction.rs` - Core transaction structure (159 lines) 
- `creation.rs` - Transaction creation utilities 
- `validation.rs` - Transaction validation logic 
- `fee_processing.rs` - Fee calculation and processing 
- `dao_fee_proofs.rs` - DAO fee proof generation 
- `priority_fees.rs` - Priority-based fee adjustments 

**Status:** Fully implemented

### 5. Incentives (`src/incentives/`)
Network participation and infrastructure rewards.

**Files:**
- `mod.rs` - Module organization
- `network_participation.rs` - Network participation rewards (168 lines) 

**Key Structures:**
- `NetworkParticipationRewards` - Bandwidth, mesh, connectivity rewards
- Anti-Sybil reward mechanisms

**Status:** Fully implemented

### 6. Distribution (`src/distribution/`)
UBI and welfare distribution system.

**Files:**
- `mod.rs` - Module organization
- `ubi_distribution.rs` - UBI distribution implementation  **STUB**

**Status:**  STUB - Needs full implementation
- Current: Single placeholder function `distribute_ubi_to_citizens() -> Result<()> { Ok(()) }`
- Needed: Full distribution logic, citizen tracking, periodic distribution scheduling

### 7. Rewards (`src/rewards/`)
Comprehensive reward calculation and distribution.

**Files:**
- `mod.rs` - Module organization
- `reward_calculator.rs` - Reward aggregation  **EMPTY**

**Status:**  EMPTY - Completely unimplemented
- Current: Empty file (0 bytes)
- Needed: Reward aggregation from multiple sources, distribution logic, historical tracking

**Note:** Token reward calculations exist in `models/token_reward.rs` (fully implemented)

### 8. Supply (`src/supply/`)
Token supply management and minting.

**Files:**
- `mod.rs` - Module organization
- `management.rs` - Supply management implementation (Full) 
- `total_supply.rs` - Total supply tracking 

**Key Structures:**
- `SupplyManager` - Manages token minting and supply tracking

**Status:** Fully implemented

### 9. Pricing (`src/pricing/`)
Dynamic pricing based on network conditions.

**Files:**
- `mod.rs` - Module organization
- `dynamic_pricing.rs` - Dynamic price calculation (Full) 
- `market_pricing.rs` - Market-based pricing 

**Key Functions:**
- `calculate_dynamic_price()` - Congestion and priority-based pricing
- `calculate_price_adjustment()` - Supply/demand adjustments
- `get_infrastructure_pricing()` - Infrastructure service rates

**Status:** Fully implemented

### 10. Types (`src/types/`)
Core type definitions used throughout the system.

**Files:**
- `mod.rs` - Type exports and organization
- Various type definition files

**Key Types:**
- `TransactionType` - Payment, Reward, UbiDistribution, etc.
- `Priority` - Low, Normal, High, Urgent
- `WorkMetrics` - Infrastructure work tracking
- `IspBypassWork` - ISP replacement work metrics
- `WalletType` - 10 specialized wallet types

**Status:** Fully implemented

### 11. WASM (`src/wasm/`)
WebAssembly compatibility layer.

**Files:**
- `mod.rs` - WASM module organization
- `compatibility.rs` - Cross-platform compatibility functions
- `logging.rs` - WASM-compatible logging
- Various WASM utilities

**Key Functions:**
- `current_timestamp()` - Cross-platform timestamp
- `hash_blake3()` - BLAKE3 hashing
- `info!()`, `error!()` - Logging macros

**Status:** Fully implemented

### 12. Integration (`src/integration/`)
Integration testing and utilities.

**Files:**
- `mod.rs` - Integration module organization
- Test utilities and mock implementations

**Status:** Fully implemented

### 13. Testing (`src/testing/`)
Test utilities and mock implementations.

**Files:**
- `mod.rs` - Testing module organization
- `mocks.rs` - Mock implementations for testing
- `test_utils.rs` - Test utility functions

**Status:** Fully implemented

### 14. Network Types (`src/network_types.rs`)
Network-specific type definitions.

**Files:**
- `network_types.rs` - Current network types
- `network_types_new.rs` - New network types (migration?)
- `network_types_old.rs` - Legacy network types (migration?)

**Status:** Fully implemented (may have migration artifacts)

## Documentation Files

### Root Documentation
- `README.md` - Project overview and quick start
- `Cargo.toml` - Project configuration and dependencies

### docs/ Directory
- `README.md` - Main documentation entry point
- `INDEX.md` - This file - complete module index
- `OVERVIEW.md` - Architecture and design philosophy
- `API_REFERENCE.md` - Complete API documentation
- `EXAMPLES.md` - Usage examples and tutorials
- `SUMMARY.md` - Quick reference guide
- `models.md` - Economic model documentation
- `wallets.md` - Multi-wallet system documentation
- `treasury_economics.md` - Treasury management guide
- `transactions.md` - Transaction system documentation
- `incentives.md` - Network participation rewards
- `distribution.md` - Distribution system (stub status noted)
- `rewards.md` - Reward calculation (empty status noted)
- `supply.md` - Supply management documentation
- `pricing.md` - Pricing system guide
- `types.md` - Type definitions reference
- `wasm.md` - WASM compatibility guide
- `integration.md` - Integration testing documentation

## Implementation Statistics

### Completed Modules: 11/13 (85%)
 models - Economic model and token rewards  
 wallets - Multi-wallet system  
 treasury_economics - Treasury management  
 transactions - Transaction system  
 incentives - Network participation  
 supply - Supply management  
 pricing - Dynamic pricing  
 types - Type definitions  
 wasm - WASM compatibility  
 integration - Integration utilities  
 testing - Test utilities  

### Stub/Incomplete Modules: 2/13 (15%)
 distribution - UBI distribution (stub)  
 rewards - Reward calculator (empty)  

### Total Lines of Code (Estimated)
- **Models**: ~650 lines
- **Wallets**: ~900 lines
- **Treasury**: ~400 lines
- **Transactions**: ~800 lines
- **Incentives**: ~250 lines
- **Supply**: ~150 lines
- **Pricing**: ~200 lines
- **Types**: ~500 lines
- **WASM**: ~300 lines
- **Other**: ~500 lines
- **Total**: ~4,650 lines of production code

## Quick Navigation

- **Getting Started**: See [README.md](./README.md) and [EXAMPLES.md](./EXAMPLES.md)
- **Architecture**: See [OVERVIEW.md](./OVERVIEW.md)
- **API Reference**: See [API_REFERENCE.md](./API_REFERENCE.md)
- **Module Details**: See individual module documentation files
- **Integration**: See [integration.md](./integration.md)

## File Count Summary

- **Source Files**: ~50+ Rust files
- **Documentation Files**: 18 markdown files
- **Test Files**: Included in modules
- **Configuration**: Cargo.toml, README.md

## Module Dependencies

```
lib-economy
├── lib-identity (wallet identity integration)
├── lib-blockchain (transaction recording)
├── lib-crypto (cryptographic operations)
├── lib-network (network metrics)
└── External crates (serde, anyhow, etc.)
```

## Critical Paths

### Transaction Flow
1. `transactions/creation.rs` - Create transaction
2. `transactions/validation.rs` - Validate transaction
3. `models/economic_model.rs` - Calculate fees
4. `transactions/fee_processing.rs` - Process fees
5. `treasury_economics/mod.rs` - Allocate DAO fees

### Reward Flow
1. `types/` - Define work metrics
2. `models/token_reward.rs` - Calculate rewards
3. `incentives/network_participation.rs` - Calculate participation bonuses
4.  `rewards/reward_calculator.rs` - **MISSING** - Aggregate and distribute

### UBI Flow
1. `treasury_economics/` - Calculate optimal UBI amount
2. `treasury_economics/treasury_calculations.rs` - Verify funding
3.  `distribution/ubi_distribution.rs` - **STUB** - Execute distribution
4. `transactions/transaction.rs` - Create UBI transactions

## Next Steps for Complete Implementation

1. **Implement `distribution/ubi_distribution.rs`**
   - Citizen tracking and verification
   - Periodic distribution scheduling
   - Distribution transaction creation
   - Anti-fraud mechanisms

2. **Implement `rewards/reward_calculator.rs`**
   - Aggregate rewards from multiple sources
   - Historical reward tracking
   - Distribution scheduling
   - Reward verification and proof generation

3. **Testing**
   - Integration tests for UBI distribution
   - Integration tests for reward calculation
   - End-to-end economic flow tests

## Related Documentation

- [lib-protocols Documentation](../../lib-protocols/docs/README.md)
- [lib-blockchain Documentation](../../lib-blockchain/docs/README.md)
- [lib-identity Documentation](../../lib-identity/docs/README.md)
