# lib-economy Documentation

**Version:** 1.0  
**Status:** Production (with minor stubs)

## Overview

`lib-economy` is the comprehensive economic system for Sovereign Network, implementing a **post-scarcity economic model** for Web4. It replaces traditional ISP revenue models with decentralized infrastructure compensation, supports Universal Basic Income (UBI) distribution, and provides sophisticated multi-wallet management for diverse economic activities.

### Core Philosophy

- **Post-Scarcity Economics**: Unlimited token supply based on utility, not artificial scarcity
- **ISP Replacement**: Fair compensation for network infrastructure (routing, storage, bandwidth)
- **DAO-Driven Welfare**: Mandatory 2% DAO fee funds UBI and welfare programs
- **Anti-Speculation**: Token value derived from network utility, not trading speculation
- **Infrastructure-First**: Rewards genuine network participation over financial games

## Key Features

### Economic Model (`models/`)
- Fee calculation with mandatory DAO contribution (2%)
- Infrastructure-based reward calculations
-  economics with fair compensation
- Dynamic pricing based on network conditions

### Multi-Wallet System (`wallets/`)
- **10 specialized wallet types** for different economic activities
- Identity-integrated wallet management
- Comprehensive transaction history
- Balance tracking and wallet lifecycle management

### Treasury Economics (`treasury_economics/`)
- DAO treasury management with transparent fund allocation
- 40% UBI allocation, 30% welfare allocation, 30% development
- Treasury sustainability calculations
- Funding gap analysis and distribution planning

### Transaction System (`transactions/`)
- Comprehensive transaction structure with fee tracking
- DAO fee proof generation
- Priority-based fee calculation
- Transaction validation and creation

### Token Rewards (`models/token_reward.rs`)
- Infrastructure service rewards (routing, storage, compute)
-  rewards for bandwidth sharing
- Quality and uptime bonuses
- Multi-source reward combination

### Network Participation (`incentives/`)
- Bandwidth sharing rewards
- Mesh networking incentives
- Anti-Sybil design (rewards infrastructure, not node count)
- Connectivity provision rewards

### Supply Management (`supply/`)
- Utility-based token minting (post-scarcity)
- Supply statistics tracking
- Unlimited max supply (no artificial caps)

### Pricing System (`pricing/`)
- Dynamic pricing based on network congestion
- Priority-based price adjustments
- Infrastructure service pricing tables

## Implementation Status

###  Fully Implemented Modules

- `models/` - Economic model, token rewards, DAO treasury
- `wallets/` - Multi-wallet manager with 10 wallet types
- `treasury_economics/` - Treasury calculations and fund allocation
- `transactions/` - Transaction creation, validation, fee processing
- `incentives/` - Network participation rewards
- `pricing/` - Dynamic pricing and market calculations
- `supply/` - Supply management and token minting
- `types/` - Core type definitions
- `wasm/` - WASM compatibility layer
- `integration/` - Integration testing utilities

###  Stub/Incomplete Modules

1. **`distribution/ubi_distribution.rs`** - STUB
   - Current: Empty placeholder function
   - Needed: Full UBI distribution implementation
   - Impact: UBI cannot be distributed to citizens yet

2. **`rewards/reward_calculator.rs`** - EMPTY
   - Current: Completely empty file
   - Needed: Reward calculation aggregation and distribution logic
   - Impact: Cannot calculate comprehensive node rewards yet

### Notes
- The stub modules do not block core functionality
- Token rewards are calculated in `models/token_reward.rs` (fully implemented)
- Treasury UBI calculations work in `treasury_economics/` (fully implemented)
- Only the distribution execution and aggregation layers are missing

## Quick Start

```rust
use lib_economy::{
    EconomicModel,
    MultiWalletManager,
    DaoTreasury,
    Transaction,
    TokenReward,
    TransactionType,
    Priority,
};

// Initialize economic model
let model = EconomicModel::new();

// Create multi-wallet manager
let mut wallet_manager = MultiWalletManager::new([0u8; 32])?;
wallet_manager.create_wallet("Personal", WalletType::Personal)?;

// Create and process transaction
let tx = Transaction::new_payment(
    sender_address,
    recipient_address,
    1000, // 1000 SOV
    Priority::Normal,
)?;

// Calculate infrastructure rewards
let rewards = TokenReward::calculate(&work_metrics, &model)?;

// Manage DAO treasury
let mut treasury = DaoTreasury::new();
treasury.receive_dao_fee(dao_fee)?;
treasury.allocate_funds()?;
```

## Documentation Structure

- **[INDEX.md](./INDEX.md)** - Complete file and module listing
- **[OVERVIEW.md](./OVERVIEW.md)** - Architecture and design philosophy
- **[API_REFERENCE.md](./API_REFERENCE.md)** - Complete API documentation
- **[EXAMPLES.md](./EXAMPLES.md)** - Usage examples and tutorials
- **[SUMMARY.md](./SUMMARY.md)** - Quick reference and cheat sheet

### Module Documentation

- **[models.md](./models.md)** - Economic model, token rewards, DAO treasury
- **[wallets.md](./wallets.md)** - Multi-wallet system documentation
- **[treasury_economics.md](./treasury_economics.md)** - Treasury management and calculations
- **[transactions.md](./transactions.md)** - Transaction system and fee processing
- **[incentives.md](./incentives.md)** - Network participation rewards
- **[distribution.md](./distribution.md)** - UBI and welfare distribution (stub status noted)
- **[rewards.md](./rewards.md)** - Reward calculation system (empty status noted)
- **[supply.md](./supply.md)** - Token supply management
- **[pricing.md](./pricing.md)** - Dynamic pricing system
- **[types.md](./types.md)** - Core type definitions
- **[wasm.md](./wasm.md)** - WASM compatibility layer
- **[integration.md](./integration.md)** - Integration testing

## Economic Constants

```rust
pub const DEFAULT_DAO_FEE_RATE: u64 = 200; // 2% (200 basis points)
pub const ISP_BYPASS_CONNECTIVITY_RATE: u64 = 100; // 100 SOV per GB bandwidth
pub const ISP_BYPASS_MESH_RATE: u64 = 1; // 1 SOV per MB packets routed
pub const ISP_BYPASS_UPTIME_BONUS: u64 = 10; // 10 SOV per hour uptime
pub const MESH_CONNECTIVITY_THRESHOLD: u32 = 3; // Minimum peers for rewards
pub const MIN_STAKING_AMOUNT: u64 = 1000; // 1000 SOV minimum stake
pub const UBI_ALLOCATION_PERCENTAGE: u64 = 40; // 40% of DAO fees to UBI
pub const WELFARE_ALLOCATION_PERCENTAGE: u64 = 30; // 30% to welfare
pub const DEVELOPMENT_ALLOCATION_PERCENTAGE: u64 = 30; // 30% to development
```

## Architecture Principles

1. **Post-Scarcity Model**: Unlimited token supply, minted based on network utility
2. **Infrastructure Economics**: Fair compensation for bandwidth, storage, routing
3. **DAO Governance**: Transparent fund allocation with mandatory contributions
4. **Anti-Sybil Design**: Rewards genuine infrastructure, not node proliferation
5. **Identity Integration**: Wallets tied to verified identities
6. **Fee Transparency**: Clear fee breakdown (base + DAO)
7. **Welfare Priority**: 70% of DAO fees fund UBI and welfare

## Use Cases

- **ISP Replacement**: Earn SOV by sharing bandwidth and routing packets
- **Storage Provider**: Earn SOV by providing decentralized storage
- **Mesh Networking**: Maintain network connectivity for consistent rewards
- **UBI Recipient**: Receive regular UBI distributions from DAO treasury
- **Application Developer**: Build economic applications with multi-wallet support
- **DAO Participant**: Contribute to and benefit from treasury operations

## Integration with Other Libraries

- **lib-identity**: Wallet management requires verified identities
- **lib-blockchain**: Transactions recorded on blockchain
- **lib-crypto**: Cryptographic operations for addresses and proofs
- **lib-network**: Network participation metrics for rewards

## Contributing

When extending lib-economy:
1. Maintain post-scarcity economic principles
2. Ensure DAO fee integration in all transactions
3. Design for anti-Sybil resistance
4. Document economic rationale for all formulas
5. Add comprehensive tests for economic calculations

## Support

For questions or issues:
- Review module documentation in `docs/`
- Check examples in `EXAMPLES.md`
- Examine tests in `tests/`
- Consult API reference in `API_REFERENCE.md`
