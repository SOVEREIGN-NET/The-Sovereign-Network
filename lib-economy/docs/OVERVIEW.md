# lib-economy Architecture Overview

## Vision: Post-Scarcity Economics for Web4

lib-economy implements a radical departure from traditional blockchain economics, creating a **post-scarcity economic model** where tokens are minted based on utility rather than artificial scarcity. The system replaces traditional ISP revenue models with fair compensation for infrastructure services while funding Universal Basic Income (UBI) through mandatory DAO contributions.

## Core Economic Principles

### 1. Post-Scarcity Model

**Traditional Blockchain Economics (Bitcoin, Ethereum):**
- Fixed supply cap creates artificial scarcity
- Value driven by speculation and trading
- Deflationary pressure rewards hoarding
- Limited utility, primarily for transfers

**Sovereign Network Economics (lib-economy):**
- Unlimited token supply based on network utility
- Value derived from actual infrastructure services
- Inflationary design rewards productive use
- Comprehensive economic activities (10+ wallet types)

```rust
// Post-scarcity: mint based on utility, not speculation
pub struct SupplyManager {
    pub current_supply: u64,
    pub max_supply: u64::MAX, // No artificial cap
}
```

### 2. ISP Replacement Economics

The system compensates network participants similarly to how ISPs and CDNs operate, but decentralized:

**Infrastructure Services:**
- **Routing**: 1 SOV per MB of data routed
- **Storage**: 10 SOV per GB stored per month
- **Bandwidth**: 100 SOV per GB bandwidth shared
- **Uptime**: 10 SOV per hour of consistent availability

**Anti-ISP Monopoly:**
- No single provider controls infrastructure
- Fair compensation for all participants
- Quality and uptime bonuses incentivize reliability
- Anti-Sybil design prevents gaming the system

```rust
pub const ISP_BYPASS_CONNECTIVITY_RATE: u64 = 100; // 100 SOV per GB
pub const ISP_BYPASS_MESH_RATE: u64 = 1;           // 1 SOV per MB routed
pub const ISP_BYPASS_UPTIME_BONUS: u64 = 10;       // 10 SOV per hour
```

### 3. DAO-Driven Welfare System

Every transaction (except UBI/welfare distributions) contributes 2% to the DAO treasury:

**Fund Allocation:**
- **40% UBI**: Universal Basic Income for all verified citizens
- **30% Welfare**: Emergency assistance and social programs
- **30% Development**: Network development and maintenance

**Transparency:**
- All allocations on-chain and auditable
- Efficiency metrics track distribution vs collection
- Sustainability calculations predict treasury health

```rust
pub const DEFAULT_DAO_FEE_RATE: u64 = 200;          // 2% (200 basis points)
pub const UBI_ALLOCATION_PERCENTAGE: u64 = 40;      // 40% to UBI
pub const WELFARE_ALLOCATION_PERCENTAGE: u64 = 30;  // 30% to welfare
pub const DEVELOPMENT_ALLOCATION_PERCENTAGE: u64 = 30; // 30% to development
```

## System Architecture

### High-Level Component Interaction

```
┌─────────────────────────────────────────────────────────────────┐
│                         lib-economy                              │
│                                                                   │
│  ┌────────────────┐      ┌────────────────┐                     │
│  │   Economic     │◄────►│   Treasury     │                     │
│  │    Model       │      │   Economics    │                     │
│  │                │      │                │                     │
│  │ • Fee calc     │      │ • DAO fees     │                     │
│  │ • Rewards      │      │ • UBI alloc    │                     │
│  │ • Parameters   │      │ • Welfare      │                     │
│  └────────┬───────┘      └────────┬───────┘                     │
│           │                       │                              │
│           ▼                       ▼                              │
│  ┌────────────────┐      ┌────────────────┐                     │
│  │ Transactions   │◄────►│  Multi-Wallet  │                     │
│  │                │      │    Manager     │                     │
│  │ • Creation     │      │                │                     │
│  │ • Validation   │      │ • 10 types     │                     │
│  │ • Fee process  │      │ • Identity     │                     │
│  └────────┬───────┘      └────────┬───────┘                     │
│           │                       │                              │
│           ▼                       ▼                              │
│  ┌─────────────────────────────────────┐                        │
│  │      Network Participation          │                        │
│  │                                     │                        │
│  │ • Bandwidth rewards                │                        │
│  │ • Mesh networking                  │                        │
│  │ • Infrastructure services          │                        │
│  └─────────────────────────────────────┘                        │
│                                                                   │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │   Supply        │    │    Pricing      │                     │
│  │   Management    │    │    System       │                     │
│  │                 │    │                 │                     │
│  │ • Minting       │    │ • Dynamic       │                     │
│  │ • Tracking      │    │ • Congestion    │                     │
│  └─────────────────┘    └─────────────────┘                     │
│                                                                   │
│   STUB MODULES (Need Implementation)                           │
│  ┌─────────────────────────────────────┐                        │
│  │  Distribution   │  Reward Calculator │                       │
│  │  (UBI stub)     │  (Empty)           │                       │
│  └─────────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
         ▲                      ▲                    ▲
         │                      │                    │
         ▼                      ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ lib-identity │    │lib-blockchain│    │  lib-crypto  │
│              │    │              │    │              │
│ • Verified   │    │ • Ledger     │    │ • Signing    │
│   citizens   │    │ • Consensus  │    │ • Hashing    │
│ • Wallet IDs │    │ • Storage    │    │ • Addresses  │
└──────────────┘    └──────────────┘    └──────────────┘
```

### Module Responsibilities

#### Economic Model (`models/`)
**Purpose:** Core economic calculations and policy implementation

**Key Components:**
- `EconomicModel`: Main economic parameters and fee calculation
- `TokenReward`: Infrastructure service reward calculations
- `DaoTreasury`: Treasury management and fund allocation

**Responsibilities:**
- Calculate base fees and DAO fees (2%)
- Process infrastructure service rewards
- Manage treasury balance and allocations
- Adjust economic parameters dynamically

#### Multi-Wallet System (`wallets/`)
**Purpose:** Manage diverse economic activities with specialized wallets

**10 Wallet Types:**
1. **Personal** - Daily spending and basic transactions
2. **Business** - Business operations and contracts
3. **Investment** - Long-term holdings and staking
4. **Savings** - Protected savings with restricted access
5. **Rewards** - Infrastructure service rewards
6. **Staking** - Network consensus participation
7. **Governance** - DAO voting and governance
8. **Escrow** - Multi-party contract escrow
9. **Development** - Development and creator funding
10. **Donation** - Charitable contributions and tips

**Key Features:**
- Identity-integrated (requires verified identity)
- Independent transaction histories
- Lifecycle management (creation, activation, deactivation, archival)
- Balance tracking and validation

#### Treasury Economics (`treasury_economics/`)
**Purpose:** DAO treasury operations and welfare distribution

**Key Functions:**
- Receive and track DAO fees (2% of all transactions)
- Allocate funds: 40% UBI, 30% welfare, 30% development
- Calculate optimal UBI per citizen
- Track efficiency metrics (distribution vs collection)
- Sustainability analysis and funding gap calculations

**Transparency:**
- All allocations auditable on-chain
- Real-time efficiency tracking
- Predictive treasury health metrics

#### Transaction System (`transactions/`)
**Purpose:** Transaction creation, validation, and fee processing

**Components:**
- `Transaction`: Core transaction structure with fee tracking
- Creation utilities for various transaction types
- Validation logic ensuring economic rules
- Fee processing and DAO fee proof generation
- Priority-based fee adjustments

**Transaction Types:**
- Payment (with fees)
- Reward (fee-free from network)
- UBI Distribution (fee-free from DAO)
- Welfare Distribution (fee-free from DAO)
- Staking (with fees)
- Infrastructure Service (with fees)

#### Network Participation (`incentives/`)
**Purpose:** Reward genuine infrastructure contribution

**Anti-Sybil Design:**
- Rewards infrastructure quality, not node count
- Fixed rewards for mesh connectivity (not per-peer)
- Quality bonuses require user service
- Uptime bonuses require consistent availability

**Reward Categories:**
- Bandwidth sharing (like ISP revenue)
- Mesh networking (fixed connectivity reward)
- Connectivity provision (uptime-based)
- Quality bonuses (for exceptional service)

#### Supply Management (`supply/`)
**Purpose:** Utility-based token minting (post-scarcity)

**Philosophy:**
- Mint tokens based on infrastructure usage
- No artificial supply cap
- Reward productive network participation
- Prevent speculation-driven scarcity

**Minting Formula:**
```rust
base_mint = infrastructure_usage * 10 SOV
activity_bonus = network_activity * 5 SOV
total_mint = base_mint + activity_bonus
```

#### Pricing System (`pricing/`)
**Purpose:** Dynamic pricing based on network conditions

**Pricing Factors:**
1. **Network Congestion**: Higher congestion = higher fees
2. **Transaction Priority**: Urgent > High > Normal > Low
3. **Supply/Demand**: Logarithmic adjustments prevent extremes

**Infrastructure Pricing:**
- Routing: 1 SOV per MB
- Storage: 10 SOV per GB
- Bandwidth: 100 SOV per GB

## Economic Formulas

### Fee Calculation

```rust
// Base infrastructure fee
base_fee = tx_size * BASE_FEE_PER_BYTE

// Mandatory DAO fee (2% of transaction amount)
dao_fee = (amount * DEFAULT_DAO_FEE_RATE) / 10000

// Priority multiplier
priority_multiplier = match priority {
    Low => 0.5,
    Normal => 1.0,
    High => 2.0,
    Urgent => 5.0,
}

// Total fee
total_fee = (base_fee * priority_multiplier) + dao_fee
```

### Infrastructure Rewards

```rust
// Routing rewards (1 SOV per MB)
routing_reward = (bytes_routed / 1_000_000) * base_routing_rate

// Storage rewards (10 SOV per GB per month)
storage_reward = (bytes_stored / 1_000_000_000) * base_storage_rate

// Compute rewards (minimal, for consensus validation)
compute_reward = compute_work * base_compute_rate

// Quality bonus (for exceptional service)
quality_bonus = if quality > 0.95 {
    base_rewards * quality_multiplier
} else { 0 }

// Uptime bonus (for consistent availability)
uptime_bonus = if uptime > 0.99 {
    base_rewards * uptime_multiplier
} else { 0 }

// Total reward
total_reward = routing + storage + compute + quality_bonus + uptime_bonus
```

### UBI Distribution

```rust
// Calculate optimal UBI per citizen
ubi_per_citizen = treasury.ubi_allocated / total_verified_citizens

// Verify sustainability
months_sustainable = ubi_allocated / (ubi_per_citizen * citizens * 12)

// Distribution condition
can_distribute = ubi_per_citizen >= minimum_viable_ubi && 
                 months_sustainable >= 3
```

## Design Patterns

### 1. Fee Transparency Pattern
Every transaction includes detailed fee breakdown:
```rust
pub struct Transaction {
    pub amount: u64,
    pub base_fee: u64,        // Infrastructure cost
    pub dao_fee: u64,         // Mandatory 2% for welfare
    pub total_fee: u64,       // base_fee + dao_fee
    pub dao_fee_proof: Option<[u8; 32]>, // Proof of correct calculation
}
```

### 2. Identity-Wallet Binding Pattern
All wallets require verified identity:
```rust
pub struct MultiWalletManager {
    identity_address: [u8; 32], // Verified identity
    wallets: Vec<Wallet>,       // Multiple specialized wallets
}
```

### 3. Anti-Sybil Reward Pattern
Rewards focus on infrastructure quality, not node count:
```rust
// Fixed reward for maintaining mesh (not per-peer)
let mesh_reward = if peers >= MESH_CONNECTIVITY_THRESHOLD {
    ISP_BYPASS_UPTIME_BONUS // Fixed amount
} else {
    0 // No reward for insufficient connectivity
};
```

### 4. Treasury Allocation Pattern
Transparent, rule-based fund allocation:
```rust
ubi_allocated = (dao_fee * UBI_ALLOCATION_PERCENTAGE) / 100;
welfare_allocated = (dao_fee * WELFARE_ALLOCATION_PERCENTAGE) / 100;
development_allocated = (dao_fee * DEVELOPMENT_ALLOCATION_PERCENTAGE) / 100;
```

## Integration Points

### lib-identity Integration
```rust
// Wallet creation requires verified identity
pub fn create_wallet(&mut self, name: &str, wallet_type: WalletType) -> Result<()> {
    // Verify identity exists and is active
    let identity = lib_identity::get_identity(self.identity_address)?;
    // Create wallet bound to identity
    let wallet = Wallet::new(name, wallet_type, self.identity_address);
    self.wallets.push(wallet);
}
```

### lib-blockchain Integration
```rust
// Transactions recorded on blockchain
pub fn record_transaction(tx: &Transaction) -> Result<()> {
    let block_data = BlockData {
        transactions: vec![tx.clone()],
        fees: tx.total_fee,
        dao_contribution: tx.dao_fee,
    };
    lib_blockchain::add_block(block_data)?;
}
```

### lib-crypto Integration
```rust
// Cryptographic operations for addresses and proofs
pub fn generate_dao_fee_proof(dao_fee: u64, timestamp: u64) -> [u8; 32] {
    lib_crypto::hash_blake3(
        &format!("dao_fee_proof_{}_{}", dao_fee, timestamp).as_bytes()
    )
}
```

## Security Considerations

### 1. DAO Fee Enforcement
- Every transaction includes `dao_fee_proof`
- Consensus layer validates DAO fee calculation
- Transactions with incorrect DAO fees are rejected

### 2. Anti-Sybil Mechanisms
- Rewards based on infrastructure quality, not node count
- Quality bonuses require serving users
- Fixed rewards prevent gaming through node proliferation

### 3. Identity Verification
- All wallets require verified identity
- UBI recipients must have verified citizenship
- Prevents duplicate welfare claims

### 4. Treasury Protection
- Fund allocation enforced by smart contracts
- Multi-signature requirements for large distributions
- Sustainability checks before distributions

## Performance Characteristics

### Transaction Throughput
- **Fee Calculation**: O(1) - constant time
- **Wallet Lookup**: O(log n) - indexed by wallet ID
- **Treasury Update**: O(1) - atomic operations
- **Reward Calculation**: O(1) - fixed formula

### Storage Requirements
- **Per Transaction**: ~300 bytes (including proofs)
- **Per Wallet**: ~500 bytes (including history)
- **Treasury State**: ~2 KB (consolidated data)

### Scalability
- Horizontal scaling through sharding
- Independent wallet managers per identity
- Async treasury updates
- Batch UBI distributions

## Future Enhancements

### Phase 1: Complete Core Implementation
-  Economic model and fee calculation
-  Multi-wallet system
-  Treasury management
-  UBI distribution (stub - needs implementation)
-  Reward calculator (empty - needs implementation)

### Phase 2: Advanced Features
- Cross-chain token bridges
- Decentralized exchange integration
- Advanced staking mechanisms
- Governance token implementation

### Phase 3: Optimization
- Zero-knowledge proofs for privacy
- Lightning-style payment channels
- Optimistic rollups for scalability
- Advanced anti-Sybil ML models

## Testing Strategy

### Unit Tests
- Fee calculation accuracy
- Wallet creation and management
- Treasury allocation correctness
- Reward calculation formulas

### Integration Tests
- End-to-end transaction flow
- Multi-wallet coordination
- Treasury fund lifecycle
- Network participation rewards

### Economic Simulations
- Long-term treasury sustainability
- Token supply growth projections
- Network effect modeling
- Attack vector analysis

## Related Documentation

- **[INDEX.md](./INDEX.md)** - Complete module listing
- **[API_REFERENCE.md](./API_REFERENCE.md)** - Detailed API documentation
- **[EXAMPLES.md](./EXAMPLES.md)** - Usage examples
- **[models.md](./models.md)** - Economic model details
- **[wallets.md](./wallets.md)** - Multi-wallet system
- **[treasury_economics.md](./treasury_economics.md)** - Treasury operations
