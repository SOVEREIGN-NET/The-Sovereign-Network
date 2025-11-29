# Rewards Module Documentation

**Status:  EMPTY - No Implementation**

## Current Status

The rewards module file (`rewards/reward_calculator.rs`) is currently **completely empty** (0 bytes). This document describes the intended functionality and available workarounds.

## Module Structure

```
rewards/
├── mod.rs                - Module organization
└── reward_calculator.rs  - Reward calculator (EMPTY - 0 bytes)
```

## Current Implementation

### reward_calculator.rs (EMPTY)

**File size:** 0 bytes  
**Content:** None  
**Functionality:** None

## What Exists Elsewhere

###  Token Reward Calculation (Fully Implemented)

**Location:** `models/token_reward.rs` (216 lines, complete)

```rust
// Infrastructure reward calculation - FULLY FUNCTIONAL
impl TokenReward {
    pub fn calculate(work: &WorkMetrics, model: &EconomicModel) -> Result<Self>;
    pub fn calculate_isp_bypass(work: &IspBypassWork) -> Result<Self>;
    pub fn combine(&mut self, other: &TokenReward);
}
```

###  Network Participation Rewards (Fully Implemented)

**Location:** `incentives/network_participation.rs` (168 lines, complete)

```rust
// Network participation rewards - FULLY FUNCTIONAL
impl NetworkParticipationRewards {
    pub fn calculate(work: &IspBypassWork, peers: u32) -> Result<Self>;
}

pub fn calculate_mesh_maintenance(peers: u32, uptime: u64) -> Result<u64>;
```

## Workaround: Manual Reward Aggregation

Until the rewards module is implemented, rewards can be aggregated manually:

```rust
use lib_economy::{TokenReward, NetworkParticipationRewards, EconomicModel};

fn calculate_total_node_rewards(
    infrastructure_work: &WorkMetrics,
    isp_work: &IspBypassWork,
    peers_connected: u32,
) -> anyhow::Result<u64> {
    let model = EconomicModel::new();
    
    // 1. Calculate infrastructure rewards
    let infra_reward = TokenReward::calculate(infrastructure_work, &model)?;
    
    // 2. Calculate  rewards
    let isp_reward = TokenReward::calculate_isp_bypass(isp_work)?;
    
    // 3. Calculate network participation rewards
    let network_reward = NetworkParticipationRewards::calculate(isp_work, peers_connected)?;
    
    // 4. Aggregate all rewards
    let total_reward = infra_reward.total_reward 
        + isp_reward.total_reward 
        + network_reward.total_participation_rewards;
    
    println!("=== Total Node Rewards ===");
    println!("Infrastructure: {} ZHTP", infra_reward.total_reward);
    println!(": {} ZHTP", isp_reward.total_reward);
    println!("Network Participation: {} ZHTP", network_reward.total_participation_rewards);
    println!("Total: {} ZHTP", total_reward);
    
    Ok(total_reward)
}
```

## Needed Implementation

### Full Implementation Requirements

The complete reward calculator should include:

#### 1. Reward Aggregator

```rust
pub struct RewardAggregator {
    infrastructure_rewards: Vec<TokenReward>,
    participation_rewards: Vec<NetworkParticipationRewards>,
    pending_distribution: u64,
}

impl RewardAggregator {
    pub fn new() -> Self;
    
    pub fn add_infrastructure_reward(&mut self, reward: TokenReward);
    pub fn add_participation_reward(&mut self, reward: NetworkParticipationRewards);
    
    pub fn calculate_total(&self) -> u64;
    pub fn get_reward_breakdown(&self) -> RewardBreakdown;
}
```

#### 2. Historical Tracking

```rust
pub struct RewardHistory {
    pub node_address: [u8; 32],
    pub records: Vec<RewardRecord>,
}

pub struct RewardRecord {
    pub timestamp: u64,
    pub reward_type: RewardType,
    pub amount: u64,
    pub work_period: (u64, u64), // (start, end)
}

pub enum RewardType {
    Infrastructure,
    IspBypass,
    NetworkParticipation,
    QualityBonus,
    UptimeBonus,
}
```

#### 3. Distribution Scheduler

```rust
pub struct RewardDistributor {
    pub distribution_frequency: DistributionFrequency,
    pub pending_rewards: HashMap<[u8; 32], u64>, // node_address -> amount
    pub last_distribution: u64,
}

pub enum DistributionFrequency {
    Hourly,
    Daily,
    Weekly,
}

impl RewardDistributor {
    pub fn schedule_distribution(&mut self, node: [u8; 32], amount: u64);
    pub fn process_distributions(&mut self) -> Result<Vec<Transaction>>;
    pub fn get_pending_reward(&self, node: [u8; 32]) -> u64;
}
```

#### 4. Complete Reward Calculator

```rust
pub struct RewardCalculator {
    aggregator: RewardAggregator,
    history: HashMap<[u8; 32], RewardHistory>,
    distributor: RewardDistributor,
}

impl RewardCalculator {
    pub fn new(distribution_frequency: DistributionFrequency) -> Self;
    
    // Calculate rewards for work period
    pub fn calculate_period_rewards(
        &mut self,
        node_address: [u8; 32],
        infrastructure_work: &WorkMetrics,
        isp_work: &IspBypassWork,
        peers_connected: u32,
    ) -> Result<u64>;
    
    // Schedule reward for distribution
    pub fn schedule_reward(&mut self, node: [u8; 32], amount: u64) -> Result<()>;
    
    // Process scheduled distributions
    pub fn distribute_pending_rewards(&mut self) -> Result<Vec<Transaction>>;
    
    // Get historical rewards
    pub fn get_node_history(&self, node: [u8; 32]) -> Option<&RewardHistory>;
    
    // Get statistics
    pub fn get_total_rewards_distributed(&self) -> u64;
    pub fn get_average_reward_per_node(&self) -> u64;
}
```

#### 5. Reward Verification

```rust
pub struct RewardVerifier {
    expected_rewards: HashMap<[u8; 32], u64>,
}

impl RewardVerifier {
    pub fn verify_reward_calculation(
        &self,
        node: [u8; 32],
        calculated_reward: u64,
        work: &WorkMetrics,
    ) -> Result<bool>;
    
    pub fn generate_proof(&self, node: [u8; 32], amount: u64) -> [u8; 32];
    
    pub fn verify_proof(&self, node: [u8; 32], amount: u64, proof: [u8; 32]) -> bool;
}
```

## Implementation Estimate

**Estimated effort:** 300-400 lines of code

**Components needed:**
- Reward aggregator (~80 lines)
- Historical tracking (~60 lines)
- Distribution scheduler (~80 lines)
- Main calculator (~120 lines)
- Verification system (~60 lines)

## Impact of Empty Status

### What Works 
- Individual reward calculations (fully functional)
- Infrastructure rewards (`TokenReward::calculate`)
-  rewards (`TokenReward::calculate_isp_bypass`)
- Network participation rewards (`NetworkParticipationRewards::calculate`)
- Reward combination (`TokenReward::combine`)

### What's Missing 
- Automated reward aggregation
- Historical reward tracking
- Distribution scheduling
- Reward verification proofs
- Node reward statistics

### Severity
**Minor** - All reward calculation functions work perfectly. Only aggregation automation and historical tracking are missing. Manual aggregation (shown above) is a viable workaround.

## Temporary Solution

Until full implementation, use manual aggregation and distribution:

```rust
use lib_economy::{TokenReward, NetworkParticipationRewards, EconomicModel, Transaction};

fn daily_reward_process(
    node_address: [u8; 32],
    daily_infrastructure_work: &WorkMetrics,
    daily_isp_work: &IspBypassWork,
    peers: u32,
) -> anyhow::Result<()> {
    let model = EconomicModel::new();
    
    // Calculate all reward types
    let infra = TokenReward::calculate(daily_infrastructure_work, &model)?;
    let isp = TokenReward::calculate_isp_bypass(daily_isp_work)?;
    let network = NetworkParticipationRewards::calculate(daily_isp_work, peers)?;
    
    // Aggregate
    let total = infra.total_reward 
        + isp.total_reward 
        + network.total_participation_rewards;
    
    // Create reward transaction
    let tx = Transaction::new_reward(node_address, total)?;
    
    // Process transaction (would be done by consensus)
    // blockchain::record_transaction(tx)?;
    
    println!(" Node {} earned {} ZHTP", 
        hex::encode(&node_address[..8]), 
        total
    );
    
    Ok(())
}
```

### Weekly Aggregation Example

```rust
fn weekly_node_rewards(
    node_address: [u8; 32],
    daily_work: Vec<(WorkMetrics, IspBypassWork, u32)>, // 7 days
) -> anyhow::Result<u64> {
    let model = EconomicModel::new();
    let mut total_weekly_reward = 0u64;
    
    for (day, (infra_work, isp_work, peers)) in daily_work.iter().enumerate() {
        let infra = TokenReward::calculate(infra_work, &model)?;
        let isp = TokenReward::calculate_isp_bypass(isp_work)?;
        let network = NetworkParticipationRewards::calculate(isp_work, *peers)?;
        
        let daily_total = infra.total_reward 
            + isp.total_reward 
            + network.total_participation_rewards;
        
        total_weekly_reward += daily_total;
        
        println!("Day {}: {} ZHTP", day + 1, daily_total);
    }
    
    println!("Weekly total: {} ZHTP", total_weekly_reward);
    Ok(total_weekly_reward)
}
```

## Related Documentation

- [Models](./models.md) - TokenReward implementation
- [Incentives](./incentives.md) - NetworkParticipationRewards
- [Transactions](./transactions.md) - Reward transaction creation
- [IMPLEMENTATION_STATUS](./IMPLEMENTATION_STATUS.md) - Overall status

## Future Implementation

When implementing the full rewards module, consider:

1. **Efficient aggregation** - Batch reward calculations
2. **Historical data storage** - Use blockchain or database
3. **Reward verification** - Cryptographic proofs
4. **Distribution optimization** - Minimize transaction overhead
5. **Statistics and analytics** - Node performance tracking
6. **Fraud detection** - Identify abnormal reward patterns

## Comparison with Existing Implementations

| Feature | TokenReward () | NetworkParticipation () | RewardCalculator () |
|---------|-----------------|--------------------------|---------------------|
| Infrastructure rewards |  Complete | N/A |  Empty |
|  rewards |  Complete |  Complete |  Empty |
| Network participation | N/A |  Complete |  Empty |
| Reward aggregation |  Manual | N/A |  Empty |
| Historical tracking |  |  |  Empty |
| Distribution scheduling |  |  |  Empty |
| Verification proofs |  |  |  Empty |

**Conclusion:** Core reward calculations are 100% functional. Only convenience and automation features need implementation.
