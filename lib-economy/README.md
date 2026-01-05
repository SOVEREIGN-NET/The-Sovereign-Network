# ZHTP Economics Engine

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![WASM Compatible](https://img.shields.io/badge/WASM-Compatible-blue.svg)](https://webassembly.org/)

> **Post-scarcity economics system for the quantum-resistant Web4 internet that replaces ISPs**

The ZHTP Economics Engine is the economic backbone of the ZHTP (Zero-knowledge Hypertext Transfer Protocol) network, implementing a post-scarcity economic model designed to replace traditional Internet Service Providers (ISPs) with a decentralized, incentivized mesh network.

##  **Vision: Web4 Economics**

ZHTP Economics enables the transition from Web3 to Web4 by creating economic incentives for:

- **ISP Replacement**: Participants earn tokens for sharing internet connectivity
- **Mesh Networking**: Rewards for packet routing and network infrastructure
- **Universal Basic Income**: 2% of all network activity funds UBI for all verified humans
- ** DAO Governance**: Community-driven economic policy and welfare distribution
- ** Quantum-Safe Finance**: Post-quantum cryptographic economic primitives

##**Architecture Overview**

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZHTP Economics Engine                        │
├─────────────────────────────────────────────────────────────────┤
│  Economic Model    │  Treasury      │  Incentives   │  Wallets   │
│  ┌─────────────┐   │  ┌──────────┐  │  ┌─────────┐  │ ┌────────┐ │
│  │ Fee Calc    │   │  │ UBI Dist │  │  │ ISP     │  │ │ Multi  │ │
│  │ Rewards     │   │  │ Welfare  │  │  │ Bypass  │  │ │ Wallet │ │
│  │ Supply Mgmt │   │  │ DAO Fees │  │  │ Mesh    │  │ │ System │ │
│  └─────────────┘   │  └──────────┘  │  └─────────┘  │ └────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                     Integration Layer                           │
│  ┌─────────────┐   ┌──────────────┐  ┌─────────────────────────┐ │
│  │ Blockchain  │   │ Network      │  │ Identity & Consensus    │ │
│  │ Integration │   │ Metrics      │  │ Integration             │ │
│  └─────────────┘   └──────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## **Core Economic Principles**

### **Post-Scarcity Model**
- **Unlimited Token Supply**: Like internet bandwidth, tokens are minted based on utility, not artificial scarcity
- **Utility-Driven Value**: Token value derives from network utility, not speculation
- **Anti-Speculation Mechanics**: Economic policies discourage hoarding and encourage usage

### **ISP Replacement Economics**
```rust
// Economic incentives mirror traditional ISP revenue streams
ISP Traditional Revenue → ZHTP Token Rewards
├── Bandwidth fees → Routing rewards (1 ZHTP/MB)
├── Storage fees → Storage rewards (10 ZHTP/GB/month)
├── Service fees → Validation rewards (5 ZHTP/validation)
└── Infrastructure → Quality bonuses (up to 50% multiplier)
```

### **Universal Basic Income Integration**
- **Mandatory DAO Fee**: 2% of all transactions fund UBI and welfare
- **Automatic Distribution**: 60% to UBI, 40% to welfare services
- **Human Verification**: Integration with ZHTP Identity system for citizen verification
- **Sustainable Funding**: Network growth directly funds social services

##  **Quick Start**

### **Add Dependency**
```toml
[dependencies]
lib-economy = { path = "../lib-economy" }
```

### **Basic Usage**
```rust
use lib_economy::*;

// Create economic model
let mut economic_model = EconomicModel::new();

// Calculate transaction fees
let (network_fee, dao_fee, total) = economic_model.calculate_fee(
    1000,              // transaction size in bytes
    50_000,            // transaction amount in ZHTP
    Priority::Normal   // transaction priority
);

// Process economic rewards
let work_metrics = WorkMetrics {
    routing_work: 1_000_000,    // 1MB routed
    storage_work: 1_000_000_000, // 1GB stored
    compute_work: 10,           // 10 validations
    quality_score: 0.95,        // 95% quality
    uptime_hours: 24,           // 24h uptime
};

let reward = TokenReward::calculate(&work_metrics, &economic_model)?;
println!("Earned {} ZHTP tokens", reward.total_reward);
```

### **Multi-Wallet System**
```rust
use lib_economy::wallets::*;
use lib_identity::Identity;

// Create comprehensive wallet system
let identity = create_test_identity(); // Your identity system
let mut wallet_manager = create_comprehensive_multi_wallet_manager(identity).await?;

// Specialized wallets for different economic activities
wallet_manager.create_specialized_wallet(WalletType::IspBypassRewards).await?;
wallet_manager.create_specialized_wallet(WalletType::Staking).await?;
wallet_manager.create_specialized_wallet(WalletType::Governance).await?;

// Transfer between wallets
let tx_id = wallet_manager.transfer_between_wallets(
    WalletType::IspBypassRewards,
    WalletType::Primary,
    100_000, // 100K ZHTP
    "Consolidating  rewards".to_string()
).await?;
```

## **Economic Components**

### **1. Fee System**
The ZHTP network implements a dual-fee structure:

```rust
pub fn calculate_fee(tx_size: u64, amount: u64, priority: Priority) -> (u64, u64, u64) {
    // Network infrastructure fee (covers bandwidth, storage, compute)
    let network_fee = tx_size * priority.fee_multiplier();
    
    // Mandatory DAO fee for UBI/welfare (2% of transaction amount)
    let dao_fee = (amount * 200) / 10_000; // 2.00%
    
    (network_fee, dao_fee, network_fee + dao_fee)
}
```

### **2. Reward System**
Economic rewards are calculated based on actual infrastructure contribution:

| Activity | Base Rate | Quality Bonus | Uptime Bonus |
|----------|-----------|---------------|---------------|
| **Packet Routing** | 1 ZHTP/MB | +50% (>95% quality) | +25% (>95% uptime) |
| **Data Storage** | 10 ZHTP/GB/month | +50% (>95% reliability) | +25% (>99% availability) |
| **Validation** | 5 ZHTP/validation | +50% (>95% accuracy) | +25% (>23h/day) |
| **** | 100 ZHTP/GB shared | +50% (>90% quality) | +10 ZHTP/hour uptime |

### **3. Treasury Economics**
```rust
pub struct DaoTreasury {
    pub treasury_balance: u64,        // Total available funds
    pub ubi_allocated: u64,           // 45% allocation to UBI
    pub sector_dao_allocated: u64,    // 30% allocation to sector DAOs
    pub emergency_allocated: u64,     // 15% allocation to emergency reserves
    pub dev_grants_allocated: u64,    // 10% allocation to dev grants
    pub total_dao_fees_collected: u64, // Historical collection
}

impl DaoTreasury {
    pub fn apply_fee_distribution(&mut self, dist: DaoFeeDistribution) -> Result<()> {
        self.treasury_balance += dist.total();
        self.ubi_allocated += dist.ubi;
        self.sector_dao_allocated += dist.sector_daos;
        self.emergency_allocated += dist.emergency_reserve;
        self.dev_grants_allocated += dist.dev_grants;
        self.total_dao_fees_collected += dist.total();
        Ok(())
    }
}
```

### **4.  Economics**
Economic incentives specifically designed to replace traditional ISPs:

```rust
pub struct IspBypassIncentives {
    pub connectivity_sharing_rate: u64,     // 100 ZHTP per GB shared
    pub mesh_routing_rate: u64,             // 1 ZHTP per MB routed
    pub uptime_bonus_rate: u64,             // 10 ZHTP per hour uptime
    pub bandwidth_quality_multiplier: f64,  // 1.5x for high quality
}
```

**Real-world Impact:**
- **Cost Savings**: Average $50/month savings per participant
- **Revenue Sharing**: Traditional ISP profits distributed to participants
- **Infrastructure Democratization**: Anyone can become an infrastructure provider

### **5. Multi-Wallet Architecture**
Specialized wallets for different economic activities:

```rust
pub enum WalletType {
    Primary,                    // General transactions
    IspBypassRewards,          //  service rewards
    MeshDiscoveryRewards,      // Mesh discovery rewards
    Staking,                   // Infrastructure investment
    Governance,                // DAO voting and governance
    UbiDistribution,           // UBI receiving
    Infrastructure,            // Infrastructure provider rewards
    Bridge,                    // Cross-chain operations
    SmartContract,             // Contract interactions
    Privacy,                   // Enhanced privacy transactions
}
```

## **Integration with ZHTP Ecosystem**

### **Blockchain Integration**
```rust
use lib_economy::integration::BlockchainIntegration;

let mut integration = BlockchainIntegration::new();

// Process economic data from blockchain
let economic_data = integration.create_economic_data_from_transaction(&transaction);
let tx_hash = integration.submit_economic_data(&economic_data)?;

// Handle blockchain confirmations
integration.process_confirmed_transaction(&tx_hash, block_height)?;
```

### **Network Metrics Integration**
```rust
use lib_economy::network_types::*;

// Get real-time network statistics for economic calculations
let network_stats = get_network_statistics().await?;
let mesh_status = get_mesh_status().await?;
let bandwidth_stats = get_bandwidth_statistics().await?;

// Adjust economic parameters based on network performance
economic_model.adjust_parameters(&network_stats)?;
```

### **Identity System Integration**
```rust
use lib_economy::wasm::IdentityId;

// Verify UBI eligibility through identity system
let verified_citizens = verify_ubi_eligibility(&citizen_identities);
let ubi_amount = calculate_ubi_amount(&dao_treasury, &verified_citizens)?;
```

##  **Economic Formulas**

### **Network Utilization Adjustment**
```rust
fn get_reward_adjustment_multiplier(&self) -> u64 {
    match self.utilization {
        u if u >= 0.9 => 105,  // +5% increase for high utilization
        u if u <= 0.3 => 98,   // -2% decrease for low utilization
        _ => 100,              // No adjustment for normal utilization
    }
}
```

### **Quality Bonus Calculation**
```rust
fn calculate_quality_bonus(&self, base_reward: u64) -> u64 {
    if self.quality_score >= 0.95 {
        (base_reward as f64 * 0.5) as u64  // 50% bonus for excellent quality
    } else if self.quality_score >= 0.9 {
        (base_reward as f64 * 0.25) as u64 // 25% bonus for good quality
    } else {
        0
    }
}
```

### **UBI Distribution Formula**
```rust
fn calculate_ubi_per_citizen(&self, citizen_count: u64) -> u64 {
    if citizen_count == 0 { return 0; }
    
    let available_ubi = self.ubi_allocated - self.total_ubi_distributed;
    available_ubi / citizen_count
}
```

## **Development**

### **Running Tests**
```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run with performance benchmarks
cargo test --features benchmark

# Run WASM compatibility tests
cargo test --target wasm32-unknown-unknown
```

### **Performance Testing**
```bash
# Stress test economic calculations
cargo test stress_tests -- --nocapture

# Edge case testing
cargo test edge_case_tests -- --nocapture

# Economic model validation
cargo test test_economic_model_validation
```

### **WASM Build**
```bash
# Build for WebAssembly
cargo build --target wasm32-unknown-unknown --features wasm

# Generate WASM bindings
wasm-pack build --target web --features wasm
```

## **Economic Constants**

```rust
// Core economic parameters
pub const DEFAULT_DAO_FEE_RATE: u64 = 200;                    // 2.00% DAO fee
pub const MINIMUM_DAO_FEE: u64 = 5;                           // 5 ZHTP minimum
pub const UBI_ALLOCATION_PERCENTAGE: u64 = 60;                // 60% to UBI
pub const WELFARE_ALLOCATION_PERCENTAGE: u64 = 40;            // 40% to welfare

// Infrastructure reward rates
pub const DEFAULT_ROUTING_RATE: u64 = 1;                      // 1 ZHTP per MB
pub const DEFAULT_STORAGE_RATE: u64 = 10;                     // 10 ZHTP per GB/month
pub const DEFAULT_COMPUTE_RATE: u64 = 5;                      // 5 ZHTP per validation

//  incentives
pub const ISP_BYPASS_CONNECTIVITY_RATE: u64 = 100;            // 100 ZHTP per GB shared
pub const ISP_BYPASS_MESH_RATE: u64 = 1;                      // 1 ZHTP per MB routed
pub const ISP_BYPASS_UPTIME_BONUS: u64 = 10;                  // 10 ZHTP per hour

// Quality and performance thresholds
pub const HIGH_UTILIZATION_THRESHOLD: f64 = 0.9;              // 90% utilization
pub const QUALITY_BONUS_THRESHOLD: f64 = 0.95;                // 95% quality for bonus
pub const UPTIME_BONUS_THRESHOLD: u64 = 23;                   // 23 hours for bonus
```

## **Use Cases**

### **1. Infrastructure Provider**
```rust
// Calculate rewards for running infrastructure
let infrastructure_work = WorkMetrics {
    routing_work: 50_000_000,      // 50MB routed
    storage_work: 10_000_000_000,  // 10GB stored
    compute_work: 100,             // 100 validations
    quality_score: 0.97,           // 97% quality
    uptime_hours: 24,              // 24h uptime
};

let daily_rewards = TokenReward::calculate(&infrastructure_work, &economic_model)?;
// Typical result: ~2,000-3,000 ZHTP tokens per day
```

### **2.  Participant**
```rust
let bypass_work = IspBypassWork {
    bandwidth_shared_gb: 100,      // 100GB shared
    packets_routed_mb: 5_000,      // 5GB routed
    uptime_hours: 24,              // 24h uptime
    connection_quality: 0.92,      // 92% quality
    users_served: 10,              // Served 10 users
    cost_savings_provided: 500,    // $500 cost savings
};

let monthly_rewards = isp_incentives.calculate_rewards(&bypass_work);
// Typical result: ~10,000-15,000 ZHTP tokens per month
// Equivalent to traditional ISP profit margins
```

### **3. UBI Recipient**
```rust
// Check UBI eligibility and amount
let verified_citizens = vec![citizen_identity_1, citizen_identity_2, /* ... */];
let ubi_amount = calculate_ubi_amount(&dao_treasury, &verified_citizens)?;

// Monthly UBI distribution
let ubi_tx = Transaction::new_ubi_distribution(citizen_wallet, ubi_amount)?;
// Typical result: 500-2,000 ZHTP tokens per month per citizen
```

## 🔮 **Future Roadmap**

### **Phase 1: Core Economics (Current)**
- Basic fee and reward system
- Multi-wallet architecture
-  economics
- UBI distribution mechanics

### **Phase 2: Advanced Economics (Q4 2025)**
- 🔲 Dynamic economic parameter adjustment
- 🔲 Advanced anti-speculation mechanisms
- 🔲 Cross-chain economic bridges
- 🔲 Predictive economic modeling

### **Phase 3: AI-Driven Economics (Q1 2026)**
- 🔲 AI-powered economic optimization
- 🔲 Adaptive reward algorithms
- 🔲 Economic attack detection
- 🔲 Autonomous economic governance

### **Phase 4: Global Scale (Q2 2026)**
- 🔲 Multi-currency integration
- 🔲 Central bank digital currency (CBDC) bridges
- 🔲 Global UBI coordination
- 🔲 Economic sovereignty tools

## **Contributing**

We welcome contributions to the ZHTP Economics Engine! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Clone the repository
git clone https://github.com/SOVEREIGN-NETWORK/ZHTPDEV.git
cd ZHTPDEV/modular-archetecture/packages/lib-economy

# Install dependencies
cargo build

# Run tests
cargo test

# Run formatting
cargo fmt

# Run linting
cargo clippy
```

### **Economic Model Contributions**
We especially welcome contributions in:
- Economic modeling and simulation
- Anti-speculation mechanism design
- UBI distribution optimization
- Cross-cultural economic adaptation
- Economic attack vector analysis

##  **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **Post-Scarcity Economics Theory**: Inspired by abundance economics principles
- **Mesh Networking Research**: Building on decades of decentralized networking research
- **Universal Basic Income**: Implementing economic research on UBI sustainability
- **Quantum-Resistant Cryptography**: Leveraging NIST-standardized post-quantum algorithms

## 📞 **Support**

- **Documentation**: [docs.zhtp.org](https://docs.zhtp.org)
- **Discord**: [ZHTP Community](https://discord.gg/zhtp)
- **GitHub Issues**: [Report bugs and request features](https://github.com/SOVEREIGN-NETWORK/ZHTPDEV/issues)
- **Email**: economics@zhtp.org

---

> **"Building the economic foundation for human freedom in the quantum age"**
> 
> The ZHTP Economics Engine enables a post-scarcity digital economy where technology serves humanity, privacy is protected by mathematics, and economic opportunity is universal.
