<<<<<<< HEAD
# Economic Storage Manager (`economic/manager.rs`)

The Economic Storage Manager serves as the central coordination point for all economic activities in the ZHTP storage network. It orchestrates contracts, payments, reputation, quality assurance, and incentive distribution to create a self-sustaining economic ecosystem.

##  Overview

The `EconomicStorageManager` is responsible for:
- **Request Processing**: Converting storage requests into economic quotes
- **Contract Lifecycle**: Managing storage contracts from creation to settlement
- **Payment Coordination**: Processing payments and escrow operations
- **Performance Monitoring**: Tracking service quality and SLA compliance
- **Reputation Management**: Updating provider reputation scores
- **Incentive Distribution**: Calculating and distributing performance rewards

## 🏗️ Core Structure

### EconomicStorageManager

```rust
pub struct EconomicStorageManager {
    /// Configuration
    config: EconomicManagerConfig,
    /// Contract manager
    contract_manager: ContractManager,
    /// Pricing engine
    pricing_engine: PricingEngine,
    /// Market manager
    market_manager: MarketManager,
    /// Reputation system
    reputation_system: ReputationSystem,
    /// Payment processor
    payment_processor: PaymentProcessor,
    /// Incentive manager
    incentive_manager: IncentiveSystem,
    /// Quality assurance
    quality_assurance: QualityAssurance,
    /// Penalty enforcer
    penalty_enforcer: PenaltyEnforcer,
    /// Reward manager
    reward_manager: RewardManager,
}
```

### EconomicManagerConfig

```rust
pub struct EconomicManagerConfig {
    pub default_duration_days: u32,
    pub base_price_per_gb_day: u64,
    pub enable_escrow: bool,
    pub quality_premium_rate: f64,
    pub network_fee_rate: f64,
    pub escrow_fee_rate: f64,
    pub min_reputation_threshold: u32,
    pub performance_bonus_threshold: f64,
    pub penalty_grace_period: u64,
}
```

##  Core Operations

### Storage Request Processing

#### process_storage_request()
```rust
pub async fn process_storage_request(
    &mut self, 
    request: EconomicStorageRequest
) -> Result<EconomicQuote>
```

Process an economic storage request and generate a comprehensive quote.

**Example:**
```rust
let request = EconomicStorageRequest {
    content: document_data,
    filename: "important_contract.pdf".to_string(),
    content_type: "application/pdf".to_string(),
    description: "Legal contract requiring high reliability".to_string(),
    preferred_tier: StorageTier::Warm,
    requirements: StorageRequirements {
        duration_days: 365, // Store for 1 year
        quality_requirements: QualityRequirements {
            min_uptime: 0.99,           // 99% uptime requirement
            max_response_time: 3000,    // 3 second max response
            min_replication: 5,         // 5 replicas for safety
            data_integrity_level: 0.999, // 99.9% integrity
        },
        budget_constraints: BudgetConstraints {
            max_total_cost: 50000,      // 50,000 SOV tokens max
            max_cost_per_gb_day: 200,   // 200 tokens per GB/day max
            preferred_payment_schedule: PaymentSchedule::Monthly,
        },
        geographic_preferences: vec!["US".to_string(), "EU".to_string()],
        replication_factor: 5,
    },
    payment_preferences: PaymentPreferences {
        escrow_preferences: EscrowPreferences {
            use_escrow: true,
            release_schedule: ReleaseSchedule::Milestone,
            dispute_resolution: DisputeResolution::Arbitration,
        },
        payment_method: PaymentMethod::ZhtpTokens,
        auto_renewal: false,
    },
    requester: client_identity,
};

let quote = manager.process_storage_request(request).await?;
```

#### Quote Generation Process

1. **Requirements Analysis**: Parse storage requirements and constraints
2. **Provider Matching**: Find suitable storage providers using market manager
3. **Pricing Calculation**: Generate dynamic pricing using pricing engine
4. **Quality Assessment**: Estimate quality metrics based on provider reputation
5. **Cost Breakdown**: Create detailed cost analysis with all fees
6. **Quote Assembly**: Package all information into comprehensive quote

### Contract Management

#### create_contract()
```rust
pub async fn create_contract(
    &mut self, 
    quote: EconomicQuote, 
    content_hash: ContentHash, 
    content_size: u64
) -> Result<Hash>
```

Create a storage contract from an accepted quote.

**Example:**
```rust
// Client accepts the quote
let contract_id = manager.create_contract(
    accepted_quote, 
    content_hash, 
    file_size
).await?;

println!("Contract created: {}", hex::encode(contract_id.as_bytes()));
```

#### Contract Creation Process

1. **Quote Validation**: Verify quote is still valid and hasn't expired
2. **Contract Terms**: Define storage terms, SLA, and payment schedule
3. **Penalty Clauses**: Add appropriate penalty clauses for SLA violations
4. **Payment Setup**: Schedule payments and setup escrow if required
5. **Market Recording**: Record contract creation in market analytics
6. **Monitoring Setup**: Initialize performance monitoring systems

### Payment Processing

#### process_payment()
```rust
pub async fn process_payment(
    &mut self, 
    contract_id: Hash, 
    payment_amount: u64
) -> Result<()>
```

Process contract payments with performance-based bonus distribution.

**Example:**
```rust
// Process milestone payment
manager.process_payment(contract_id, milestone_amount).await?;
```

#### Payment Distribution Process

1. **Payment Processing**: Process pending payments through payment processor
2. **Contract Update**: Update contract payment status
3. **Performance Assessment**: Evaluate provider performance metrics
4. **Bonus Calculation**: Calculate performance-based bonuses
5. **Reward Distribution**: Distribute payments and bonuses to providers
6. **Incentive Recording**: Update incentive system with payment information

### Performance Monitoring

#### monitor_contract_performance()
```rust
pub async fn monitor_contract_performance(
    &mut self, 
    contract_id: Hash
) -> Result<()>
```

Monitor contract performance and enforce SLA compliance.

**Example:**
```rust
// Monitor all active contracts
let active_contracts = manager.get_active_contracts().await?;
for contract_id in active_contracts {
    manager.monitor_contract_performance(contract_id).await?;
}
```

#### Performance Monitoring Process

1. **Metrics Collection**: Gather performance metrics from quality assurance
2. **SLA Evaluation**: Compare actual performance against SLA requirements
3. **Violation Detection**: Identify any SLA violations or quality issues
4. **Penalty Enforcement**: Apply penalties for violations
5. **Reputation Updates**: Update provider reputation based on performance
6. **Reward Calculation**: Calculate performance-based rewards
7. **Incentive Distribution**: Distribute rewards for good performance

##  Economic Calculations

### Cost Breakdown Generation

```rust
let base_cost = price_quote.final_price;
let quality_premium = (base_cost as f64 * 0.1) as u64;     // 10% quality premium
let network_fees = (base_cost as f64 * 0.05) as u64;       // 5% network fees
let escrow_fees = if use_escrow {
    (base_cost as f64 * 0.02) as u64                       // 2% escrow fees
} else { 0 };

let total_cost = base_cost + quality_premium + network_fees + escrow_fees;
```

### Quality Metrics Calculation

```rust
async fn calculate_expected_quality(&self, nodes: &[String]) -> Result<QualityMetrics> {
    let mut total_reliability = 0.0;
    let mut total_availability = 0.0;
    let mut total_response_time = 0;
    let mut total_integrity = 0.0;

    for node_id in nodes {
        let reputation = self.reputation_system.get_reputation(node_id)?;
        let metrics = self.quality_assurance.get_node_metrics(node_id).await?;
        
        total_reliability += reputation.overall_score;
        total_availability += metrics.availability;
        total_response_time += metrics.avg_response_time;
        total_integrity += metrics.data_integrity;
    }

    let node_count = nodes.len() as f64;
    
    Ok(QualityMetrics {
        current_uptime: total_availability / node_count,
        avg_response_time: (total_response_time as f64 / node_count) as u64,
        data_integrity: total_integrity / node_count,
        reliability: total_reliability / node_count,
        overall_score: (total_reliability / node_count) * 0.5 + 
                      (total_availability / node_count) * 0.3 + 
                      (total_integrity / node_count) * 0.2,
        // ... other fields
    })
}
```

### Penalty Calculation

```rust
fn calculate_penalty_amount(&self, penalty_type: &PenaltyType, contract_value: u64) -> u64 {
    match penalty_type {
        PenaltyType::DataLoss => contract_value / 2,        // 50% of contract value
        PenaltyType::Unavailability => contract_value / 10, // 10% of contract value
        PenaltyType::SlowResponse => contract_value / 20,   // 5% of contract value
        PenaltyType::ContractBreach => contract_value,     // 100% of contract value
        PenaltyType::QualityDegradation => contract_value / 5, // 20% of contract value
    }
}
```

##  Default Configurations

### Default Penalty Clauses

```rust
fn create_default_penalties(&self) -> Vec<PenaltyClause> {
    vec![
        PenaltyClause {
            penalty_type: PenaltyType::DataLoss,
            penalty_amount: 10000,                    // 10,000 SOV tokens
            conditions: "Data integrity below 99%".to_string(),
            grace_period: 3600,                       // 1 hour grace period
            max_applications: 3,                      // Max 3 applications per day
        },
        PenaltyClause {
            penalty_type: PenaltyType::Unavailability,
            penalty_amount: 5000,                     // 5,000 SOV tokens
            conditions: "Uptime below 95%".to_string(),
            grace_period: 1800,                       // 30 minute grace period
            max_applications: 5,                      // Max 5 applications per day
        },
        // ... additional penalty clauses
    ]
}
```

### Configuration Defaults

```rust
impl Default for EconomicManagerConfig {
    fn default() -> Self {
        Self {
            default_duration_days: 30,
            base_price_per_gb_day: 100,               // 100 SOV tokens per GB/day
            enable_escrow: true,
            quality_premium_rate: 0.10,               // 10% quality premium
            network_fee_rate: 0.05,                   // 5% network fees
            escrow_fee_rate: 0.02,                    // 2% escrow fees
            min_reputation_threshold: 500,            // Minimum reputation for contracts
            performance_bonus_threshold: 0.95,        // 95% performance for bonus
            penalty_grace_period: 3600,               // 1 hour grace period
        }
    }
}
```

##  Statistics and Analytics

### get_statistics()
```rust
pub async fn get_statistics(&self) -> Result<EconomicStats>
```

Get comprehensive economic statistics across all subsystems.

**Example:**
```rust
let stats = manager.get_statistics().await?;

println!("Economic Statistics:");
println!("  Total contracts: {}", stats.total_contracts);
println!("  Total storage under contract: {} GB", 
         stats.total_storage / (1024 * 1024 * 1024));
println!("  Total value locked: {} SOV", stats.total_value_locked);
println!("  Average contract value: {} SOV", stats.average_contract_value);
println!("  Total penalties enforced: {} SOV", stats.total_penalties);
println!("  Total rewards distributed: {} SOV", stats.total_rewards);
```

### EconomicStats Structure

```rust
pub struct EconomicStats {
    pub total_contracts: u64,
    pub total_storage: u64,
    pub total_value_locked: u64,
    pub average_contract_value: u64,
    pub total_penalties: u64,
    pub total_rewards: u64,
    pub active_providers: u32,
    pub average_reputation: f64,
    pub contract_success_rate: f64,
    pub network_utilization: f64,
}
```

##  Configuration Management

### update_config()
```rust
pub fn update_config(&mut self, config: EconomicManagerConfig)
```

Update system configuration dynamically.

### get_config()
```rust
pub fn get_config(&self) -> &EconomicManagerConfig
```

Get current system configuration.

##  Testing and Development

### Unit Testing

```rust
#[tokio::test]
async fn test_economic_manager_creation() {
    let config = EconomicManagerConfig::default();
    let manager = EconomicStorageManager::new(config);
    
    assert_eq!(manager.config.default_duration_days, 30);
    assert_eq!(manager.config.base_price_per_gb_day, 100);
}

#[tokio::test]  
async fn test_storage_request_processing() {
    let mut manager = EconomicStorageManager::new(EconomicManagerConfig::default());
    
    let request = create_test_storage_request();
    let result = manager.process_storage_request(request).await;
    
    // Test would verify quote generation and pricing calculations
    assert!(result.is_ok());
}
```

### Integration Testing

- **End-to-End Workflows**: Test complete storage request to payment flow
- **Multi-Provider Scenarios**: Test provider selection and coordination
- **Performance Monitoring**: Test SLA monitoring and penalty enforcement
- **Economic Model Validation**: Test pricing, incentives, and market dynamics

##  Best Practices

### Request Processing
```rust
// Always validate budget constraints
if total_cost > request.requirements.budget_constraints.max_total_cost {
    return Err(anyhow!("Quote exceeds budget constraints"));
}

// Select high-reputation providers for critical data
let critical_providers = market_manager.find_high_reputation_providers(
    min_reputation_threshold,
    required_capacity
);
```

### Performance Monitoring
```rust
// Regular performance monitoring for all active contracts
async fn monitor_all_contracts(&mut self) -> Result<()> {
    let active_contracts = self.contract_manager.get_active_contracts().await?;
    
    for contract_id in active_contracts {
        if let Err(e) = self.monitor_contract_performance(contract_id).await {
            eprintln!("Contract monitoring failed for {}: {}", contract_id, e);
        }
    }
    
    Ok(())
}
```

### Error Handling
```rust
// Graceful handling of subsystem failures
match self.process_payment(contract_id, amount).await {
    Ok(_) => println!("Payment processed successfully"),
    Err(e) => {
        eprintln!("Payment processing failed: {}", e);
        // Implement retry logic or fallback mechanisms
        self.schedule_payment_retry(contract_id, amount)?;
    }
}
```

---

=======
# Economic Storage Manager (`economic/manager.rs`)

The Economic Storage Manager serves as the central coordination point for all economic activities in the ZHTP storage network. It orchestrates contracts, payments, reputation, quality assurance, and incentive distribution to create a self-sustaining economic ecosystem.

##  Overview

The `EconomicStorageManager` is responsible for:
- **Request Processing**: Converting storage requests into economic quotes
- **Contract Lifecycle**: Managing storage contracts from creation to settlement
- **Payment Coordination**: Processing payments and escrow operations
- **Performance Monitoring**: Tracking service quality and SLA compliance
- **Reputation Management**: Updating provider reputation scores
- **Incentive Distribution**: Calculating and distributing performance rewards

## 🏗️ Core Structure

### EconomicStorageManager

```rust
pub struct EconomicStorageManager {
    /// Configuration
    config: EconomicManagerConfig,
    /// Contract manager
    contract_manager: ContractManager,
    /// Pricing engine
    pricing_engine: PricingEngine,
    /// Market manager
    market_manager: MarketManager,
    /// Reputation system
    reputation_system: ReputationSystem,
    /// Payment processor
    payment_processor: PaymentProcessor,
    /// Incentive manager
    incentive_manager: IncentiveSystem,
    /// Quality assurance
    quality_assurance: QualityAssurance,
    /// Penalty enforcer
    penalty_enforcer: PenaltyEnforcer,
    /// Reward manager
    reward_manager: RewardManager,
}
```

### EconomicManagerConfig

```rust
pub struct EconomicManagerConfig {
    pub default_duration_days: u32,
    pub base_price_per_gb_day: u64,
    pub enable_escrow: bool,
    pub quality_premium_rate: f64,
    pub network_fee_rate: f64,
    pub escrow_fee_rate: f64,
    pub min_reputation_threshold: u32,
    pub performance_bonus_threshold: f64,
    pub penalty_grace_period: u64,
}
```

##  Core Operations

### Storage Request Processing

#### process_storage_request()
```rust
pub async fn process_storage_request(
    &mut self, 
    request: EconomicStorageRequest
) -> Result<EconomicQuote>
```

Process an economic storage request and generate a comprehensive quote.

**Example:**
```rust
let request = EconomicStorageRequest {
    content: document_data,
    filename: "important_contract.pdf".to_string(),
    content_type: "application/pdf".to_string(),
    description: "Legal contract requiring high reliability".to_string(),
    preferred_tier: StorageTier::Warm,
    requirements: StorageRequirements {
        duration_days: 365, // Store for 1 year
        quality_requirements: QualityRequirements {
            min_uptime: 0.99,           // 99% uptime requirement
            max_response_time: 3000,    // 3 second max response
            min_replication: 5,         // 5 replicas for safety
            data_integrity_level: 0.999, // 99.9% integrity
        },
        budget_constraints: BudgetConstraints {
            max_total_cost: 50000,      // 50,000 SOV tokens max
            max_cost_per_gb_day: 200,   // 200 tokens per GB/day max
            preferred_payment_schedule: PaymentSchedule::Monthly,
        },
        geographic_preferences: vec!["US".to_string(), "EU".to_string()],
        replication_factor: 5,
    },
    payment_preferences: PaymentPreferences {
        escrow_preferences: EscrowPreferences {
            use_escrow: true,
            release_schedule: ReleaseSchedule::Milestone,
            dispute_resolution: DisputeResolution::Arbitration,
        },
        payment_method: PaymentMethod::ZhtpTokens,
        auto_renewal: false,
    },
    requester: client_identity,
};

let quote = manager.process_storage_request(request).await?;
```

#### Quote Generation Process

1. **Requirements Analysis**: Parse storage requirements and constraints
2. **Provider Matching**: Find suitable storage providers using market manager
3. **Pricing Calculation**: Generate dynamic pricing using pricing engine
4. **Quality Assessment**: Estimate quality metrics based on provider reputation
5. **Cost Breakdown**: Create detailed cost analysis with all fees
6. **Quote Assembly**: Package all information into comprehensive quote

### Contract Management

#### create_contract()
```rust
pub async fn create_contract(
    &mut self, 
    quote: EconomicQuote, 
    content_hash: ContentHash, 
    content_size: u64
) -> Result<Hash>
```

Create a storage contract from an accepted quote.

**Example:**
```rust
// Client accepts the quote
let contract_id = manager.create_contract(
    accepted_quote, 
    content_hash, 
    file_size
).await?;

println!("Contract created: {}", hex::encode(contract_id.as_bytes()));
```

#### Contract Creation Process

1. **Quote Validation**: Verify quote is still valid and hasn't expired
2. **Contract Terms**: Define storage terms, SLA, and payment schedule
3. **Penalty Clauses**: Add appropriate penalty clauses for SLA violations
4. **Payment Setup**: Schedule payments and setup escrow if required
5. **Market Recording**: Record contract creation in market analytics
6. **Monitoring Setup**: Initialize performance monitoring systems

### Payment Processing

#### process_payment()
```rust
pub async fn process_payment(
    &mut self, 
    contract_id: Hash, 
    payment_amount: u64
) -> Result<()>
```

Process contract payments with performance-based bonus distribution.

**Example:**
```rust
// Process milestone payment
manager.process_payment(contract_id, milestone_amount).await?;
```

#### Payment Distribution Process

1. **Payment Processing**: Process pending payments through payment processor
2. **Contract Update**: Update contract payment status
3. **Performance Assessment**: Evaluate provider performance metrics
4. **Bonus Calculation**: Calculate performance-based bonuses
5. **Reward Distribution**: Distribute payments and bonuses to providers
6. **Incentive Recording**: Update incentive system with payment information

### Performance Monitoring

#### monitor_contract_performance()
```rust
pub async fn monitor_contract_performance(
    &mut self, 
    contract_id: Hash
) -> Result<()>
```

Monitor contract performance and enforce SLA compliance.

**Example:**
```rust
// Monitor all active contracts
let active_contracts = manager.get_active_contracts().await?;
for contract_id in active_contracts {
    manager.monitor_contract_performance(contract_id).await?;
}
```

#### Performance Monitoring Process

1. **Metrics Collection**: Gather performance metrics from quality assurance
2. **SLA Evaluation**: Compare actual performance against SLA requirements
3. **Violation Detection**: Identify any SLA violations or quality issues
4. **Penalty Enforcement**: Apply penalties for violations
5. **Reputation Updates**: Update provider reputation based on performance
6. **Reward Calculation**: Calculate performance-based rewards
7. **Incentive Distribution**: Distribute rewards for good performance

##  Economic Calculations

### Cost Breakdown Generation

```rust
let base_cost = price_quote.final_price;
let quality_premium = (base_cost as f64 * 0.1) as u64;     // 10% quality premium
let network_fees = (base_cost as f64 * 0.05) as u64;       // 5% network fees
let escrow_fees = if use_escrow {
    (base_cost as f64 * 0.02) as u64                       // 2% escrow fees
} else { 0 };

let total_cost = base_cost + quality_premium + network_fees + escrow_fees;
```

### Quality Metrics Calculation

```rust
async fn calculate_expected_quality(&self, nodes: &[String]) -> Result<QualityMetrics> {
    let mut total_reliability = 0.0;
    let mut total_availability = 0.0;
    let mut total_response_time = 0;
    let mut total_integrity = 0.0;

    for node_id in nodes {
        let reputation = self.reputation_system.get_reputation(node_id)?;
        let metrics = self.quality_assurance.get_node_metrics(node_id).await?;
        
        total_reliability += reputation.overall_score;
        total_availability += metrics.availability;
        total_response_time += metrics.avg_response_time;
        total_integrity += metrics.data_integrity;
    }

    let node_count = nodes.len() as f64;
    
    Ok(QualityMetrics {
        current_uptime: total_availability / node_count,
        avg_response_time: (total_response_time as f64 / node_count) as u64,
        data_integrity: total_integrity / node_count,
        reliability: total_reliability / node_count,
        overall_score: (total_reliability / node_count) * 0.5 + 
                      (total_availability / node_count) * 0.3 + 
                      (total_integrity / node_count) * 0.2,
        // ... other fields
    })
}
```

### Penalty Calculation

```rust
fn calculate_penalty_amount(&self, penalty_type: &PenaltyType, contract_value: u64) -> u64 {
    match penalty_type {
        PenaltyType::DataLoss => contract_value / 2,        // 50% of contract value
        PenaltyType::Unavailability => contract_value / 10, // 10% of contract value
        PenaltyType::SlowResponse => contract_value / 20,   // 5% of contract value
        PenaltyType::ContractBreach => contract_value,     // 100% of contract value
        PenaltyType::QualityDegradation => contract_value / 5, // 20% of contract value
    }
}
```

##  Default Configurations

### Default Penalty Clauses

```rust
fn create_default_penalties(&self) -> Vec<PenaltyClause> {
    vec![
        PenaltyClause {
            penalty_type: PenaltyType::DataLoss,
            penalty_amount: 10000,                    // 10,000 SOV tokens
            conditions: "Data integrity below 99%".to_string(),
            grace_period: 3600,                       // 1 hour grace period
            max_applications: 3,                      // Max 3 applications per day
        },
        PenaltyClause {
            penalty_type: PenaltyType::Unavailability,
            penalty_amount: 5000,                     // 5,000 SOV tokens
            conditions: "Uptime below 95%".to_string(),
            grace_period: 1800,                       // 30 minute grace period
            max_applications: 5,                      // Max 5 applications per day
        },
        // ... additional penalty clauses
    ]
}
```

### Configuration Defaults

```rust
impl Default for EconomicManagerConfig {
    fn default() -> Self {
        Self {
            default_duration_days: 30,
            base_price_per_gb_day: 100,               // 100 SOV tokens per GB/day
            enable_escrow: true,
            quality_premium_rate: 0.10,               // 10% quality premium
            network_fee_rate: 0.05,                   // 5% network fees
            escrow_fee_rate: 0.02,                    // 2% escrow fees
            min_reputation_threshold: 500,            // Minimum reputation for contracts
            performance_bonus_threshold: 0.95,        // 95% performance for bonus
            penalty_grace_period: 3600,               // 1 hour grace period
        }
    }
}
```

##  Statistics and Analytics

### get_statistics()
```rust
pub async fn get_statistics(&self) -> Result<EconomicStats>
```

Get comprehensive economic statistics across all subsystems.

**Example:**
```rust
let stats = manager.get_statistics().await?;

println!("Economic Statistics:");
println!("  Total contracts: {}", stats.total_contracts);
println!("  Total storage under contract: {} GB", 
         stats.total_storage / (1024 * 1024 * 1024));
println!("  Total value locked: {} SOV", stats.total_value_locked);
println!("  Average contract value: {} SOV", stats.average_contract_value);
println!("  Total penalties enforced: {} SOV", stats.total_penalties);
println!("  Total rewards distributed: {} SOV", stats.total_rewards);
```

### EconomicStats Structure

```rust
pub struct EconomicStats {
    pub total_contracts: u64,
    pub total_storage: u64,
    pub total_value_locked: u64,
    pub average_contract_value: u64,
    pub total_penalties: u64,
    pub total_rewards: u64,
    pub active_providers: u32,
    pub average_reputation: f64,
    pub contract_success_rate: f64,
    pub network_utilization: f64,
}
```

##  Configuration Management

### update_config()
```rust
pub fn update_config(&mut self, config: EconomicManagerConfig)
```

Update system configuration dynamically.

### get_config()
```rust
pub fn get_config(&self) -> &EconomicManagerConfig
```

Get current system configuration.

##  Testing and Development

### Unit Testing

```rust
#[tokio::test]
async fn test_economic_manager_creation() {
    let config = EconomicManagerConfig::default();
    let manager = EconomicStorageManager::new(config);
    
    assert_eq!(manager.config.default_duration_days, 30);
    assert_eq!(manager.config.base_price_per_gb_day, 100);
}

#[tokio::test]  
async fn test_storage_request_processing() {
    let mut manager = EconomicStorageManager::new(EconomicManagerConfig::default());
    
    let request = create_test_storage_request();
    let result = manager.process_storage_request(request).await;
    
    // Test would verify quote generation and pricing calculations
    assert!(result.is_ok());
}
```

### Integration Testing

- **End-to-End Workflows**: Test complete storage request to payment flow
- **Multi-Provider Scenarios**: Test provider selection and coordination
- **Performance Monitoring**: Test SLA monitoring and penalty enforcement
- **Economic Model Validation**: Test pricing, incentives, and market dynamics

##  Best Practices

### Request Processing
```rust
// Always validate budget constraints
if total_cost > request.requirements.budget_constraints.max_total_cost {
    return Err(anyhow!("Quote exceeds budget constraints"));
}

// Select high-reputation providers for critical data
let critical_providers = market_manager.find_high_reputation_providers(
    min_reputation_threshold,
    required_capacity
);
```

### Performance Monitoring
```rust
// Regular performance monitoring for all active contracts
async fn monitor_all_contracts(&mut self) -> Result<()> {
    let active_contracts = self.contract_manager.get_active_contracts().await?;
    
    for contract_id in active_contracts {
        if let Err(e) = self.monitor_contract_performance(contract_id).await {
            eprintln!("Contract monitoring failed for {}: {}", contract_id, e);
        }
    }
    
    Ok(())
}
```

### Error Handling
```rust
// Graceful handling of subsystem failures
match self.process_payment(contract_id, amount).await {
    Ok(_) => println!("Payment processed successfully"),
    Err(e) => {
        eprintln!("Payment processing failed: {}", e);
        // Implement retry logic or fallback mechanisms
        self.schedule_payment_retry(contract_id, amount)?;
    }
}
```

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
The Economic Storage Manager creates a sophisticated economic ecosystem that aligns incentives between storage providers and clients while ensuring high-quality service delivery through automated monitoring and enforcement mechanisms.