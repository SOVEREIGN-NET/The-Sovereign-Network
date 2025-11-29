# Economics Module

This module provides economic logic for ZHTP protocols, integrating with the `lib-economy` package for DAO fees, UBI, and economic models.

## Main Types
- `ZhtpEconomics`: Holds the economic model and config.
- `EconomicConfig`: Configures DAO fees, UBI, and fee calculation methods.
- `EconomicAssessment`: Represents a fee breakdown for an operation.

## Key Features
- Dynamic fee calculation based on operation type, data size, and priority
- DAO fee and UBI support
- Configurable fee methods and minimums

## Example Usage
```rust
let econ = ZhtpEconomics::new(EconomicConfig::default())?;
let assessment = econ.calculate_operation_fees("POST", 2048, Priority::Normal)?;
```
