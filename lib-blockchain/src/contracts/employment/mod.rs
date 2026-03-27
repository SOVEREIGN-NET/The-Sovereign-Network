//! Employment contract tracking module
//!
//! Provides employment contract registry with tax, profit-sharing, and voting power integration.

pub mod employment_registry;

pub use employment_registry::{
    ContractAccessType, EconomicPeriod, EmploymentContract, EmploymentRegistry, EmploymentStatus,
    PaymentDetails, ProfitShareResult, TerminationReason,
};
