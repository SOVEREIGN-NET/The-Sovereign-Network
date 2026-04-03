pub mod cbe_token;
pub mod constants;
pub mod core;
pub mod dao_token;
pub mod functions;
pub mod token_id;

// Re-export core types and canonical token ID function
pub use core::{TokenContract, TokenInfo};
pub use dao_token::DAOToken;
pub use token_id::derive_token_id;

// Re-export canonical SOV constants (single source of truth)
pub use constants::{
    SOV_FEE_RATE_BPS, SOV_PROTOCOL_DECIMALS, SOV_PROTOCOL_MAX_SUPPLY, SOV_TOKEN_DECIMALS,
    SOV_TOKEN_MAX_SUPPLY, SOV_TOKEN_NAME, SOV_TOKEN_SYMBOL, SOV_TOTAL_SUPPLY_TOKENS,
};
pub use lib_types::{
    CBE_DECIMALS as CBE_PROTOCOL_DECIMALS, CBE_MAX_SUPPLY as CBE_PROTOCOL_MAX_SUPPLY,
    CBE_TOTAL_SUPPLY_TOKENS,
};

// Re-export CBE token
pub use cbe_token::{
    CbeToken, CbeTokenError, DistributionAllocation, VestingPool, VestingSchedule,
    CBE_COMPENSATION_POOL, CBE_DECIMALS, CBE_NAME, CBE_OPERATIONAL_TREASURY,
    CBE_PERFORMANCE_INCENTIVES, CBE_STRATEGIC_RESERVES, CBE_SYMBOL, CBE_TOTAL_SUPPLY,
};
