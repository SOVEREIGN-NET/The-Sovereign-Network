pub mod constants;
pub mod core;
pub mod functions;
pub mod dao_token;
pub mod token_id;
pub mod cbe_token;

// Re-export core types and canonical token ID function
pub use core::{TokenContract, TokenInfo};
pub use dao_token::DAOToken;
pub use token_id::derive_token_id;

// Re-export canonical SOV constants (single source of truth)
pub use constants::{
    SOV_TOKEN_NAME, SOV_TOKEN_SYMBOL, SOV_TOKEN_DECIMALS,
    SOV_TOKEN_MAX_SUPPLY, SOV_FEE_RATE_BPS,
};

// Re-export CBE token
pub use cbe_token::{
    CbeToken, CbeTokenError, DistributionAllocation, VestingSchedule, VestingPool,
    CBE_TOTAL_SUPPLY, CBE_DECIMALS, CBE_SYMBOL, CBE_NAME,
    CBE_COMPENSATION_POOL, CBE_OPERATIONAL_TREASURY,
    CBE_PERFORMANCE_INCENTIVES, CBE_STRATEGIC_RESERVES,
};
