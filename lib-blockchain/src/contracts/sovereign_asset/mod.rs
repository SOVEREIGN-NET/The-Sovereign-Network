//! Sovereign Asset — unified DAO/token primitive (ADR: docs/arch/sovereign-asset.md).

mod projection;
mod state;
mod types;

pub use projection::{
    is_sov_native_token_id, merge_curve_into_asset, project_from_bonding_curve_token,
    project_from_token_contract, BUBL_NAME, BUBL_SYMBOL,
};
pub use state::*;
pub use types::*;