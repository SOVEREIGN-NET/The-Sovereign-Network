//! Canonical bonding-curve API surface.
//!
//! Legacy route families under `/api/v1/curve`, `/api/v1/swap`, and
//! `/api/v1/valuation` have been removed. The canonical public API lives under
//! `/api/v1/bonding-curve/*`.

pub mod api_v1;

use anyhow::Result;
use serde_json::Value;

use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

pub(crate) fn create_json_response(data: Value) -> Result<ZhtpResponse> {
    let json_response = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

pub(crate) fn create_error_response(status: ZhtpStatus, message: String) -> ZhtpResponse {
    ZhtpResponse::error(status, message)
}
