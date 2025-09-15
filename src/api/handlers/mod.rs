//! ZHTP API Handlers
//! 
//! Categorized API handlers for the ZHTP orchestrator.
//! Each module handles a specific domain of functionality.

pub mod identity;
pub mod wallet;
pub mod dao;
pub mod blockchain;
pub mod network;
pub mod protocol;
pub mod zk;
// pub mod session;
// pub mod content;
// pub mod economics;

#[cfg(test)]
pub mod identity_integration_test;

// Re-export all handlers
pub use identity::*;
pub use wallet::*;
pub use dao::*;
pub use blockchain::*;
pub use network::*;
pub use protocol::*;
pub use zk::*;
// pub use session::*;
// pub use content::*;
// pub use economics::*;

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

/// Base trait for all API handlers
#[async_trait::async_trait]
pub trait ApiHandler: Send + Sync {
    /// Handle the API request
    async fn handle(&self, method: &str, path: &str, body: &[u8], headers: &HashMap<String, String>) -> Result<Value>;
    
    /// Check if this handler can handle the given path
    fn can_handle(&self, path: &str) -> bool;
    
    /// Get the base path this handler manages
    fn base_path(&self) -> &'static str;
}

/// Helper macro to create simple JSON responses
#[macro_export]
macro_rules! json_response {
    ($($key:expr => $value:expr),* $(,)?) => {
        serde_json::json!({
            $($key: $value,)*
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "orchestrator": "ZHTP v1.0"
        })
    };
}

/// Helper macro to create error responses
#[macro_export]
macro_rules! error_response {
    ($code:expr, $message:expr) => {
        serde_json::json!({
            "error": {
                "code": $code,
                "message": $message,
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            }
        })
    };
}
