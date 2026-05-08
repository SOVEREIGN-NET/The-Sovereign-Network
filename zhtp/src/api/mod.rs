//! API Module
//!
//! Clean, minimal API structure for ZHTP

pub mod auth_errors;
pub mod handlers;
pub mod middleware;
pub mod principal;
pub mod server;

pub use handlers::*;
pub use middleware::*;
pub use server::*;
