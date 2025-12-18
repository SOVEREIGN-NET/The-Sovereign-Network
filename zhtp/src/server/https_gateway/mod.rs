//! HTTPS Gateway Server for Web4 Browser Access
//!
//! Provides HTTPS termination for browsers to access Web4 content.
//! This is the primary entry point for browser-based Web4 access.
//!
//! # Architecture
//!
//! ```text
//! Browser (HTTPS) → HTTPS Gateway → Web4ContentService → DHT Content
//!                      ↓
//!                 TLS Termination
//!                 (CA certs or private CA)
//! ```
//!
//! # TLS Modes
//!
//! 1. **Standard CA** (default for alpha): Uses certificates from Let's Encrypt or other CAs
//! 2. **Private CA**: For enterprise/controlled environments with `.zhtp`/`.sov` domains
//! 3. **Self-signed**: For development/testing
//!
//! # Host Routing
//!
//! - `myapp.zhtp.gateway.example.com` → Web4 domain `myapp.zhtp`
//! - `myapp.zhtp.localhost:8443` → Local development
//! - Standard domains → Gateway landing page or error

mod config;
mod server;
mod handlers;

pub use config::{GatewayTlsConfig, TlsMode};
pub use server::HttpsGateway;
pub use handlers::gateway_handler;

#[cfg(test)]
mod tests;
