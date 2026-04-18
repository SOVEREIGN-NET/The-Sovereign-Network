//! zhtp-daemon library — reusable gateway service and QUIC server.
//!
//! When used as a library from the `zhtp` binary, only the gateway/ingress
//! parts are typically needed.  The HTTP server (browser-extension API) is
//! kept in `main.rs` and is NOT re-exported here.

pub mod backend_pool;
pub mod config;
pub mod discovery;
pub mod identity;
pub mod metrics;
pub mod quic_server;
pub mod service;

// api module is HTTP-only; not re-exported for library use.
mod api;
