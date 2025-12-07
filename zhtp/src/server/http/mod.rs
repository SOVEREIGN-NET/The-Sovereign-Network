//! HTTP Server Module
//!
//! Provides HTTP middleware (CORS, rate limiting, auth)
//!
//! NOTE: HttpRouter removed - QUIC is the only entry point.
//! HTTP requests over QUIC are handled by HttpCompatibilityLayer → ZhtpRouter

pub mod middleware;

pub use middleware::{Middleware, CorsMiddleware, RateLimitMiddleware, AuthMiddleware};
