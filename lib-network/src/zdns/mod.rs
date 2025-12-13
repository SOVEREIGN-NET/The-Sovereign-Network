//! ZDNS (Zero-Knowledge Domain Name System) Resolver
//!
//! This module provides a high-performance, caching DNS resolver for Web4 domains.
//! It integrates with the DomainRegistry and provides:
//!
//! - LRU caching for resolved records
//! - TTL-based cache expiration
//! - Cache invalidation on domain changes
//! - Thread-safe concurrent access
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
//! │  Gateway/API     │────▶│   ZdnsResolver   │────▶│  DomainRegistry  │
//! │  Handlers        │     │   (LRU Cache)    │     │  (Storage)       │
//! └──────────────────┘     └──────────────────┘     └──────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let resolver = ZdnsResolver::new(domain_registry.clone(), ZdnsConfig::default());
//!
//! // Resolve a domain (hits cache or registry)
//! let record = resolver.resolve_web4("myapp.zhtp").await?;
//!
//! // Invalidate cache when domain changes
//! resolver.invalidate("myapp.zhtp");
//! ```

mod resolver;
mod config;
mod error;

pub use resolver::{ZdnsResolver, Web4Record, CachedRecord};
pub use config::ZdnsConfig;
pub use error::ZdnsError;
