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

pub mod resolver;
pub mod config;
pub mod error;
pub mod packet;
pub mod transport;

pub use resolver::{ZdnsResolver, Web4Record, CachedRecord, ResolverMetrics};
pub use config::ZdnsConfig;
pub use error::ZdnsError;
pub use packet::{DnsPacket, DnsQuestion, DnsAnswer, MAX_UDP_SIZE};
pub use transport::{ZdnsTransportServer, ZdnsServerConfig, TransportStats, DNS_PORT};
