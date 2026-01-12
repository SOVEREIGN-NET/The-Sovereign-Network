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
//! │  Gateway/API     │────▶│   ZdnsResolver   │────▶│  NameResolver    │
//! │  Handlers        │     │   (LRU Cache)    │     │  (Storage)       │
//! └──────────────────┘     └──────────────────┘     └──────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let resolver = ZdnsResolver::new(name_resolver.clone(), ZdnsConfig::default());
//!
//! // Resolve a domain (hits cache or registry)
//! let record = resolver.resolve_web4("myapp.zhtp").await?;
//!
//! // Invalidate cache when domain changes
//! resolver.invalidate("myapp.zhtp");
//! ```

// ZDNS runtime was moved to zhtp; enabling storage-integration here is blocked until relocation is finished.
#[cfg(feature = "storage-integration")]
compile_error!("lib-network no longer ships ZDNS runtime. Use zhtp stubs/relocated module (Phase 4 relocation pass).");

#[cfg(feature = "storage-integration")]
pub mod resolver;
#[cfg(feature = "storage-integration")]
pub mod config;
#[cfg(feature = "storage-integration")]
pub mod error;
#[cfg(feature = "storage-integration")]
pub mod packet;
#[cfg(feature = "storage-integration")]
pub mod transport;

#[cfg(feature = "storage-integration")]
pub use resolver::{ZdnsResolver, Web4Record, CachedRecord, ResolverMetrics};
#[cfg(feature = "storage-integration")]
pub use config::ZdnsConfig;
#[cfg(feature = "storage-integration")]
pub use error::ZdnsError;
#[cfg(feature = "storage-integration")]
pub use packet::{DnsPacket, DnsQuestion, DnsAnswer, MAX_UDP_SIZE};
#[cfg(feature = "storage-integration")]
pub use transport::{ZdnsTransportServer, ZdnsServerConfig, TransportStats, DNS_PORT};
