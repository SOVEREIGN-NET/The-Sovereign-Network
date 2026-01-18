//! Web4 Domain Registry and Content Publishing System
//!
//! This module provides the formal Web4 domain registry and content publishing
//! infrastructure that was missing from the ZHTP ecosystem. It integrates with
//! the existing DHT and ZDNS systems to provide complete Web4 functionality.
//!
//! # Content Service
//!
//! The `Web4ContentService` is the single canonical internal API for retrieving
//! and serving Web4 content. It handles:
//! - Path normalization (security-critical)
//! - SPA routing policy
//! - MIME type resolution
//! - Cache header generation

#[cfg(feature = "quic")]
pub mod trust;

// Web4 system - always compiled with protocol-only design
// Uses trait-based UnifiedStorage from lib-network, never depends on lib-storage directly
pub mod domain_registry;
pub mod name_resolver;
pub mod content_publisher;
pub mod content_service;
pub mod types;
#[cfg(feature = "quic")]
pub mod client;

pub use domain_registry::*;
pub use name_resolver::NameResolver;
pub use content_publisher::*;
pub use content_service::*;
pub use types::*;
#[cfg(feature = "quic")]
pub use client::Web4Client;
#[cfg(feature = "quic")]
pub use trust::{TrustConfig, TrustDb, TrustAnchor, TrustPolicy, TrustAuditEntry, ZhtpTrustVerifier};

// NOTE: initialization helpers removed - zhtp is the composition root
// zhtp wires DomainRegistry + ContentPublisher -> Web4Manager directly
