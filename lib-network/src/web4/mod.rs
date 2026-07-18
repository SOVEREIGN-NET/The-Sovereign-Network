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
#[cfg(feature = "quic")]
pub mod client;
pub mod content_publisher;
pub mod content_service;
pub mod domain_registry;
pub mod domain_signing;
pub mod name_resolver;
pub mod types;

#[cfg(feature = "quic")]
pub use client::Web4Client;
pub use content_publisher::*;
pub use content_service::*;
pub use domain_registry::*;
pub use domain_signing::{
    domain_registration_signing_message, domain_transfer_signing_candidates,
    domain_update_signing_message, domain_update_signing_message_legacy,
    domain_update_verify_candidates, has_owner_signing_key, validate_domain_owner_signature_hex,
    verify_domain_registration_signature, verify_domain_transfer_signature,
    verify_domain_update_signature, DILITHIUM5_HEX_SIGNATURE_LEN, ZHTP_DOMAIN_UPDATE_SIGN_DOMAIN,
};
pub use name_resolver::NameResolver;
#[cfg(feature = "quic")]
pub use trust::{
    TrustAnchor, TrustAuditEntry, TrustConfig, TrustDb, TrustPolicy, ZhtpTrustVerifier,
};
pub use types::*;

// NOTE: initialization helpers removed - zhtp is the composition root
// zhtp wires DomainRegistry + ContentPublisher -> Web4Manager directly
