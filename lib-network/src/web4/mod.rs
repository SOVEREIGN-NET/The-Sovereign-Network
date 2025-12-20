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

// Web4 has been stubbed/moved to zhtp; enable storage-integration only after relocation.
#[cfg(feature = "storage-integration")]
compile_error!("lib-network no longer owns Web4. Use zhtp web4_stub or the relocated module (Phase 4 relocation pass).");

#[cfg(feature = "storage-integration")]
pub mod domain_registry;
#[cfg(feature = "storage-integration")]
pub mod content_publisher;
#[cfg(feature = "storage-integration")]
pub mod content_service;
#[cfg(feature = "storage-integration")]
pub mod types;
#[cfg(feature = "storage-integration")]
pub mod client;
#[cfg(feature = "storage-integration")]
pub mod trust;

#[cfg(feature = "storage-integration")]
pub use domain_registry::*;
#[cfg(feature = "storage-integration")]
pub use content_publisher::*;
#[cfg(feature = "storage-integration")]
pub use content_service::*;
#[cfg(feature = "storage-integration")]
pub use types::*;
#[cfg(feature = "storage-integration")]
pub use client::Web4Client;
#[cfg(feature = "storage-integration")]
pub use trust::{TrustConfig, TrustDb, TrustAnchor, TrustPolicy, TrustAuditEntry, ZhtpTrustVerifier};

#[cfg(feature = "storage-integration")]
use anyhow::Result;
#[cfg(feature = "storage-integration")]
use crate::dht::ZkDHTIntegration;
#[cfg(feature = "storage-integration")]
use std::sync::Arc;
#[cfg(feature = "storage-integration")]
use tokio::sync::RwLock;

/// Initialize the Web4 system with DHT backend
#[cfg(feature = "storage-integration")]
pub async fn initialize_web4_system() -> Result<Web4Manager> {
    initialize_web4_system_with_dht(None).await
}

/// Initialize the Web4 system with existing storage system to avoid creating duplicates
#[cfg(feature = "storage-integration")]
pub async fn initialize_web4_system_with_storage(storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>) -> Result<Web4Manager> {
    let manager = Web4Manager::new_with_storage(storage).await?;
    tracing::info!("Web4 domain registry and content publishing system initialized with existing storage");
    Ok(manager)
}

/// Initialize the Web4 system with optional existing DHT client to avoid creating duplicates
#[cfg(feature = "storage-integration")]
pub async fn initialize_web4_system_with_dht(dht_client: Option<ZkDHTIntegration>) -> Result<Web4Manager> {
    let manager = Web4Manager::new_with_dht(dht_client).await?;
    tracing::info!("Web4 domain registry and content publishing system initialized");
    Ok(manager)
}
