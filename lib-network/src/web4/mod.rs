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

pub mod domain_registry;
pub mod content_publisher;
pub mod content_service;
pub mod types;
pub mod client;

pub use domain_registry::*;
pub use content_publisher::*;
pub use content_service::*;
pub use types::*;
pub use client::Web4Client;

use anyhow::Result;
use crate::dht::ZkDHTIntegration;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Initialize the Web4 system with DHT backend
pub async fn initialize_web4_system() -> Result<Web4Manager> {
    initialize_web4_system_with_dht(None).await
}

/// Initialize the Web4 system with existing storage system to avoid creating duplicates
pub async fn initialize_web4_system_with_storage(storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>) -> Result<Web4Manager> {
    let manager = Web4Manager::new_with_storage(storage).await?;
    tracing::info!("Web4 domain registry and content publishing system initialized with existing storage");
    Ok(manager)
}

/// Initialize the Web4 system with optional existing DHT client to avoid creating duplicates
pub async fn initialize_web4_system_with_dht(dht_client: Option<ZkDHTIntegration>) -> Result<Web4Manager> {
    let manager = Web4Manager::new_with_dht(dht_client).await?;
    tracing::info!("Web4 domain registry and content publishing system initialized");
    Ok(manager)
}