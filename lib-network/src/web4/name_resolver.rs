//! Chain-backed name resolver (view model).

use std::sync::Arc;
use anyhow::Result;

use super::domain_registry::DomainRegistry;
use super::types::ResolvedNameRecord;

#[derive(Clone)]
pub struct NameResolver {
    registry: Arc<DomainRegistry>,
}

impl NameResolver {
    pub fn new(registry: Arc<DomainRegistry>) -> Self {
        Self { registry }
    }

    /// Resolve a name into a read-only view model.
    ///
    /// NOTE: Until chain-backed queries are wired, this uses the local registry cache.
    pub async fn resolve(&self, domain: &str) -> Result<ResolvedNameRecord> {
        let record = self.registry.lookup_domain(domain).await?;
        Ok(record.into())
    }

    pub fn registry(&self) -> &Arc<DomainRegistry> {
        &self.registry
    }
}
