//! Global in-process grant registry (dual-auth Phase B2).
//!
//! Process-local until sled/chain persistence lands. Same OnceLock pattern as
//! other runtime providers.

use lib_access_control::GrantRegistry;
use std::sync::OnceLock;
use tracing::info;

static GLOBAL_GRANT_REGISTRY: OnceLock<GrantRegistry> = OnceLock::new();

/// Install (or return) the process grant registry. Safe to call repeatedly.
pub fn get_global_grant_registry() -> &'static GrantRegistry {
    GLOBAL_GRANT_REGISTRY.get_or_init(|| {
        info!(target: "access_control", "Initializing global GrantRegistry (in-memory)");
        GrantRegistry::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_access_control::{GrantAuthDescriptor, GrantAuthScheme, GrantClass, GrantRecord};
    use lib_access_control::{AccessDomain, AccessOperation};

    #[test]
    fn global_registry_offer_claim() {
        let reg = get_global_grant_registry();
        let id = format!("test-offer-{}", std::process::id());
        let offer = GrantRecord::offer_council(
            &id,
            "did:zhtp:test-alice",
            "did:zhtp:council",
            GrantClass::AuditRead,
            vec![AccessDomain::WalletGraph],
            vec![AccessOperation::Read],
        );
        // May already exist if tests re-run in same process — ignore duplicate.
        let _ = reg.register_offer(offer);
        let _ = reg.claim(
            &id,
            "did:zhtp:test-alice",
            GrantAuthDescriptor {
                scheme: GrantAuthScheme::DevAccept,
                public_key: vec![],
            },
            1,
        );
        assert!(reg.get(&id).is_some());
    }
}
