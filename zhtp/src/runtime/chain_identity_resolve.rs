//! Chain-first identity resolution for reward / PoUW paths.
//!
//! Committed blockchain projections are authoritative. IdentityManager is only
//! a fallback when the global blockchain is unavailable (unit tests / early
//! boot). When the chain is available, a DID present only in the manager is
//! treated as missing so stale local cache cannot authorize rewards.

use std::sync::Arc;
use tokio::sync::RwLock;

use lib_identity::IdentityManager;

/// Where a PoUW client identity was resolved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PouwIdentitySource {
    /// Durable / in-block projection via blockchain facades.
    Chain,
    /// IdentityManager only — blockchain provider unavailable.
    ManagerFallback,
}

/// Minimal identity view needed for PoUW eligibility and signature checks.
#[derive(Debug, Clone)]
pub struct PouwClientIdentity {
    pub did: String,
    pub created_at: u64,
    /// Dilithium5 public key bytes (2592).
    pub dilithium_pk: Vec<u8>,
    pub source: PouwIdentitySource,
}

/// Resolve a client DID for PoUW: chain first, manager only if chain is down.
///
/// # Errors
/// Returns a human-readable error for API / rejection mapping.
pub async fn resolve_pouw_client_identity(
    client_did: &str,
    identity_manager: &Arc<RwLock<IdentityManager>>,
) -> Result<PouwClientIdentity, String> {
    if !client_did.starts_with("did:zhtp:") {
        return Err("Invalid DID format: must start with 'did:zhtp:'".to_string());
    }

    match crate::runtime::blockchain_provider::get_global_blockchain().await {
        Ok(bc_arc) => {
            let bc = bc_arc.read().await;
            if !bc.identity_exists(client_did) {
                return Err(format!(
                    "Client DID not found on chain identity projection: {}",
                    client_did
                ));
            }

            let created_at = bc
                .identity_consensus_by_did(client_did)
                .map(|c| c.created_at)
                .or_else(|| {
                    bc.identity_transaction_data(client_did)
                        .map(|d| d.created_at)
                })
                .unwrap_or(0);

            let dilithium_pk = bc.identity_public_key(client_did).ok_or_else(|| {
                format!(
                    "Client DID on chain but Dilithium public key missing: {}",
                    client_did
                )
            })?;

            Ok(PouwClientIdentity {
                did: client_did.to_string(),
                created_at,
                dilithium_pk,
                source: PouwIdentitySource::Chain,
            })
        }
        Err(_) => {
            // Chain unavailable: manager is the only option (tests / early boot).
            let mgr = identity_manager.read().await;
            let identity = mgr.get_identity_by_did(client_did).ok_or_else(|| {
                format!(
                    "Client DID not found in identity registry (chain unavailable): {}",
                    client_did
                )
            })?;
            if identity.did != client_did {
                return Err(format!(
                    "Client DID mismatch: requested {}, found {}",
                    client_did, identity.did
                ));
            }
            Ok(PouwClientIdentity {
                did: client_did.to_string(),
                created_at: identity.created_at,
                dilithium_pk: identity.public_key.dilithium_pk.to_vec(),
                source: PouwIdentitySource::ManagerFallback,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::IdentityType;

    #[tokio::test]
    async fn manager_fallback_when_chain_unavailable() {
        let did = "did:zhtp:1111111111111111111111111111111111111111111111111111111111111111";
        let keypair = lib_crypto::generate_keypair().expect("keypair");
        let identity_id = lib_identity::did::parse_did_to_identity_id(did).expect("did");
        let mgr = Arc::new(RwLock::new(IdentityManager::new()));
        mgr.write()
            .await
            .register_external_identity(
                identity_id,
                did.to_string(),
                keypair.public_key,
                IdentityType::Human,
                "test-device".to_string(),
                Some("test".to_string()),
                1_700_000_000,
            )
            .expect("register");

        // Do not set global blockchain — fallback path.
        let view = resolve_pouw_client_identity(did, &mgr)
            .await
            .expect("manager fallback");
        assert_eq!(view.source, PouwIdentitySource::ManagerFallback);
        assert_eq!(view.created_at, 1_700_000_000);
        assert_eq!(view.dilithium_pk.len(), 2592);
    }

    #[tokio::test]
    async fn rejects_bad_did_format() {
        let mgr = Arc::new(RwLock::new(IdentityManager::new()));
        let err = resolve_pouw_client_identity("not-a-did", &mgr)
            .await
            .unwrap_err();
        assert!(err.contains("Invalid DID format"));
    }
}
