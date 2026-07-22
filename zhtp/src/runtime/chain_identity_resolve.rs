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
            // Committed projection only — never treat pure mempool pending as
            // PoUW-eligible (matches module doc; identity_exists includes pending).
            if !bc.identity_committed(client_did) {
                return Err(format!(
                    "Client DID not found on chain identity projection: {}",
                    client_did
                ));
            }

            // Fail closed on age: created_at=0 (Unix epoch) would pass any
            // min_identity_age_secs gate. Missing projection fields must not
            // become age-exempt (#2925 review).
            let created_at = bc
                .identity_consensus_by_did(client_did)
                .map(|c| c.created_at)
                .or_else(|| {
                    bc.identity_transaction_data(client_did)
                        .map(|d| d.created_at)
                })
                .filter(|&ts| ts > 0)
                .ok_or_else(|| {
                    format!(
                        "Client DID on chain but created_at unresolvable: {}",
                        client_did
                    )
                })?;

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
    use lib_blockchain::Blockchain;
    use lib_identity::IdentityType;
    use std::sync::{Mutex, OnceLock};

    /// Serialise tests that touch the process-global blockchain provider.
    fn global_blockchain_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    async fn install_empty_global_blockchain() {
        crate::runtime::blockchain_provider::initialize_global_blockchain_provider();
        let bc = Blockchain::new().expect("genesis");
        crate::runtime::blockchain_provider::set_global_blockchain(Arc::new(RwLock::new(bc)))
            .await
            .expect("set global blockchain");
    }

    async fn clear_global_blockchain() {
        crate::runtime::blockchain_provider::clear_global_blockchain_for_tests().await;
    }

    async fn register_manager_did(did: &str, created_at: u64) -> Arc<RwLock<IdentityManager>> {
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
                created_at,
            )
            .expect("register");
        mgr
    }

    #[tokio::test]
    async fn manager_fallback_when_chain_unavailable() {
        let _guard = global_blockchain_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Ensure chain path is closed so this test is deterministic under
        // parallel workers that may have set the global provider.
        clear_global_blockchain().await;

        let did = "did:zhtp:1111111111111111111111111111111111111111111111111111111111111111";
        let mgr = register_manager_did(did, 1_700_000_000).await;

        let view = resolve_pouw_client_identity(did, &mgr)
            .await
            .expect("manager fallback");
        assert_eq!(view.source, PouwIdentitySource::ManagerFallback);
        assert_eq!(view.created_at, 1_700_000_000);
        assert_eq!(view.dilithium_pk.len(), 2592);
    }

    #[tokio::test]
    async fn rejects_manager_only_did_when_chain_available() {
        let _guard = global_blockchain_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let did = "did:zhtp:2222222222222222222222222222222222222222222222222222222222222222";
        let mgr = register_manager_did(did, 1_700_000_000).await;

        // Chain up, empty projection: DID exists only in IdentityManager.
        install_empty_global_blockchain().await;

        let err = resolve_pouw_client_identity(did, &mgr)
            .await
            .expect_err("stale manager DID must not authorize when chain is up");
        assert!(
            err.contains("not found on chain identity projection"),
            "expected chain rejection, got: {err}"
        );
        assert!(
            !err.contains("chain unavailable"),
            "must not take manager-fallback path: {err}"
        );

        clear_global_blockchain().await;
    }

    #[tokio::test]
    async fn rejects_chain_identity_with_unresolvable_created_at() {
        let _guard = global_blockchain_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let did = "did:zhtp:3333333333333333333333333333333333333333333333333333333333333333";
        let mgr = Arc::new(RwLock::new(IdentityManager::new()));

        crate::runtime::blockchain_provider::initialize_global_blockchain_provider();
        let mut bc = Blockchain::new().expect("genesis");
        // Shadow-only identity with created_at=0: committed for existence, but
        // age must fail closed (never treat epoch as "old enough").
        bc.insert_identity_shadow(
            did.to_string(),
            lib_blockchain::transaction::IdentityTransactionData {
                did: did.to_string(),
                did_document_hash: lib_blockchain::Hash::default(),
                public_key: vec![0xAB; 2592],
                ownership_proof: vec![],
                identity_type: "Human".to_string(),
                display_name: "zero-age".to_string(),
                registration_fee: 0,
                dao_fee: 0,
                created_at: 0,
                controlled_nodes: vec![],
                owned_wallets: vec![],
                kyber_public_key: vec![],
            },
        );
        crate::runtime::blockchain_provider::set_global_blockchain(Arc::new(RwLock::new(bc)))
            .await
            .expect("set global blockchain");

        let err = resolve_pouw_client_identity(did, &mgr)
            .await
            .expect_err("created_at=0 must fail closed");
        assert!(
            err.contains("created_at unresolvable"),
            "expected created_at failure, got: {err}"
        );

        clear_global_blockchain().await;
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
