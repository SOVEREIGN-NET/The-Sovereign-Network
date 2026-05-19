//! Block processing for user credential transactions.

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::transaction::credentials::{AuthMethod, UserCredential};
use crate::types::transaction_type::TransactionType;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

/// S7 #2561: lifetime count of in-place argon2id → OPAQUE credential
/// upgrades observed by the executor. Exposed via
/// `lobby_auth_migrations_total()` for any metrics surface that wants it.
static LOBBY_AUTH_MIGRATIONS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Read the current count of completed lobby-auth migrations.
pub fn lobby_auth_migrations_total() -> u64 {
    LOBBY_AUTH_MIGRATIONS_TOTAL.load(Ordering::Relaxed)
}

impl Blockchain {
    /// Process RegisterCredential and UpdateCredentialPassword transactions in a block.
    pub fn process_credential_transactions(&mut self, block: &Block) {
        let block_height = block.height();
        let block_ts = block.header.timestamp;

        for tx in &block.transactions {
            match tx.transaction_type {
                TransactionType::RegisterCredential => {
                    if let crate::transaction::TransactionPayload::RegisterCredential(ref data) =
                        tx.payload
                    {
                        // Validate username format
                        if let Err(e) =
                            crate::transaction::credentials::validate_username(&data.username)
                        {
                            warn!(
                                "RegisterCredential rejected at height {}: {}",
                                block_height, e
                            );
                            continue;
                        }

                        // Check DID exists in identity registry. Done before
                        // the uniqueness gate so that upgrade and fresh-
                        // register paths share the same prereq.
                        if !self.identity_registry.contains_key(&data.owner_did) {
                            warn!(
                                "RegisterCredential rejected at height {}: DID {} not found in identity registry",
                                block_height, &data.owner_did[..20.min(data.owner_did.len())]
                            );
                            continue;
                        }

                        // S7 #2561: in-place upgrade path.
                        // If the username already exists, accept the tx ONLY
                        // when this is a legitimate Argon2idPhc → Opaque
                        // migration by the SAME owner. Anything else is
                        // rejected as a hijack / replay / downgrade attempt.
                        if let Some(existing) =
                            self.credential_registry.get(&data.username).cloned()
                        {
                            let is_upgrade = existing.auth_method == AuthMethod::Argon2idPhc
                                && data.auth_method == AuthMethod::Opaque
                                && existing.owner_did == data.owner_did
                                && !data.opaque_record.is_empty();

                            if !is_upgrade {
                                warn!(
                                    "RegisterCredential rejected at height {}: username '{}' \
                                     already taken (not an upgrade by owning DID)",
                                    block_height, data.username
                                );
                                continue;
                            }

                            // Apply upgrade in place. did_to_username already
                            // points at this username from the original
                            // registration — don't touch it.
                            let upgraded = UserCredential {
                                username: data.username.clone(),
                                owner_did: existing.owner_did.clone(),
                                // Clear the legacy argon2 hash — signin
                                // handler refuses Opaque-method creds anyway,
                                // but keeping the old hash around is dead
                                // weight at best and a leak vector at worst.
                                password_hash: String::new(),
                                registered_at_height: existing.registered_at_height,
                                registered_at: existing.registered_at,
                                password_changed_at_height: block_height,
                                opaque_record: data.opaque_record.clone(),
                                auth_method: AuthMethod::Opaque,
                            };
                            self.credential_registry
                                .insert(data.username.clone(), upgraded);

                            LOBBY_AUTH_MIGRATIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            info!(
                                "Lobby auth migrated: username '{}' (DID {}...) Argon2idPhc → Opaque at height {} \
                                 (total migrations: {})",
                                data.username,
                                &data.owner_did[..20.min(data.owner_did.len())],
                                block_height,
                                lobby_auth_migrations_total()
                            );
                            continue;
                        }

                        // Fresh registration path.
                        // Check DID doesn't already have credentials under a
                        // different username (one-credential-per-DID rule).
                        if self.did_to_username.contains_key(&data.owner_did) {
                            warn!(
                                "RegisterCredential rejected at height {}: DID {} already has credentials",
                                block_height, &data.owner_did[..20.min(data.owner_did.len())]
                            );
                            continue;
                        }

                        let credential = UserCredential {
                            username: data.username.clone(),
                            owner_did: data.owner_did.clone(),
                            password_hash: data.password_hash.clone(),
                            registered_at_height: block_height,
                            registered_at: block_ts,
                            password_changed_at_height: 0,
                            opaque_record: data.opaque_record.clone(),
                            auth_method: data.auth_method,
                        };

                        self.did_to_username
                            .insert(data.owner_did.clone(), data.username.clone());
                        self.credential_registry
                            .insert(data.username.clone(), credential);

                        // Unify: mirror the username into the identity's display_name
                        // so callers reading either field get the same value.
                        if let Some(id) = self.identity_registry.get_mut(&data.owner_did) {
                            id.display_name = data.username.clone();
                        }

                        info!(
                            "Credential registered: username '{}' for DID {}... at height {}",
                            data.username,
                            &data.owner_did[..20.min(data.owner_did.len())],
                            block_height
                        );
                    }
                }
                TransactionType::UpdateCredentialPassword => {
                    if let crate::transaction::TransactionPayload::UpdateCredentialPassword(
                        ref data,
                    ) = tx.payload
                    {
                        // Verify ownership
                        match self.credential_registry.get_mut(&data.username) {
                            Some(cred) if cred.owner_did == data.owner_did => {
                                cred.password_hash = data.new_password_hash.clone();
                                cred.password_changed_at_height = block_height;
                                info!(
                                    "Password updated for username '{}' at height {}",
                                    data.username, block_height
                                );
                            }
                            Some(_) => {
                                warn!(
                                    "UpdateCredentialPassword rejected: DID mismatch for '{}'",
                                    data.username
                                );
                            }
                            None => {
                                warn!(
                                    "UpdateCredentialPassword rejected: username '{}' not found",
                                    data.username
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
