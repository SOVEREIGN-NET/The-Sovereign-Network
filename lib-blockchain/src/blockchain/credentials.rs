//! Block processing for user credential transactions.

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::transaction::credentials::UserCredential;
use crate::types::transaction_type::TransactionType;
use tracing::{info, warn};

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

                        // Check username uniqueness
                        if self.credential_registry.contains_key(&data.username) {
                            warn!(
                                "RegisterCredential rejected at height {}: username '{}' already taken",
                                block_height, data.username
                            );
                            continue;
                        }

                        // Check DID doesn't already have credentials
                        if self.did_to_username.contains_key(&data.owner_did) {
                            warn!(
                                "RegisterCredential rejected at height {}: DID {} already has credentials",
                                block_height, &data.owner_did[..20.min(data.owner_did.len())]
                            );
                            continue;
                        }

                        // Check DID exists in identity registry
                        if !self.identity_registry.contains_key(&data.owner_did) {
                            warn!(
                                "RegisterCredential rejected at height {}: DID {} not found in identity registry",
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
