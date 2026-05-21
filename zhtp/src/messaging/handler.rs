//! Messaging API handler.
//!
//! All endpoints require key-authenticated sessions (not password sessions).
//! All crypto happens client-side — the server relays opaque ciphertext.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use lib_blockchain::{Blockchain, BlockchainQuery};
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use super::deposit::DepositStore;
use super::presence::PresenceTracker;

pub struct MessagingHandler {
    blockchain: Arc<RwLock<Blockchain>>,
    deposits: Arc<DepositStore>,
    presence: Arc<PresenceTracker>,
}

// ── Request types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct SessionInitRequest {
    sender_did: String,
    recipient: String, // DID or @username
}

#[derive(Deserialize)]
struct SendRequest {
    /// Serialized MessageEnvelope bytes (hex-encoded)
    envelope_hex: String,
}

#[derive(Deserialize)]
struct DepositRequest {
    sender_did: String,
    recipient_did: String,
    /// List of serialized encrypted envelopes (hex-encoded)
    envelopes_hex: Vec<String>,
}

#[derive(Deserialize)]
struct PresenceWatchRequest {
    watcher_did: String,
    target_dids: Vec<String>,
}

// ── Handler ────────────────────────────────────────────────────────

fn json_response(data: serde_json::Value) -> Result<ZhtpResponse> {
    let body = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        body,
        "application/json".to_string(),
        None,
    ))
}

fn error_resp(status: ZhtpStatus, msg: &str) -> ZhtpResponse {
    ZhtpResponse::error(status, msg.to_string())
}

impl MessagingHandler {
    pub fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        deposits: Arc<DepositStore>,
        presence: Arc<PresenceTracker>,
    ) -> Self {
        Self {
            blockchain,
            deposits,
            presence,
        }
    }

    /// POST /api/v1/msg/session/init
    /// Returns the recipient's Kyber public key so the client can encapsulate.
    async fn handle_session_init(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: SessionInitRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let blockchain = self.blockchain.read().await;

        // Resolve recipient: @username, full DID, or raw hex identity ID
        let recipient_did = if req.recipient.starts_with('@') {
            let username = &req.recipient[1..];
            match blockchain.did_to_username().iter().find(|(_, u)| u.as_str() == username) {
                Some((did, _)) => did.clone(),
                None => return Ok(error_resp(ZhtpStatus::NotFound, "Username not found")),
            }
        } else if req.recipient.starts_with("did:zhtp:") {
            req.recipient.clone()
        } else {
            // Raw hex identity ID — add did:zhtp: prefix
            format!("did:zhtp:{}", req.recipient)
        };

        // Get recipient's identity (including Kyber key)
        let identity = match blockchain.query_identity(&recipient_did) {
            Some(id) => id.clone(),
            None => return Ok(error_resp(ZhtpStatus::NotFound, "Recipient DID not found")),
        };

        if identity.kyber_public_key.is_empty() {
            return Ok(error_resp(
                ZhtpStatus::BadRequest,
                "Recipient has no Kyber public key — cannot establish encrypted session",
            ));
        }

        // Get username if available
        let username = blockchain.did_to_username().get(&recipient_did).cloned();

        json_response(json!({
            "status": "success",
            "recipient_did": recipient_did,
            "recipient_username": username,
            "kyber_public_key": hex::encode(&identity.kyber_public_key),
            "dilithium_public_key": hex::encode(&identity.public_key),
        }))
    }

    /// POST /api/v1/msg/send
    /// Relay an encrypted envelope to the recipient via QUIC mesh.
    async fn handle_send(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: SendRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let envelope_bytes = hex::decode(&req.envelope_hex)
            .map_err(|_| anyhow::anyhow!("Invalid hex in envelope"))?;

        // Deserialize just enough to get the recipient DID
        let envelope: super::envelope::MessageEnvelope =
            bincode::deserialize(&envelope_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid envelope: {}", e))?;

        let recipient_did = envelope.recipient_did.clone();

        let messaging_provider =
            crate::runtime::messaging_provider::get_global_messaging_provider();

        // Check if recipient has a live inbound subscriber on this node — push it
        // straight onto the stream. Skips the deposit-then-poll round trip.
        if messaging_provider
            .try_push(&recipient_did, envelope_bytes.clone())
            .await
        {
            info!(
                "Message pushed to live subscriber for {}",
                &recipient_did[..16.min(recipient_did.len())]
            );
            return json_response(json!({
                "status": "delivered",
                "recipient_did": recipient_did,
            }));
        }

        // Always deposit locally — recipient may poll any node, or come online later
        let _ = self.deposits
            .deposit(&envelope.sender_did, &recipient_did, vec![envelope_bytes.clone()])
            .await;

        // Also relay via mesh so all nodes have the message
        if let Ok(mesh_router) = crate::runtime::mesh_router_provider::get_global_mesh_router().await {
            let quic_guard = mesh_router.quic_protocol.read().await;
            if let Some(ref qp) = *quic_guard {
                let mesh_msg = lib_network::types::mesh_message::ZhtpMeshMessage::MessageRelay {
                    recipient_did: recipient_did.clone(),
                    envelope: envelope_bytes,
                };
                let peer_ids = qp.connected_peer_ids();
                info!(
                    "msg/send: relaying to {} mesh peers for recipient {}",
                    peer_ids.len(),
                    recipient_did
                );
                for peer_id in &peer_ids {
                    match qp.send_to_peer(peer_id, mesh_msg.clone()).await {
                        Ok(_) => info!("  relay -> peer {} OK", hex::encode(&peer_id[..8.min(peer_id.len())])),
                        Err(e) => info!("  relay -> peer {} FAILED: {}", hex::encode(&peer_id[..8.min(peer_id.len())]), e),
                    }
                }
            } else {
                info!("msg/send: QUIC protocol not available — no mesh relay");
            }
        } else {
            info!("msg/send: mesh router unavailable — no mesh relay");
        }

        info!(
            "Message deposited + relayed for {}",
            &recipient_did[..16.min(recipient_did.len())]
        );
        json_response(json!({
            "status": "delivered",
            "recipient_did": recipient_did,
        }))
    }

    /// POST /api/v1/msg/deposit
    /// Deposit encrypted envelopes before sender disconnects.
    async fn handle_deposit(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: DepositRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let envelopes: Vec<Vec<u8>> = req
            .envelopes_hex
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect();

        if envelopes.is_empty() {
            return Ok(error_resp(ZhtpStatus::BadRequest, "No valid envelopes"));
        }

        match self
            .deposits
            .deposit(&req.sender_did, &req.recipient_did, envelopes)
            .await
        {
            Ok(count) => json_response(json!({
                "status": "deposited",
                "count": count,
                "ttl_hours": 48,
            })),
            Err(e) => Ok(error_resp(ZhtpStatus::BadRequest, &e)),
        }
    }

    /// GET /api/v1/msg/receive
    /// Poll for pending messages (deposits from other users).
    async fn handle_receive(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract recipient DID from authenticated session.
        // The requester identity hash may differ from the DID (key_id = blake3(dil||kyber)
        // vs DID = blake3(dil) only). Look up the canonical DID from the identity registry.
        let requester_key_id = request
            .requester
            .as_ref()
            .map(|id| hex::encode(&id.0))
            .unwrap_or_default();

        if requester_key_id.is_empty() {
            return Ok(error_resp(
                ZhtpStatus::Unauthorized,
                "Authenticated DID required",
            ));
        }

        // Try multiple DID derivations to find the canonical DID the deposit was keyed under.
        // QUIC identity_id = blake3(dilithium_pk || kyber_pk) — that's what request.requester.0 is.
        // Canonical DID = "did:zhtp:" + blake3(dilithium_pk) — that's what envelopes use.
        // The registry stores entries keyed by the canonical DID. To match the polling phone's
        // authenticated identity to the canonical DID, we scan the registry trying all
        // derivations (dil-only, dil||kyber). Genesis identities may have kyber_pk empty,
        // mobile-registered identities have a real kyber_pk.
        let key_id_did = format!("did:zhtp:{}", requester_key_id);
        let recipient_did = {
            let blockchain = self.blockchain.read().await;
            if blockchain.identity_registry().contains_key(&key_id_did) {
                key_id_did.clone()
            } else {
                blockchain
                    .identity_registry()
                    .iter()
                    .find(|(_, id)| {
                        if id.public_key.len() < 32 {
                            return false;
                        }
                        // Match against dilithium-only hash (canonical DID derivation).
                        let dil_hash = hex::encode(lib_crypto::hash_blake3(&id.public_key));
                        if dil_hash == requester_key_id {
                            return true;
                        }
                        // Match against dilithium||kyber hash (QUIC identity_id derivation).
                        if !id.kyber_public_key.is_empty() {
                            let combined =
                                [&id.public_key[..], &id.kyber_public_key[..]].concat();
                            let combined_hash =
                                hex::encode(lib_crypto::hash_blake3(&combined));
                            if combined_hash == requester_key_id {
                                return true;
                            }
                        }
                        false
                    })
                    .map(|(did, _)| did.clone())
                    .unwrap_or(key_id_did)
            }
        };

        info!(
            "msg/receive lookup: requester_key_id={} -> recipient_did={}",
            requester_key_id, recipient_did
        );

        // Mark as online
        self.presence.set_online(&recipient_did).await;

        // Collect pending deposits
        let deliveries = self.deposits.collect_for_recipient(&recipient_did).await;
        info!(
            "msg/receive collected {} deliveries for {}",
            deliveries.len(),
            recipient_did
        );

        let mut all_envelopes: Vec<serde_json::Value> = Vec::new();
        for delivery in &deliveries {
            for env_bytes in &delivery.envelopes {
                all_envelopes.push(json!({
                    "sender_did": delivery.sender_did,
                    "envelope_hex": hex::encode(env_bytes),
                    "deposited_at": delivery.deposited_at,
                }));
            }
        }

        json_response(json!({
            "status": "success",
            "count": all_envelopes.len(),
            "messages": all_envelopes,
        }))
    }

    /// GET /api/v1/msg/presence/watch
    /// Subscribe to presence changes for specific DIDs.
    async fn handle_presence_watch(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: PresenceWatchRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        for target in &req.target_dids {
            self.presence.watch(&req.watcher_did, target).await;
        }

        // Return current status of watched DIDs
        let mut statuses = Vec::new();
        for target in &req.target_dids {
            statuses.push(json!({
                "did": target,
                "online": self.presence.is_online(target).await,
            }));
        }

        json_response(json!({
            "status": "success",
            "watching": statuses,
        }))
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for MessagingHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Access zone gate: messaging requires key authentication
        if crate::session_manager::is_request_password_session(&request).await {
            return Ok(error_resp(
                ZhtpStatus::Forbidden,
                "Messaging requires key authentication",
            ));
        }

        let path = request.uri.split('?').next().unwrap_or("").trim_end_matches('/');

        match (&request.method, path) {
            (ZhtpMethod::Post, "/api/v1/msg/session/init") => {
                Ok(self.handle_session_init(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/msg/send") => {
                Ok(self.handle_send(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/msg/deposit") => {
                Ok(self.handle_deposit(&request).await?)
            }
            (ZhtpMethod::Get, "/api/v1/msg/receive") => {
                Ok(self.handle_receive(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/msg/presence/watch") => {
                Ok(self.handle_presence_watch(&request).await?)
            }
            _ => Ok(error_resp(ZhtpStatus::NotFound, "Not found")),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/msg/")
    }
}
