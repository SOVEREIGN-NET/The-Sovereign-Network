//! Messaging API handler.
//!
//! All endpoints require key-authenticated sessions (not password sessions).
//! All crypto happens client-side — the server relays opaque ciphertext.

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use lib_blockchain::Blockchain;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use super::deposit::DepositStore;
use super::metrics::{metrics, redact_did};
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

#[derive(Deserialize)]
struct AckRequest {
    /// Message ids returned by receive / computed as hex(blake3(envelope)).
    message_ids: Vec<String>,
}

#[derive(Deserialize)]
struct CancelRequest {
    /// Recipient DID for undelivered mail to cancel (caller must be sender).
    recipient_did: String,
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

/// MSG-R9: when `ZHTP_MSG_VERIFY_ENVELOPES=1`, require a valid Dilithium
/// signature on the envelope against the sender's on-chain public key.
fn verify_envelopes_enabled() -> bool {
    matches!(
        std::env::var("ZHTP_MSG_VERIFY_ENVELOPES")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        true
    )
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
            match blockchain.did_to_username.iter().find(|(_, u)| u.as_str() == username) {
                Some((did, _)) => did.clone(),
                None => return Ok(error_resp(ZhtpStatus::NotFound, "Username not found")),
            }
        } else if req.recipient.starts_with("did:zhtp:") {
            req.recipient.clone()
        } else {
            // Raw hex identity ID — add did:zhtp: prefix
            format!("did:zhtp:{}", req.recipient)
        };

        let dilithium_public_key = match blockchain.identity_public_key(&recipient_did) {
            Some(pk) => pk,
            None => return Ok(error_resp(ZhtpStatus::NotFound, "Recipient DID not found")),
        };
        let kyber_public_key = match blockchain.identity_kyber_public_key(&recipient_did) {
            Some(k) => k,
            None => {
                return Ok(error_resp(
                    ZhtpStatus::BadRequest,
                    "Recipient has no Kyber public key — cannot establish encrypted session",
                ))
            }
        };

        let username = blockchain.did_to_username.get(&recipient_did).cloned();

        json_response(json!({
            "status": "success",
            "recipient_did": recipient_did,
            "recipient_username": username,
            "kyber_public_key": hex::encode(&kyber_public_key),
            "dilithium_public_key": hex::encode(&dilithium_public_key),
        }))
    }

    /// MSG-R8: authenticated caller DID must match claimed sender.
    async fn bind_sender(
        &self,
        request: &ZhtpRequest,
        claimed_sender: &str,
    ) -> Result<String, String> {
        let caller = self.resolve_caller_did(request).await?;
        if caller != claimed_sender {
            metrics().auth_rejects.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "sender_did does not match authenticated session (claimed {}, session {})",
                redact_did(claimed_sender),
                redact_did(&caller)
            ));
        }
        Ok(caller)
    }

    /// MSG-R9: optional Dilithium envelope verify against on-chain sender key.
    async fn maybe_verify_envelope(
        &self,
        envelope: &super::envelope::MessageEnvelope,
    ) -> Result<(), String> {
        if !verify_envelopes_enabled() {
            return Ok(());
        }
        if envelope.signature.is_empty() {
            metrics().verify_rejects.fetch_add(1, Ordering::Relaxed);
            return Err("envelope signature required (ZHTP_MSG_VERIFY_ENVELOPES)".to_string());
        }
        let blockchain = self.blockchain.read().await;
        let pk = blockchain
            .identity_public_key(&envelope.sender_did)
            .ok_or_else(|| {
                metrics().verify_rejects.fetch_add(1, Ordering::Relaxed);
                format!(
                    "sender DID not registered: {}",
                    redact_did(&envelope.sender_did)
                )
            })?;
        match envelope.verify_signature(&pk) {
            Ok(true) => Ok(()),
            Ok(false) => {
                metrics().verify_rejects.fetch_add(1, Ordering::Relaxed);
                Err("envelope signature invalid".to_string())
            }
            Err(e) => {
                metrics().verify_rejects.fetch_add(1, Ordering::Relaxed);
                Err(format!("envelope signature verify error: {e}"))
            }
        }
    }

    /// POST /api/v1/msg/send
    /// Deposit (always) then optionally push to a live inbound subscriber.
    /// Status is honest: `queued` (stored only) or `pushed` (stored + live).
    async fn handle_send(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: SendRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let envelope_bytes = hex::decode(&req.envelope_hex)
            .map_err(|_| anyhow::anyhow!("Invalid hex in envelope"))?;

        let envelope: super::envelope::MessageEnvelope =
            bincode::deserialize(&envelope_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid envelope: {}", e))?;

        // MSG-R8: bind sender to session
        if let Err(e) = self.bind_sender(request, &envelope.sender_did).await {
            return Ok(error_resp(ZhtpStatus::Forbidden, &e));
        }

        if let Err(e) = self.maybe_verify_envelope(&envelope).await {
            return Ok(error_resp(ZhtpStatus::BadRequest, &e));
        }

        let recipient_did = envelope.recipient_did.clone();
        let message_id = super::deposit::message_id_for_envelope(&envelope_bytes);

        if let Err(e) = self.deposits.deposit_one(
            &envelope.sender_did,
            &recipient_did,
            envelope_bytes.clone(),
        ) {
            warn!(
                error = %e,
                message_id = %message_id,
                "msg/send: local deposit failed — continuing mesh relay"
            );
        }

        let messaging_provider =
            crate::runtime::messaging_provider::get_global_messaging_provider();

        let pushed = messaging_provider
            .try_push(&recipient_did, envelope_bytes.clone())
            .await;
        if pushed {
            metrics().live_pushes.fetch_add(1, Ordering::Relaxed);
        }

        // MSG-R14: presence-directed mesh — skip flood when recipient is
        // online on this node (live subscriber or presence tracker).
        let local_online = pushed
            || self.presence.is_online(&recipient_did).await
            || messaging_provider.has_subscriber(&recipient_did).await;

        if !local_online {
            self.mesh_relay(&recipient_did, envelope_bytes).await;
        } else {
            info!(
                message_id = %message_id,
                recipient = %redact_did(&recipient_did),
                "msg/send: recipient local — skipping mesh flood"
            );
        }

        let status = if pushed { "pushed" } else { "queued" };
        info!(
            message_id = %message_id,
            status,
            recipient = %redact_did(&recipient_did),
            "msg/send"
        );
        json_response(json!({
            "status": status,
            "message_id": message_id,
            "recipient_did": recipient_did,
        }))
    }

    async fn mesh_relay(&self, recipient_did: &str, envelope_bytes: Vec<u8>) {
        if let Ok(mesh_router) =
            crate::runtime::mesh_router_provider::get_global_mesh_router().await
        {
            let quic_guard = mesh_router.quic_protocol.read().await;
            if let Some(ref qp) = *quic_guard {
                let mesh_msg = lib_network::types::mesh_message::ZhtpMeshMessage::MessageRelay {
                    recipient_did: recipient_did.to_string(),
                    envelope: envelope_bytes,
                };
                let peer_ids = qp.connected_peer_ids();
                info!(
                    peers = peer_ids.len(),
                    recipient = %redact_did(recipient_did),
                    "msg/send: mesh relay"
                );
                for peer_id in &peer_ids {
                    match qp.send_to_peer(peer_id, mesh_msg.clone()).await {
                        Ok(_) => {
                            metrics().mesh_relays_out.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => warn!(
                            peer = %hex::encode(&peer_id[..8.min(peer_id.len())]),
                            error = %e,
                            "mesh relay failed"
                        ),
                    }
                }
            } else {
                info!("msg/send: QUIC protocol not available — no mesh relay");
            }
        } else {
            info!("msg/send: mesh router unavailable — no mesh relay");
        }
    }

    /// POST /api/v1/msg/deposit
    /// Deposit encrypted envelopes before sender disconnects.
    async fn handle_deposit(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: DepositRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        if let Err(e) = self.bind_sender(request, &req.sender_did).await {
            return Ok(error_resp(ZhtpStatus::Forbidden, &e));
        }

        let envelopes: Vec<Vec<u8>> = req
            .envelopes_hex
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect();

        if envelopes.is_empty() {
            return Ok(error_resp(ZhtpStatus::BadRequest, "No valid envelopes"));
        }

        // MSG-R8: every envelope's embedded sender must match the deposit sender
        // (session-bound above). Optional Dilithium verify when env is set.
        for env_bytes in &envelopes {
            let envelope: super::envelope::MessageEnvelope = match bincode::deserialize(env_bytes)
            {
                Ok(e) => e,
                Err(e) => {
                    return Ok(error_resp(
                        ZhtpStatus::BadRequest,
                        &format!("Invalid envelope: {e}"),
                    ));
                }
            };
            if envelope.sender_did != req.sender_did {
                metrics().auth_rejects.fetch_add(1, Ordering::Relaxed);
                return Ok(error_resp(
                    ZhtpStatus::Forbidden,
                    "envelope sender_did does not match deposit sender_did",
                ));
            }
            if let Err(e) = self.maybe_verify_envelope(&envelope).await {
                return Ok(error_resp(ZhtpStatus::BadRequest, &e));
            }
        }

        match self
            .deposits
            .deposit(&req.sender_did, &req.recipient_did, envelopes)
        {
            Ok((count, message_ids)) => json_response(json!({
                "status": "deposited",
                "count": count,
                "message_ids": message_ids,
                "ttl_hours": 48,
            })),
            Err(e) => Ok(error_resp(ZhtpStatus::BadRequest, &e)),
        }
    }

    /// Resolve authenticated requester → canonical DID (shared with inbound / receive).
    async fn resolve_caller_did(&self, request: &ZhtpRequest) -> Result<String, String> {
        let blockchain = self.blockchain.read().await;
        super::did_resolve::resolve_recipient_did_from_request(request, &blockchain).await
    }

    /// POST /api/v1/msg/ack
    /// Client confirms receipt; removes only envelopes addressed to the caller.
    async fn handle_ack(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: AckRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        if req.message_ids.is_empty() {
            return Ok(error_resp(ZhtpStatus::BadRequest, "message_ids required"));
        }

        let recipient_did = match self.resolve_caller_did(request).await {
            Ok(d) => d,
            Err(e) => return Ok(error_resp(ZhtpStatus::Unauthorized, &e)),
        };

        let removed = self.deposits.ack(&recipient_did, &req.message_ids);
        json_response(json!({
            "status": "success",
            "acked": removed,
        }))
    }

    /// POST /api/v1/msg/cancel (MSG-R11)
    /// Sender cancels undelivered mail to a recipient on this node.
    async fn handle_cancel(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: CancelRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let sender_did = match self.resolve_caller_did(request).await {
            Ok(d) => d,
            Err(e) => return Ok(error_resp(ZhtpStatus::Unauthorized, &e)),
        };

        if req.recipient_did.is_empty() {
            return Ok(error_resp(ZhtpStatus::BadRequest, "recipient_did required"));
        }

        let cancelled = self.deposits.cancel(&sender_did, &req.recipient_did);
        json_response(json!({
            "status": "success",
            "cancelled": cancelled,
            "sender_did": sender_did,
            "recipient_did": req.recipient_did,
        }))
    }

    /// GET /api/v1/msg/receive
    /// Peek pending messages (does not remove — client must POST /api/v1/msg/ack).
    async fn handle_receive(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let recipient_did = match self.resolve_caller_did(request).await {
            Ok(d) => d,
            Err(e) => return Ok(error_resp(ZhtpStatus::Unauthorized, &e)),
        };

        info!(
            recipient = %redact_did(&recipient_did),
            "msg/receive lookup"
        );

        self.presence.set_online(&recipient_did).await;

        let deliveries = self.deposits.peek_for_recipient(&recipient_did);
        info!(
            count = deliveries.len(),
            recipient = %redact_did(&recipient_did),
            "msg/receive peeked"
        );

        let all_envelopes: Vec<serde_json::Value> = deliveries
            .iter()
            .map(|d| {
                json!({
                    "message_id": d.message_id,
                    "sender_did": d.sender_did,
                    "envelope_hex": hex::encode(&d.envelope),
                    "deposited_at": d.deposited_at,
                })
            })
            .collect();

        json_response(json!({
            "status": "success",
            "count": all_envelopes.len(),
            "messages": all_envelopes,
        }))
    }

    /// POST /api/v1/msg/presence/watch
    async fn handle_presence_watch(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: PresenceWatchRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Bind watcher to session when possible
        if let Ok(caller) = self.resolve_caller_did(request).await {
            if caller != req.watcher_did {
                metrics().auth_rejects.fetch_add(1, Ordering::Relaxed);
                return Ok(error_resp(
                    ZhtpStatus::Forbidden,
                    "watcher_did does not match authenticated session",
                ));
            }
        }

        for target in &req.target_dids {
            self.presence.watch(&req.watcher_did, target).await;
        }

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

    /// GET /api/v1/msg/stats (MSG-R12) — operator queue depth + counters.
    async fn handle_stats(&self, _request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let mut snap = metrics().snapshot();
        snap.pending = self.deposits.total_pending() as u64;
        json_response(json!({
            "status": "success",
            "metrics": snap,
            "at_rest_encryption": self.deposits.at_rest_enabled(),
            "envelope_verify": verify_envelopes_enabled(),
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
            (ZhtpMethod::Post, "/api/v1/msg/ack") => {
                Ok(self.handle_ack(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/msg/cancel") => {
                Ok(self.handle_cancel(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/msg/presence/watch") => {
                Ok(self.handle_presence_watch(&request).await?)
            }
            (ZhtpMethod::Get, "/api/v1/msg/stats") => {
                Ok(self.handle_stats(&request).await?)
            }
            _ => Ok(error_resp(ZhtpStatus::NotFound, "Not found")),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/msg/")
    }
}
