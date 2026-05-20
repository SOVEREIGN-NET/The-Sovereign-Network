//! Observer admission HTTP/JSON-RPC handlers (observer-admission-6).
//!
//! Provides REST endpoints under `/api/v1/observer/admission/...` that
//! build & submit canonical observer admission transactions and read
//! canonical state.
//!
//! # Endpoint contract
//!
//! These handlers **never** mutate authorization state directly. They
//! construct typed [`lib_blockchain::transaction::Transaction`] values
//! and submit them to the mempool. All authorization decisions are made
//! by the executor (admission-4) when the block containing the tx is
//! applied. The handler only:
//!   - parses the request body
//!   - validates structural shape (400 on failure)
//!   - reconstructs the caller-supplied transaction signature
//!   - builds the typed transaction
//!   - submits to the mempool (500 on transport failure)
//!
//! Read endpoints (`status`, `by-sponsor`) consult the canonical
//! [`BlockchainStore`] via the global blockchain provider.
//!
//! # Error model
//!
//! - `400 BadRequest`     — malformed JSON, missing fields, invalid base64, etc.
//! - `403 Forbidden`      — request well-formed but caller is not allowed
//!                          (e.g. blockchain provider not initialized).
//! - `500 InternalServer` — transport / mempool / store I/O failure.
//!
//! # Anti-replay challenge
//!
//! [`handle_admission_challenge`] returns a freshly generated
//! [`ObserverAdmissionChallengeRef`]. v1 issues challenges
//! statelessly — server-side persistence and one-shot enforcement are
//! deferred to admission-8.

use lib_blockchain::storage::did_to_hash;
use lib_blockchain::transaction::{
    RegisterObserverData, ReauthorizeObserverData, RevokeObserverData, SuspendObserverData,
    Transaction, UpdateObserverMetadataData,
};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use lib_types::{
    ObserverAdmissionChallengeRef, ObserverAdmissionPolicy, ObserverAdmissionRecord,
    ObserverProofLevel, ObserverRateLimitTier,
};
use serde::{Deserialize, Serialize};

const CONTENT_TYPE_JSON: &str = "application/json";
const CHALLENGE_TTL_SECS: u64 = 300; // 5 minutes

// =============================================================================
// REQUEST / RESPONSE DTOs
// =============================================================================

/// Common signature envelope for transaction-submitting endpoints.
///
/// Caller pre-signs the transaction body; the handler only reconstructs
/// the [`lib_crypto::Signature`] from these fields.
#[derive(Debug, Deserialize)]
pub struct TxSignatureEnvelope {
    /// Raw signature bytes.
    pub signature_bytes: Vec<u8>,
    /// Signer's Dilithium5 public key (2592 bytes).
    pub signer_dilithium_pk: Vec<u8>,
    /// Optional Kyber public key (1568 bytes). Defaults to zeros.
    #[serde(default)]
    pub signer_kyber_pk: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdmissionChallengeRequest {
    /// DID of the observer node requesting admission.
    pub observer_node_did: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdmissionChallengeResponse {
    pub status: String,
    pub challenge: ObserverAdmissionChallengeRef,
}

#[derive(Debug, Deserialize)]
pub struct RegisterObserverRequest {
    pub observer_node_did: String,
    pub observer_public_key: Vec<u8>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub sponsor_user_did: String,
    pub sponsor_proof_level: ObserverProofLevel,
    pub sponsor_signature: Vec<u8>,
    pub allowed_network: String,
    #[serde(default)]
    pub trusted_sync_scope: Option<String>,
    pub rate_limit_tier: ObserverRateLimitTier,
    #[serde(default)]
    pub expires_at: Option<u64>,
    pub nonce: u64,
    pub tx_signature: TxSignatureEnvelope,
}

#[derive(Debug, Deserialize)]
pub struct UpdateObserverRequest {
    pub observer_node_did: String,
    pub actor_did: String,
    #[serde(default)]
    pub new_endpoints: Vec<String>,
    #[serde(default)]
    pub new_allowed_network: Option<String>,
    #[serde(default)]
    pub new_trusted_sync_scope: Option<String>,
    #[serde(default)]
    pub new_rate_limit_tier: Option<ObserverRateLimitTier>,
    #[serde(default)]
    pub new_expires_at: Option<Option<u64>>,
    pub nonce: u64,
    pub tx_signature: TxSignatureEnvelope,
}

#[derive(Debug, Deserialize)]
pub struct SuspendObserverRequest {
    pub observer_node_did: String,
    pub actor_did: String,
    pub reason: String,
    pub nonce: u64,
    pub tx_signature: TxSignatureEnvelope,
}

#[derive(Debug, Deserialize)]
pub struct RevokeObserverRequest {
    pub observer_node_did: String,
    pub actor_did: String,
    pub reason: String,
    pub nonce: u64,
    pub tx_signature: TxSignatureEnvelope,
}

#[derive(Debug, Deserialize)]
pub struct ReauthorizeObserverRequest {
    pub observer_node_did: String,
    pub sponsor_user_did: String,
    pub nonce: u64,
    pub tx_signature: TxSignatureEnvelope,
}

/// Request body for `POST /api/v1/observer/admission/prepare`.
///
/// All hex strings use lowercase hex without a `0x` prefix.
#[derive(Debug, Deserialize)]
pub struct PrepareObserverRequest {
    pub observer_node_did: String,
    /// Hex-encoded Dilithium5 public key of the observer node (2592 bytes).
    pub observer_dilithium_pk_hex: String,
    /// Hex-encoded Kyber1024 public key of the observer node (1568 bytes).
    /// Pass an empty string or omit to use an all-zero placeholder.
    #[serde(default)]
    pub observer_kyber_pk_hex: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub sponsor_user_did: String,
    pub sponsor_proof_level: ObserverProofLevel,
    pub allowed_network: String,
    #[serde(default)]
    pub trusted_sync_scope: Option<String>,
    pub rate_limit_tier: ObserverRateLimitTier,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// Response body for `POST /api/v1/observer/admission/prepare`.
#[derive(Debug, Serialize)]
pub struct PrepareObserverResponse {
    /// Hex-encoded 32-byte blake3 hash that the sponsor must sign with their
    /// Dilithium5 private key. Pass the resulting signature bytes as
    /// `tx_signature.signature_bytes` in the subsequent `/admission/register`
    /// call, using the same `nonce` field that appears in this response.
    pub tx_canonical_bytes_hex: String,
    /// The nonce value that must appear in the `/admission/register` request.
    /// This is the sponsor's current SOV nonce; the executor expects this
    /// exact value and increments it to `sponsor_next_nonce` on success.
    pub nonce: u64,
    /// The sponsor's SOV nonce after this transaction is applied (= nonce + 1).
    pub sponsor_next_nonce: u64,
    pub chain_id: u8,
}

#[derive(Debug, Serialize)]
pub struct TxSubmissionResponse {
    pub status: String,
    pub transaction_hash: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ObserverStatusResponse {
    pub status: String,
    pub record: Option<ObserverAdmissionRecord>,
}

#[derive(Debug, Serialize)]
pub struct ObserverBySponsorResponse {
    pub status: String,
    pub records: Vec<ObserverAdmissionRecord>,
}

// =============================================================================
// HELPERS
// =============================================================================

fn bad_request(msg: impl Into<String>) -> ZhtpResponse {
    ZhtpResponse::error(ZhtpStatus::BadRequest, msg.into())
}

fn forbidden(msg: impl Into<String>) -> ZhtpResponse {
    ZhtpResponse::error(ZhtpStatus::Forbidden, msg.into())
}

fn server_error(msg: impl Into<String>) -> ZhtpResponse {
    ZhtpResponse::error(ZhtpStatus::InternalServerError, msg.into())
}

fn json_ok<T: Serialize>(value: &T) -> ZhtpResult<ZhtpResponse> {
    let body = serde_json::to_vec(value)
        .map_err(|e| anyhow::anyhow!("JSON serialization failed: {}", e))?;
    Ok(ZhtpResponse::success_with_content_type(
        body,
        CONTENT_TYPE_JSON.to_string(),
        None,
    ))
}

/// Parse a `?did=...` query parameter from the request URI.
fn parse_did_query(uri: &str) -> Option<String> {
    let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in query.split('&') {
        if let Some(("did", value)) = pair.split_once('=') {
            return urlencoding::decode(value).ok().map(|c| c.into_owned());
        }
    }
    None
}

/// Reconstruct a `lib_crypto::Signature` from the envelope.
fn reconstruct_signature(env: &TxSignatureEnvelope) -> Result<lib_crypto::Signature, String> {
    if env.signer_dilithium_pk.len() != 2592 {
        return Err(format!(
            "signer_dilithium_pk must be 2592 bytes, got {}",
            env.signer_dilithium_pk.len()
        ));
    }
    let mut dilithium_pk = [0u8; 2592];
    dilithium_pk.copy_from_slice(&env.signer_dilithium_pk);

    let kyber_pk = match &env.signer_kyber_pk {
        Some(k) if k.len() == 1568 => {
            let mut buf = [0u8; 1568];
            buf.copy_from_slice(k);
            buf
        }
        Some(k) => {
            return Err(format!(
                "signer_kyber_pk must be 1568 bytes, got {}",
                k.len()
            ))
        }
        None => [0u8; 1568],
    };

    let public_key = lib_crypto::PublicKey {
        dilithium_pk,
        kyber_pk,
        key_id: lib_crypto::hash_blake3(&dilithium_pk),
    };

    Ok(lib_crypto::Signature {
        signature: env.signature_bytes.clone(),
        public_key,
        algorithm: lib_crypto::SignatureAlgorithm::DEFAULT,
        timestamp: now_secs(),
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Submit a fully-built transaction to the mempool via the global
/// blockchain provider.
///
/// Maps:
///   - provider not initialized → 403 Forbidden (canonical: caller cannot
///     submit because the local node is not running a blockchain).
///   - mempool rejection → 500 (transport-style failure; the canonical
///     authorization decision happens at block apply time).
async fn submit_transaction(tx: Transaction) -> ZhtpResult<ZhtpResponse> {
    let tx_hash = tx.hash();
    let blockchain_arc =
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                return Ok(forbidden(format!(
                    "blockchain provider unavailable: {e}"
                )));
            }
        };
    let mut blockchain = blockchain_arc.write().await;
    match blockchain.add_pending_transaction(tx) {
        Ok(()) => json_ok(&TxSubmissionResponse {
            status: "submitted".to_string(),
            transaction_hash: tx_hash.to_string(),
            message: "Observer admission transaction added to mempool".to_string(),
        }),
        Err(e) => Ok(server_error(format!("mempool rejected transaction: {e}"))),
    }
}

/// Resolve the local `chain_id` from the runtime config.
fn chain_id_from_runtime(runtime: &crate::runtime::RuntimeOrchestrator) -> u8 {
    runtime.config().environment.chain_id()
}

/// Resolve the canonical observer admission policy for pre-validation
/// (observer-admission-8). Reads from the runtime store; falls back to
/// `default_policy()` when no policy is persisted yet.
fn resolve_admission_policy(_runtime: &crate::runtime::RuntimeOrchestrator) -> ObserverAdmissionPolicy {
    // CONS-505 / admission-8 post-merge: store path removed; falling back
    // to default_policy until the runtime exposes a stable store handle.
    lib_blockchain::observer::default_policy()
}

/// Reject a register payload before it reaches the mempool when the
/// declared sponsor proof level cannot satisfy policy
/// (observer-admission-8). Returns `Some(403 response)` if rejected.
fn pre_validate_register_proof_level(
    sponsor_proof_level: ObserverProofLevel,
    policy: &ObserverAdmissionPolicy,
) -> Option<ZhtpResponse> {
    if sponsor_proof_level == ObserverProofLevel::None {
        return Some(forbidden(
            "anonymous sponsors (proof_level=None) cannot enroll observers",
        ));
    }
    if sponsor_proof_level < policy.minimum_proof_level {
        return Some(forbidden(format!(
            "sponsor proof level {:?} is below the network minimum {:?}",
            sponsor_proof_level, policy.minimum_proof_level
        )));
    }
    None
}

// =============================================================================
// HANDLERS
// =============================================================================

/// `POST /api/v1/observer/admission/challenge` — issue a fresh challenge.
pub async fn handle_admission_challenge(request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
    let req: AdmissionChallengeRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => return Ok(bad_request(format!("invalid challenge request: {e}"))),
    };
    if req.observer_node_did.trim().is_empty() {
        return Ok(bad_request("observer_node_did is required"));
    }

    let now = now_secs();
    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let challenge_id = hex::encode(lib_crypto::hash_blake3(&nonce));

    let challenge = ObserverAdmissionChallengeRef {
        challenge_id,
        challenge_nonce: nonce.to_vec(),
        expires_at: now.saturating_add(CHALLENGE_TTL_SECS),
    };
    json_ok(&AdmissionChallengeResponse {
        status: "issued".to_string(),
        challenge,
    })
}

/// `POST /api/v1/observer/admission/register` — submit `RegisterObserver`.
///
/// `policy` is the canonical [`ObserverAdmissionPolicy`] used for the
/// pre-validation gate (observer-admission-8). The dispatcher resolves
/// it from the runtime store; tests pass [`lib_blockchain::observer::default_policy`].
pub async fn handle_admission_register(
    request: ZhtpRequest,
    chain_id: u8,
    policy: &ObserverAdmissionPolicy,
) -> ZhtpResult<ZhtpResponse> {
    let req: RegisterObserverRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => return Ok(bad_request(format!("invalid register request: {e}"))),
    };
    if req.observer_node_did.trim().is_empty() {
        return Ok(bad_request("observer_node_did is required"));
    }
    if req.sponsor_user_did.trim().is_empty() {
        return Ok(bad_request("sponsor_user_did is required"));
    }
    if req.allowed_network.trim().is_empty() {
        return Ok(bad_request("allowed_network is required"));
    }
    if req.observer_public_key.is_empty() {
        return Ok(bad_request("observer_public_key is required"));
    }

    // Anti-abuse pre-validation (observer-admission-8): never relay an
    // enrollment that the canonical policy would deny on apply.
    if let Some(resp) = pre_validate_register_proof_level(req.sponsor_proof_level, policy) {
        return Ok(resp);
    }

    let signature = match reconstruct_signature(&req.tx_signature) {
        Ok(s) => s,
        Err(e) => return Ok(bad_request(e)),
    };

    let data = RegisterObserverData {
        observer_node_did: req.observer_node_did,
        observer_public_key: req.observer_public_key,
        endpoints: req.endpoints,
        sponsor_user_did: req.sponsor_user_did,
        sponsor_proof_level: req.sponsor_proof_level,
        sponsor_signature: req.sponsor_signature,
        allowed_network: req.allowed_network,
        trusted_sync_scope: req.trusted_sync_scope,
        rate_limit_tier: req.rate_limit_tier,
        expires_at: req.expires_at,
        nonce: req.nonce,
    };
    let tx = Transaction::new_register_observer(chain_id, data, signature);
    submit_transaction(tx).await
}

/// `POST /api/v1/observer/admission/update` — submit `UpdateObserverMetadata`.
pub async fn handle_admission_update(
    request: ZhtpRequest,
    chain_id: u8,
) -> ZhtpResult<ZhtpResponse> {
    let req: UpdateObserverRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => return Ok(bad_request(format!("invalid update request: {e}"))),
    };
    if req.observer_node_did.trim().is_empty() {
        return Ok(bad_request("observer_node_did is required"));
    }
    if req.actor_did.trim().is_empty() {
        return Ok(bad_request("actor_did is required"));
    }

    let signature = match reconstruct_signature(&req.tx_signature) {
        Ok(s) => s,
        Err(e) => return Ok(bad_request(e)),
    };

    let new_network = req.new_allowed_network.map(|allowed_network| {
        lib_blockchain::transaction::ObserverNetworkUpdate {
            allowed_network,
            trusted_sync_scope: req.new_trusted_sync_scope,
        }
    });

    let data = UpdateObserverMetadataData {
        observer_node_did: req.observer_node_did,
        actor_did: req.actor_did,
        new_endpoints: if req.new_endpoints.is_empty() { None } else { Some(req.new_endpoints) },
        new_network,
        new_rate_limit_tier: req.new_rate_limit_tier,
        new_expires_at: req.new_expires_at,
        nonce: req.nonce,
    };
    let tx = Transaction::new_update_observer_metadata(chain_id, data, signature);
    submit_transaction(tx).await
}

/// `POST /api/v1/observer/admission/suspend` — submit `SuspendObserver`.
pub async fn handle_admission_suspend(
    request: ZhtpRequest,
    chain_id: u8,
) -> ZhtpResult<ZhtpResponse> {
    let req: SuspendObserverRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => return Ok(bad_request(format!("invalid suspend request: {e}"))),
    };
    if req.observer_node_did.trim().is_empty() || req.actor_did.trim().is_empty() {
        return Ok(bad_request("observer_node_did and actor_did are required"));
    }

    let signature = match reconstruct_signature(&req.tx_signature) {
        Ok(s) => s,
        Err(e) => return Ok(bad_request(e)),
    };

    let data = SuspendObserverData {
        observer_node_did: req.observer_node_did,
        actor_did: req.actor_did,
        reason: req.reason,
        nonce: req.nonce,
    };
    let tx = Transaction::new_suspend_observer(chain_id, data, signature);
    submit_transaction(tx).await
}

/// `POST /api/v1/observer/admission/revoke` — submit `RevokeObserver`.
pub async fn handle_admission_revoke(
    request: ZhtpRequest,
    chain_id: u8,
) -> ZhtpResult<ZhtpResponse> {
    let req: RevokeObserverRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => return Ok(bad_request(format!("invalid revoke request: {e}"))),
    };
    if req.observer_node_did.trim().is_empty() || req.actor_did.trim().is_empty() {
        return Ok(bad_request("observer_node_did and actor_did are required"));
    }

    let signature = match reconstruct_signature(&req.tx_signature) {
        Ok(s) => s,
        Err(e) => return Ok(bad_request(e)),
    };

    let data = RevokeObserverData {
        observer_node_did: req.observer_node_did,
        actor_did: req.actor_did,
        reason: req.reason,
        nonce: req.nonce,
    };
    let tx = Transaction::new_revoke_observer(chain_id, data, signature);
    submit_transaction(tx).await
}

/// `POST /api/v1/observer/admission/reauthorize` — submit `ReauthorizeObserver`.
pub async fn handle_admission_reauthorize(
    request: ZhtpRequest,
    chain_id: u8,
) -> ZhtpResult<ZhtpResponse> {
    let req: ReauthorizeObserverRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => return Ok(bad_request(format!("invalid reauthorize request: {e}"))),
    };
    if req.observer_node_did.trim().is_empty() || req.sponsor_user_did.trim().is_empty() {
        return Ok(bad_request(
            "observer_node_did and sponsor_user_did are required",
        ));
    }

    let signature = match reconstruct_signature(&req.tx_signature) {
        Ok(s) => s,
        Err(e) => return Ok(bad_request(e)),
    };

    let data = ReauthorizeObserverData {
        observer_node_did: req.observer_node_did,
        sponsor_user_did: req.sponsor_user_did,
        nonce: req.nonce,
    };
    let tx = Transaction::new_reauthorize_observer(chain_id, data, signature);
    submit_transaction(tx).await
}

/// `GET /api/v1/observer/admission/status?did=...` — read a record.
pub async fn handle_admission_status(request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
    let did = match parse_did_query(&request.uri) {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(bad_request("missing required query parameter: did")),
    };
    let did_hash = did_to_hash(&did);

    let blockchain_arc =
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => bc,
            Err(e) => return Ok(forbidden(format!("blockchain provider unavailable: {e}"))),
        };
    let blockchain = blockchain_arc.read().await;
    let store = match blockchain.store.as_ref() {
        Some(s) => s.clone(),
        None => return Ok(server_error("blockchain has no persistent store")),
    };
    drop(blockchain);

    match store.get_observer_record(&did_hash) {
        Ok(record) => json_ok(&ObserverStatusResponse {
            status: "ok".to_string(),
            record,
        }),
        Err(e) => Ok(server_error(format!("store error: {e}"))),
    }
}

/// `GET /api/v1/observer/admission/by-sponsor?did=...` — list sponsor's observers.
pub async fn handle_admission_by_sponsor(request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
    let did = match parse_did_query(&request.uri) {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(bad_request("missing required query parameter: did")),
    };
    let sponsor_hash = did_to_hash(&did);

    let blockchain_arc =
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => bc,
            Err(e) => return Ok(forbidden(format!("blockchain provider unavailable: {e}"))),
        };
    let blockchain = blockchain_arc.read().await;
    let store = match blockchain.store.as_ref() {
        Some(s) => s.clone(),
        None => return Ok(server_error("blockchain has no persistent store")),
    };
    drop(blockchain);

    match store.iter_observer_records_for_sponsor(&sponsor_hash) {
        Ok(records) => json_ok(&ObserverBySponsorResponse {
            status: "ok".to_string(),
            records,
        }),
        Err(e) => Ok(server_error(format!("store error: {e}"))),
    }
}

/// `POST /api/v1/observer/admission/prepare` — build canonical signing bytes.
///
/// Called by the mobile app after scanning the sponsor QR code. Returns the
/// 32-byte blake3 signing hash (hex-encoded) that the sponsor must sign with
/// their Dilithium5 key. The returned `nonce` must be echoed verbatim in the
/// subsequent `/admission/register` call.
///
/// Returns 403 when the sponsor DID has no on-chain identity record.
pub async fn handle_admission_prepare(
    request: ZhtpRequest,
    chain_id: u8,
) -> ZhtpResult<ZhtpResponse> {
    let req: PrepareObserverRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => return Ok(bad_request(format!("invalid prepare request: {e}"))),
    };

    if req.observer_node_did.trim().is_empty() {
        return Ok(bad_request("observer_node_did is required"));
    }
    if req.sponsor_user_did.trim().is_empty() {
        return Ok(bad_request("sponsor_user_did is required"));
    }
    if req.allowed_network.trim().is_empty() {
        return Ok(bad_request("allowed_network is required"));
    }
    if req.observer_dilithium_pk_hex.trim().is_empty() {
        return Ok(bad_request("observer_dilithium_pk_hex is required"));
    }

    let observer_dilithium_pk = match hex::decode(&req.observer_dilithium_pk_hex) {
        Ok(b) => b,
        Err(_) => return Ok(bad_request("observer_dilithium_pk_hex is not valid hex")),
    };

    if !req.observer_kyber_pk_hex.trim().is_empty() {
        if hex::decode(&req.observer_kyber_pk_hex).is_err() {
            return Ok(bad_request("observer_kyber_pk_hex is not valid hex"));
        }
    }

    let blockchain_arc =
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                return Ok(forbidden(format!(
                    "blockchain provider unavailable: {e}"
                )));
            }
        };
    let blockchain = blockchain_arc.read().await;
    let store = match blockchain.store.as_ref() {
        Some(s) => s.clone(),
        None => return Ok(server_error("blockchain has no persistent store")),
    };
    drop(blockchain);

    let sponsor_did_hash = did_to_hash(&req.sponsor_user_did);
    let identity = match store.get_identity(&sponsor_did_hash) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Ok(forbidden(format!(
                "sponsor DID {} not found on chain",
                req.sponsor_user_did
            )))
        }
        Err(e) => return Ok(server_error(format!("identity store error: {e}"))),
    };

    let sov_token = lib_blockchain::storage::TokenId::new(
        lib_blockchain::contracts::utils::generate_lib_token_id(),
    );
    let sponsor_addr = identity.owner;
    let current_nonce = match store.get_token_nonce(&sov_token, &sponsor_addr) {
        Ok(n) => n,
        Err(e) => return Ok(server_error(format!("nonce lookup failed: {e}"))),
    };

    let data = RegisterObserverData {
        observer_node_did: req.observer_node_did,
        observer_public_key: observer_dilithium_pk,
        endpoints: req.endpoints,
        sponsor_user_did: req.sponsor_user_did,
        sponsor_proof_level: req.sponsor_proof_level,
        sponsor_signature: Vec::new(),
        allowed_network: req.allowed_network,
        trusted_sync_scope: req.trusted_sync_scope,
        rate_limit_tier: req.rate_limit_tier,
        expires_at: req.expires_at,
        nonce: current_nonce,
    };

    let zeroed_sig = lib_crypto::Signature {
        signature: Vec::new(),
        public_key: lib_crypto::PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [0u8; 32],
        },
        algorithm: lib_crypto::SignatureAlgorithm::DEFAULT,
        timestamp: 0,
    };

    let tx = Transaction::new_register_observer(chain_id, data, zeroed_sig);
    let signing_hash =
        lib_blockchain::transaction::hashing::hash_for_signature(&tx);
    let tx_canonical_bytes_hex = hex::encode(signing_hash.as_bytes());

    json_ok(&PrepareObserverResponse {
        tx_canonical_bytes_hex,
        nonce: current_nonce,
        sponsor_next_nonce: current_nonce.saturating_add(1),
        chain_id,
    })
}

/// Convenience wrapper for routing in `observer.rs` that resolves the
/// chain_id from the runtime before dispatching write endpoints.
pub async fn dispatch_admission_write(
    path: &str,
    request: ZhtpRequest,
    runtime: &crate::runtime::RuntimeOrchestrator,
) -> ZhtpResult<ZhtpResponse> {
    let chain_id = chain_id_from_runtime(runtime);
    match path {
        "/api/v1/observer/admission/prepare" => {
            handle_admission_prepare(request, chain_id).await
        }
        "/api/v1/observer/admission/register" => {
            let policy = resolve_admission_policy(runtime);
            handle_admission_register(request, chain_id, &policy).await
        }
        "/api/v1/observer/admission/update" => handle_admission_update(request, chain_id).await,
        "/api/v1/observer/admission/suspend" => handle_admission_suspend(request, chain_id).await,
        "/api/v1/observer/admission/revoke" => handle_admission_revoke(request, chain_id).await,
        "/api/v1/observer/admission/reauthorize" => {
            handle_admission_reauthorize(request, chain_id).await
        }
        _ => Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            format!("unknown admission write endpoint: {path}"),
        )),
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lib_protocols::types::{ZhtpHeaders, ZhtpMethod};

    const ZHTP_VERSION: &str = "1.0";

    fn build_request(method: ZhtpMethod, uri: &str, body: Vec<u8>) -> ZhtpRequest {
        ZhtpRequest {
            method,
            uri: uri.to_string(),
            version: ZHTP_VERSION.to_string(),
            headers: ZhtpHeaders::new(),
            body,
            timestamp: 0,
            requester: None,
            auth_proof: None,
        }
    }

    #[tokio::test]
    async fn challenge_returns_issued_with_nonce() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "did:zhtp:obs"
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/challenge",
            body,
        );
        let resp = handle_admission_challenge(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok);
        let parsed: AdmissionChallengeResponse = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(parsed.status, "issued");
        assert_eq!(parsed.challenge.challenge_nonce.len(), 32);
        assert!(!parsed.challenge.challenge_id.is_empty());
        assert!(parsed.challenge.expires_at > 0);
    }

    #[tokio::test]
    async fn challenge_rejects_empty_did() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": ""
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/challenge",
            body,
        );
        let resp = handle_admission_challenge(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn challenge_rejects_malformed_body() {
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/challenge",
            b"not json".to_vec(),
        );
        let resp = handle_admission_challenge(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn register_rejects_missing_observer_did() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "",
            "observer_public_key": [1, 2, 3],
            "sponsor_user_did": "did:zhtp:sponsor",
            "sponsor_proof_level": "Basic",
            "sponsor_signature": [9, 9, 9],
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard",
            "nonce": 1,
            "tx_signature": {
                "signature_bytes": [1; 64],
                "signer_dilithium_pk": [0; 2592]
            }
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/register",
            body,
        );
        let policy = lib_blockchain::observer::default_policy();
        let resp = handle_admission_register(req, 0, &policy).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn register_rejects_wrong_pubkey_length() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "did:zhtp:obs",
            "observer_public_key": [1, 2, 3],
            "sponsor_user_did": "did:zhtp:sponsor",
            "sponsor_proof_level": "Basic",
            "sponsor_signature": [9, 9, 9],
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard",
            "nonce": 1,
            "tx_signature": {
                "signature_bytes": [1, 2, 3],
                "signer_dilithium_pk": [0, 0, 0]
            }
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/register",
            body,
        );
        let policy = lib_blockchain::observer::default_policy();
        let resp = handle_admission_register(req, 0, &policy).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn suspend_rejects_empty_actor() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "did:zhtp:obs",
            "actor_did": "",
            "reason": "test",
            "nonce": 1,
            "tx_signature": {
                "signature_bytes": [1; 64],
                "signer_dilithium_pk": [0; 2592]
            }
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/suspend",
            body,
        );
        let resp = handle_admission_suspend(req, 0).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn status_requires_did_query_param() {
        let req = build_request(
            ZhtpMethod::Get,
            "/api/v1/observer/admission/status",
            vec![],
        );
        let resp = handle_admission_status(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn by_sponsor_requires_did_query_param() {
        let req = build_request(
            ZhtpMethod::Get,
            "/api/v1/observer/admission/by-sponsor",
            vec![],
        );
        let resp = handle_admission_by_sponsor(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[test]
    fn parse_did_query_extracts_value() {
        assert_eq!(
            parse_did_query("/api/v1/observer/admission/status?did=did%3Azhtp%3Afoo"),
            Some("did:zhtp:foo".to_string())
        );
        assert_eq!(
            parse_did_query("/api/v1/observer/admission/status?other=x&did=bar"),
            Some("bar".to_string())
        );
        assert_eq!(parse_did_query("/api/v1/observer/admission/status"), None);
    }

    #[test]
    fn reconstruct_signature_rejects_wrong_dilithium_length() {
        let env = TxSignatureEnvelope {
            signature_bytes: vec![1, 2, 3],
            signer_dilithium_pk: vec![0; 100],
            signer_kyber_pk: None,
        };
        assert!(reconstruct_signature(&env).is_err());
    }

    #[test]
    fn reconstruct_signature_accepts_valid_lengths() {
        let env = TxSignatureEnvelope {
            signature_bytes: vec![1, 2, 3],
            signer_dilithium_pk: vec![0u8; 2592],
            signer_kyber_pk: None,
        };
        let sig = reconstruct_signature(&env).expect("valid lengths must succeed");
        assert_eq!(sig.signature, vec![1, 2, 3]);
        assert_eq!(sig.public_key.dilithium_pk.len(), 2592);
    }

    // ---- observer-admission-8 anti-abuse pre-validation ----

    fn valid_register_body(proof_level: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "did:zhtp:obs",
            "observer_public_key": [1, 2, 3],
            "sponsor_user_did": "did:zhtp:sponsor",
            "sponsor_proof_level": proof_level,
            "sponsor_signature": [9, 9, 9],
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard",
            "nonce": 1,
            "tx_signature": {
                "signature_bytes": [1; 64],
                "signer_dilithium_pk": [0; 2592]
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn register_rejects_anonymous_sponsor_with_403() {
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/register",
            valid_register_body("None"),
        );
        let policy = lib_blockchain::observer::default_policy();
        let resp = handle_admission_register(req, 0, &policy).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Forbidden);
    }

    #[tokio::test]
    async fn register_rejects_below_minimum_proof_level_with_403() {
        let mut policy = lib_blockchain::observer::default_policy();
        policy.minimum_proof_level = ObserverProofLevel::Enhanced;
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/register",
            valid_register_body("Basic"),
        );
        let resp = handle_admission_register(req, 0, &policy).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Forbidden);
    }

    #[test]
    fn pre_validate_proof_level_helper_passes_at_minimum() {
        let policy = lib_blockchain::observer::default_policy();
        assert!(
            pre_validate_register_proof_level(ObserverProofLevel::Basic, &policy).is_none(),
            "Basic must satisfy default minimum (Basic)"
        );
        assert!(
            pre_validate_register_proof_level(ObserverProofLevel::Enhanced, &policy).is_none()
        );
        assert!(
            pre_validate_register_proof_level(ObserverProofLevel::Organizational, &policy)
                .is_none()
        );
    }

    #[test]
    fn pre_validate_proof_level_helper_rejects_none() {
        let policy = lib_blockchain::observer::default_policy();
        assert!(pre_validate_register_proof_level(ObserverProofLevel::None, &policy).is_some());
    }

    // ---- prepare endpoint unit tests (no blockchain required) ----

    #[tokio::test]
    async fn prepare_rejects_missing_observer_did() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "",
            "observer_dilithium_pk_hex": hex::encode(vec![1u8; 2592]),
            "sponsor_user_did": "did:zhtp:sponsor",
            "sponsor_proof_level": "Basic",
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard"
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/prepare",
            body,
        );
        let resp = handle_admission_prepare(req, 3).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn prepare_rejects_missing_sponsor_did() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "did:zhtp:obs",
            "observer_dilithium_pk_hex": hex::encode(vec![1u8; 2592]),
            "sponsor_user_did": "",
            "sponsor_proof_level": "Basic",
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard"
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/prepare",
            body,
        );
        let resp = handle_admission_prepare(req, 3).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn prepare_rejects_missing_dilithium_pk() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "did:zhtp:obs",
            "observer_dilithium_pk_hex": "",
            "sponsor_user_did": "did:zhtp:sponsor",
            "sponsor_proof_level": "Basic",
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard"
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/prepare",
            body,
        );
        let resp = handle_admission_prepare(req, 3).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn prepare_rejects_invalid_hex_pk() {
        let body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": "did:zhtp:obs",
            "observer_dilithium_pk_hex": "not-valid-hex!!",
            "sponsor_user_did": "did:zhtp:sponsor",
            "sponsor_proof_level": "Basic",
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard"
        }))
        .unwrap();
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/prepare",
            body,
        );
        let resp = handle_admission_prepare(req, 3).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    /// Full round-trip: prepare → sign → register → apply block → verify sled record.
    ///
    /// Also validates:
    ///   - prepare returns valid bytes and nonce for a known sponsor (acceptance criterion 1)
    ///   - 403 when sponsor DID is not found on chain (acceptance criterion 3)
    ///   - observer record appears in sled with correct sponsor binding (acceptance criterion 2)
    #[tokio::test]
    async fn prepare_register_round_trip() {
        use lib_blockchain::{
            storage::{did_to_hash, IdentityConsensus, IdentityStatus, IdentityType, SledStore},
            Block, BlockHeader, Blockchain,
        };
        use lib_blockchain::contracts::utils::generate_lib_token_id;
        use lib_blockchain::observer::default_policy;
        use lib_blockchain::storage::{Address, TokenId};
        use lib_blockchain::types::Hash;
        use lib_crypto::KeyPair;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        // --- Sled store (temp dir kept alive for test duration) ---
        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn lib_blockchain::storage::BlockchainStore> =
            Arc::new(SledStore::open(dir.path()).expect("sled open"));

        // --- Sponsor keypair + identity ---
        let sponsor_kp = KeyPair::generate().expect("sponsor keygen");
        let sponsor_did = "did:zhtp:sponsor-rt";
        let sponsor_did_hash = did_to_hash(sponsor_did);
        let sponsor_addr = Address::new(sponsor_kp.public_key.key_id);

        store
            .put_identity(
                &sponsor_did_hash,
                &IdentityConsensus::new(
                    sponsor_did_hash,
                    sponsor_addr,
                    &sponsor_kp.public_key.dilithium_pk,
                    IdentityType::User,
                ),
            )
            .expect("put identity");
        store
            .put_identity_owner_index(&sponsor_addr, &sponsor_did_hash)
            .expect("owner index");

        // --- Fund sponsor with enough SOV for the registration fee ---
        let sov_token = TokenId::new(generate_lib_token_id());
        store
            .set_token_balance(&sov_token, &sponsor_addr, 1_000_000)
            .expect("seed SOV");

        // --- Seed auto-approve policy so the record lands in Active status ---
        let mut policy = default_policy();
        policy.auto_approve = true;
        store.save_observer_policy(&policy).expect("seed policy");

        // --- Create blockchain and apply genesis ---
        let bc = Blockchain::new_with_store(store.clone()).expect("new blockchain");
        let genesis = lib_blockchain::create_genesis_block();
        let genesis_hash = genesis.header.block_hash;
        bc.executor
            .as_ref()
            .expect("executor")
            .apply_block(&genesis)
            .expect("genesis");

        // --- Seed global provider (bypasses IPC server) ---
        let bc_arc = Arc::new(RwLock::new(bc));
        crate::runtime::blockchain_provider::initialize_global_blockchain_provider()
            .set_blockchain(bc_arc.clone())
            .await
            .expect("set global blockchain");

        // --- Observer keypair ---
        let obs_kp = KeyPair::generate().expect("obs keygen");
        let obs_did = "did:zhtp:observer-rt";

        // --- Call prepare ---
        let prep_body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": obs_did,
            "observer_dilithium_pk_hex": hex::encode(obs_kp.public_key.dilithium_pk),
            "observer_kyber_pk_hex": "",
            "endpoints": ["127.0.0.1:9000"],
            "sponsor_user_did": sponsor_did,
            "sponsor_proof_level": "Basic",
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard"
        }))
        .unwrap();
        let prep_req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/prepare",
            prep_body,
        );
        let prep_resp = handle_admission_prepare(prep_req, 0x03).await.unwrap();
        assert_eq!(prep_resp.status, ZhtpStatus::Ok, "prepare must succeed");

        let prep: PrepareObserverResponse =
            serde_json::from_slice(&prep_resp.body).expect("parse prepare response");
        assert_eq!(prep.chain_id, 0x03);
        assert_eq!(prep.nonce, 0, "fresh sponsor nonce must be 0");
        assert_eq!(prep.sponsor_next_nonce, 1);
        assert_eq!(prep.tx_canonical_bytes_hex.len(), 64, "32 bytes hex = 64 chars");

        // --- 403 for sponsor not on chain (acceptance criterion 3) ---
        let bad_body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": obs_did,
            "observer_dilithium_pk_hex": hex::encode(obs_kp.public_key.dilithium_pk),
            "sponsor_user_did": "did:zhtp:no-such-sponsor",
            "sponsor_proof_level": "Basic",
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard"
        }))
        .unwrap();
        let bad_req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/prepare",
            bad_body,
        );
        let bad_resp = handle_admission_prepare(bad_req, 0x03).await.unwrap();
        assert_eq!(bad_resp.status, ZhtpStatus::Forbidden, "unknown sponsor must 403");

        // --- Sign canonical bytes ---
        let canonical = hex::decode(&prep.tx_canonical_bytes_hex).expect("decode hex");
        let sig = sponsor_kp.sign(&canonical).expect("sign");

        // --- Submit to /admission/register ---
        let reg_body = serde_json::to_vec(&serde_json::json!({
            "observer_node_did": obs_did,
            "observer_public_key": obs_kp.public_key.dilithium_pk.to_vec(),
            "endpoints": ["127.0.0.1:9000"],
            "sponsor_user_did": sponsor_did,
            "sponsor_proof_level": "Basic",
            "sponsor_signature": sig.signature,
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard",
            "nonce": prep.nonce,
            "tx_signature": {
                "signature_bytes": sig.signature,
                "signer_dilithium_pk": sponsor_kp.public_key.dilithium_pk.to_vec()
            }
        }))
        .unwrap();
        let reg_req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/register",
            reg_body,
        );
        let reg_policy = default_policy();
        let reg_resp = handle_admission_register(reg_req, 0x03, &reg_policy)
            .await
            .unwrap();
        assert_eq!(reg_resp.status, ZhtpStatus::Ok, "register must be submitted");

        // --- Apply a block to execute the pending transaction ---
        let pending_tx = {
            let bc = bc_arc.read().await;
            bc.pending_transactions()
                .first()
                .cloned()
                .expect("pending tx must exist after register")
        };

        let apply_block = {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..8].copy_from_slice(&1u64.to_be_bytes());
            let block_hash = Hash::new(hash_bytes);
            let header = BlockHeader {
                version: 1,
                previous_hash: genesis_hash.into(),
                data_helix_root: Hash::default().into(),
                timestamp: 2_000_000,
                height: 1,
                verification_helix_root: [0u8; 32],
                state_root: Hash::default().into(),
                bft_quorum_root: [0u8; 32],
                block_hash,
            };
            Block::new(header, vec![pending_tx])
        };

        {
            let bc = bc_arc.read().await;
            bc.executor
                .as_ref()
                .expect("executor")
                .apply_block(&apply_block)
                .expect("apply register block");
        }

        // --- Verify observer record exists in sled with correct sponsor binding ---
        let obs_did_hash = did_to_hash(obs_did);
        let record = store
            .get_observer_record(&obs_did_hash)
            .expect("store read")
            .expect("observer record must exist in sled after block apply");

        assert_eq!(record.node_info.observer_node_did, obs_did);
        assert_eq!(record.sponsor.sponsoring_user_did, sponsor_did);
        assert_eq!(record.node_info.endpoints, vec!["127.0.0.1:9000"]);
    }

    #[tokio::test]
    async fn prepare_rejects_malformed_body() {
        let req = build_request(
            ZhtpMethod::Post,
            "/api/v1/observer/admission/prepare",
            b"not json".to_vec(),
        );
        let resp = handle_admission_prepare(req, 3).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }
}
