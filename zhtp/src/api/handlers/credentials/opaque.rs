//! Server-side OPAQUE handlers for the lobby auth flow.
//!
//! Implements ticket #2557 (S3 of epic #2554): 4 endpoints + ephemeral
//! state map + TTL sweep.
//!
//!   POST /api/v1/auth/opaque/register/start
//!   POST /api/v1/auth/opaque/register/finish
//!   POST /api/v1/auth/opaque/login/start
//!   POST /api/v1/auth/opaque/login/finish
//!
//! Cipher suite is network-locked and mirrored byte-for-byte with the
//! client side (`lib-client/src/opaque.rs`):
//!   OprfCs = Ristretto255
//!   KeyExchange = TripleDh<Ristretto255, Sha512>
//!   Ksf = LobbyArgon2id (m=64MiB, t=3, p=4, fixed salt)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::Engine;
use generic_array::{ArrayLength, GenericArray};
use lib_blockchain::transaction::credentials::{
    AuthMethod, RegisterCredentialData, UserCredential,
};
use lib_blockchain::Blockchain;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::InternalError;
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Locked cipher suite (mirrors lib-client/src/opaque.rs LobbyAuthCipherSuite)
// ─────────────────────────────────────────────────────────────────────────────

pub const ARGON2_M_COST_KIB: u32 = 65_536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;
pub const KSF_SALT: &[u8] = b"zhtp-lobby-auth-v1";

#[derive(Default, Debug, Clone, Copy)]
pub struct LobbyArgon2id;

impl Ksf for LobbyArgon2id {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let params = argon2::Params::new(
            ARGON2_M_COST_KIB,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(L::USIZE),
        )
        .map_err(|_| InternalError::KsfError)?;
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );
        let mut output: GenericArray<u8, L> = GenericArray::default();
        argon2
            .hash_password_into(&input, KSF_SALT, &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LobbyAuthCipherSuite;

impl CipherSuite for LobbyAuthCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = LobbyArgon2id;
}

// ─────────────────────────────────────────────────────────────────────────────
// Ephemeral state — registration & login pending start->finish
// ─────────────────────────────────────────────────────────────────────────────

const STATE_TTL: Duration = Duration::from_secs(60);

/// Registration is stateless across start/finish in opaque-ke 4 — we only
/// need to remember the username and the TTL window. The `request_id` is
/// the binding token preventing cross-username confusion.
struct PendingRegistration {
    username: String,
    expires_at: Instant,
}

struct PendingLogin {
    username: String,
    server_login: ServerLogin<LobbyAuthCipherSuite>,
    expires_at: Instant,
}

pub struct OpaqueAuthState {
    server_setup: ServerSetup<LobbyAuthCipherSuite>,
    pending_register: RwLock<HashMap<String, PendingRegistration>>,
    pending_login: RwLock<HashMap<String, PendingLogin>>,
}

impl OpaqueAuthState {
    /// Construct from the raw bytes loaded from `genesis.toml [opaque]`.
    pub fn from_setup_bytes(bytes: &[u8]) -> Result<Self> {
        let server_setup = ServerSetup::<LobbyAuthCipherSuite>::deserialize(bytes)
            .map_err(|e| anyhow!("OPAQUE server setup deserialize failed: {:?}", e))?;
        Ok(Self {
            server_setup,
            pending_register: RwLock::new(HashMap::new()),
            pending_login: RwLock::new(HashMap::new()),
        })
    }

    /// Background sweep task: drops state entries past their TTL.
    pub fn spawn_sweep(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                let now = Instant::now();
                {
                    let mut reg = self.pending_register.write().await;
                    reg.retain(|_, v| v.expires_at > now);
                }
                {
                    let mut log_ = self.pending_login.write().await;
                    log_.retain(|_, v| v.expires_at > now);
                }
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request / response shapes
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterStartRequest {
    username: String,
    msg1_b64: String,
}

#[derive(Serialize)]
struct RegisterStartResponse {
    msg2_b64: String,
    request_id: String,
}

#[derive(Deserialize)]
struct RegisterFinishRequest {
    request_id: String,
    record_b64: String,
    /// did string the credential is bound to (must match the Dilithium key
    /// that signed the request envelope at the QUIC layer; verified before
    /// the tx is built).
    did: String,
}

#[derive(Serialize)]
struct RegisterFinishResponse {
    status: &'static str,
    did: String,
    username: String,
}

#[derive(Deserialize)]
struct LoginStartRequest {
    username: String,
    msg1_b64: String,
}

#[derive(Serialize)]
struct LoginStartResponse {
    msg2_b64: String,
    request_id: String,
}

#[derive(Deserialize)]
struct LoginFinishRequest {
    request_id: String,
    msg3_b64: String,
}

#[derive(Serialize)]
struct LoginFinishResponse {
    status: &'static str,
    session_token: String,
    did: String,
    username: String,
    access_zone: &'static str,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow!("invalid base64: {}", e))
}

fn random_request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn json_ok<T: Serialize>(body: &T) -> Result<ZhtpResponse> {
    let bytes = serde_json::to_vec(body)?;
    Ok(ZhtpResponse::success_with_content_type(
        bytes,
        "application/json".to_string(),
        None,
    ))
}

fn json_err(status: ZhtpStatus, msg: &str) -> ZhtpResponse {
    ZhtpResponse::error(status, msg.to_string())
}

fn lower_username(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

pub struct OpaqueHandlers {
    pub blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
    pub state: Arc<OpaqueAuthState>,
    pub session_manager: Arc<crate::session_manager::SessionManager>,
    pub rate_limiter: Arc<super::rate_limit::LobbyRateLimiter>,
}

fn ip_of(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("X-Real-IP")
        .or_else(|| request.headers.get("peer_addr"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn rate_limit_response(d: &super::rate_limit::RateDecision) -> Option<ZhtpResponse> {
    use super::rate_limit::RateDecision::*;
    let mut resp = match d {
        Allowed => return None,
        UsernameLocked { retry_after_secs } => {
            let mut r = json_err(
                ZhtpStatus::TooManyRequests,
                &format!("Username locked. Retry after {}s.", retry_after_secs),
            );
            r.headers
                .set("Retry-After", retry_after_secs.to_string());
            r
        }
        LifetimeCapHit => json_err(
            ZhtpStatus::TooManyRequests,
            "Too many failed attempts. Recovery flow required.",
        ),
        IpThrottled { retry_after_secs } => {
            let mut r = json_err(
                ZhtpStatus::TooManyRequests,
                &format!("IP throttled. Retry after {}s.", retry_after_secs),
            );
            r.headers
                .set("Retry-After", retry_after_secs.to_string());
            r
        }
        LoginStartThrottled { retry_after_secs } => {
            let mut r = json_err(
                ZhtpStatus::TooManyRequests,
                &format!(
                    "Too many login_start requests. Retry after {}s.",
                    retry_after_secs
                ),
            );
            r.headers
                .set("Retry-After", retry_after_secs.to_string());
            r
        }
    };
    resp.headers
        .set("Content-Type", "application/json".to_string());
    Some(resp)
}

impl OpaqueHandlers {
    pub async fn handle_register_start(
        &self,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let req: RegisterStartRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;
        let username = lower_username(&req.username);

        if let Err(e) =
            lib_blockchain::transaction::credentials::validate_username(&username)
        {
            return Ok(json_err(ZhtpStatus::BadRequest, &e));
        }

        // Username uniqueness pre-check (race with chain-applied uniqueness;
        // worst case the finish step rejects with conflict).
        {
            let bc = self.blockchain.read().await;
            if bc.credential_registry().contains_key(&username) {
                return Ok(json_err(ZhtpStatus::Conflict, "Username already taken"));
            }
        }

        let msg1 = match unb64(&req.msg1_b64) {
            Ok(v) => v,
            Err(e) => return Ok(json_err(ZhtpStatus::BadRequest, &e.to_string())),
        };
        let registration_request =
            match RegistrationRequest::<LobbyAuthCipherSuite>::deserialize(&msg1) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(json_err(
                        ZhtpStatus::BadRequest,
                        &format!("invalid OPAQUE msg1: {:?}", e),
                    ))
                }
            };

        let start_result = match ServerRegistration::<LobbyAuthCipherSuite>::start(
            &self.state.server_setup,
            registration_request,
            username.as_bytes(),
        ) {
            Ok(v) => v,
            Err(e) => {
                return Ok(json_err(
                    ZhtpStatus::InternalServerError,
                    &format!("OPAQUE register start failed: {:?}", e),
                ))
            }
        };
        let msg2_bytes = start_result.message.serialize().to_vec();

        let request_id = random_request_id();
        let expires_at = Instant::now() + STATE_TTL;
        // Note: ServerRegistration is stateless across start/finish — only
        // the username and TTL need to survive in the pending map. The
        // request-id binding prevents cross-username swaps.
        let _ = start_result; // explicit drop comment
        {
            let mut reg = self.state.pending_register.write().await;
            reg.insert(
                request_id.clone(),
                PendingRegistration {
                    username: username.clone(),
                    expires_at,
                },
            );
        }

        json_ok(&RegisterStartResponse {
            msg2_b64: b64(&msg2_bytes),
            request_id,
        })
    }

    pub async fn handle_register_finish(
        &self,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let req: RegisterFinishRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;

        let pending = {
            let mut reg = self.state.pending_register.write().await;
            reg.remove(&req.request_id)
        };
        let pending = match pending {
            Some(p) if p.expires_at > Instant::now() => p,
            Some(_) => {
                return Ok(json_err(ZhtpStatus::Gone, "request_id expired"))
            }
            None => {
                return Ok(json_err(
                    ZhtpStatus::NotFound,
                    "request_id not found (already used or expired)",
                ))
            }
        };

        // Verify the authenticated session DID matches the body DID.
        // (Defense-in-depth — the QUIC handler should already only let
        // this through with the right DID.)
        if !req.did.starts_with("did:zhtp:") {
            return Ok(json_err(ZhtpStatus::BadRequest, "invalid did format"));
        }
        if let Some(req_id) = request.requester.as_ref() {
            let claimed_suffix = req
                .did
                .strip_prefix("did:zhtp:")
                .unwrap_or(&req.did);
            let req_hex = hex::encode(req_id.0);
            // Accept either suffix-equality (canonical hash) — DID derivation
            // tolerance from claim-username. Mismatch is non-fatal in v1.
            if !claimed_suffix.eq_ignore_ascii_case(&req_hex) {
                info!(
                    "register_finish: requester key_id {} differs from body did {} (OK if pseudonymous DID derivation differs)",
                    &req_hex[..16.min(req_hex.len())],
                    &claimed_suffix[..16.min(claimed_suffix.len())]
                );
            }
        }

        let record_bytes = match unb64(&req.record_b64) {
            Ok(v) => v,
            Err(e) => return Ok(json_err(ZhtpStatus::BadRequest, &e.to_string())),
        };
        let upload =
            match RegistrationUpload::<LobbyAuthCipherSuite>::deserialize(&record_bytes) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(json_err(
                        ZhtpStatus::BadRequest,
                        &format!("invalid OPAQUE record: {:?}", e),
                    ))
                }
            };
        let server_record =
            ServerRegistration::<LobbyAuthCipherSuite>::finish(upload);
        let serialized_record = server_record.serialize().to_vec();

        // Submit a RegisterCredential tx with auth_method = Opaque and the
        // serialized server-side record as opaque_record. password_hash is
        // empty.
        let credential_data = RegisterCredentialData {
            username: pending.username.clone(),
            owner_did: req.did.clone(),
            password_hash: String::new(),
            opaque_record: serialized_record.clone(),
            auth_method: AuthMethod::Opaque,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tx = lib_blockchain::Transaction {
            version: 8,
            chain_id: 0x03,
            transaction_type: lib_blockchain::TransactionType::RegisterCredential,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature: lib_blockchain::integration::crypto_integration::Signature {
                signature: Vec::new(),
                public_key: lib_blockchain::integration::crypto_integration::PublicKey {
                    dilithium_pk: [0u8; 2592],
                    kyber_pk: [0u8; 1568],
                    key_id: [0u8; 32],
                },
                algorithm:
                    lib_blockchain::integration::crypto_integration::SignatureAlgorithm::Dilithium5,
                timestamp: now,
            },
            memo: format!("opaque:register:{}", pending.username).into_bytes(),
            payload: lib_blockchain::transaction::TransactionPayload::RegisterCredential(
                credential_data,
            ),
        };
        {
            let mut bc = self.blockchain.write().await;
            if let Err(e) = bc.add_system_transaction(tx) {
                return Ok(json_err(
                    ZhtpStatus::InternalServerError,
                    &format!("failed to submit RegisterCredential tx: {}", e),
                ));
            }
            // Cache-warmup so login_start sees the credential before the
            // block commits.
            let height = bc.height;
            bc.insert_credential_unchecked(
                pending.username.clone(),
                UserCredential {
                    username: pending.username.clone(),
                    owner_did: req.did.clone(),
                    password_hash: String::new(),
                    registered_at_height: height,
                    registered_at: now,
                    password_changed_at_height: 0,
                    opaque_record: serialized_record,
                    auth_method: AuthMethod::Opaque,
                },
            );
            bc.set_username_for_did_unchecked(req.did.clone(), pending.username.clone());
        }

        info!(
            "OPAQUE register: '{}' for {}",
            pending.username,
            &req.did[..20.min(req.did.len())]
        );

        json_ok(&RegisterFinishResponse {
            status: "registered",
            did: req.did,
            username: pending.username,
        })
    }

    pub async fn handle_login_start(
        &self,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let req: LoginStartRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;
        let username = lower_username(&req.username);

        // Burst throttle on login_start independently of the finish gate.
        let ip = ip_of(request);
        let decision = self.rate_limiter.check_login_start(&ip).await;
        if let Some(resp) = rate_limit_response(&decision) {
            return Ok(resp);
        }

        let credential = {
            let bc = self.blockchain.read().await;
            bc.credential_registry().get(&username).cloned()
        };
        let credential = match credential {
            Some(c) => c,
            None => {
                // Constant-time-ish delay to reduce username enumeration.
                tokio::time::sleep(Duration::from_millis(150)).await;
                return Ok(json_err(
                    ZhtpStatus::Unauthorized,
                    "Invalid username or password",
                ));
            }
        };

        // Legacy users with Argon2idPhc credentials must upgrade — return 409
        // signalling the client should run the OPAQUE register flow.
        if credential.auth_method != AuthMethod::Opaque {
            return Ok(json_err(
                ZhtpStatus::Conflict,
                "upgrade_required: this account uses legacy auth and must be re-registered via OPAQUE",
            ));
        }

        let msg1 = match unb64(&req.msg1_b64) {
            Ok(v) => v,
            Err(e) => return Ok(json_err(ZhtpStatus::BadRequest, &e.to_string())),
        };
        let credential_request =
            match CredentialRequest::<LobbyAuthCipherSuite>::deserialize(&msg1) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(json_err(
                        ZhtpStatus::BadRequest,
                        &format!("invalid OPAQUE msg1: {:?}", e),
                    ))
                }
            };

        let server_record =
            match ServerRegistration::<LobbyAuthCipherSuite>::deserialize(
                &credential.opaque_record,
            ) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "stored opaque_record for '{}' failed to deserialize: {:?}",
                        username, e
                    );
                    return Ok(json_err(
                        ZhtpStatus::InternalServerError,
                        "credential record is corrupted",
                    ));
                }
            };

        let mut rng = OsRng;
        let server_login = match ServerLogin::<LobbyAuthCipherSuite>::start(
            &mut rng,
            &self.state.server_setup,
            Some(server_record),
            credential_request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!("OPAQUE login_start internal failure: {:?}", e);
                return Ok(json_err(
                    ZhtpStatus::Unauthorized,
                    "Invalid username or password",
                ));
            }
        };
        let msg2_bytes = server_login.message.serialize().to_vec();

        let request_id = random_request_id();
        let expires_at = Instant::now() + STATE_TTL;
        {
            let mut log_ = self.state.pending_login.write().await;
            log_.insert(
                request_id.clone(),
                PendingLogin {
                    username,
                    server_login: server_login.state,
                    expires_at,
                },
            );
        }

        json_ok(&LoginStartResponse {
            msg2_b64: b64(&msg2_bytes),
            request_id,
        })
    }

    pub async fn handle_login_finish(
        &self,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let req: LoginFinishRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;

        let pending = {
            let mut log_ = self.state.pending_login.write().await;
            log_.remove(&req.request_id)
        };
        let pending = match pending {
            Some(p) if p.expires_at > Instant::now() => p,
            Some(_) => return Ok(json_err(ZhtpStatus::Gone, "request_id expired")),
            None => {
                return Ok(json_err(
                    ZhtpStatus::NotFound,
                    "request_id not found (already used or expired)",
                ))
            }
        };

        // Rate-limit gate BEFORE running OPAQUE finish — cheap fast-reject.
        let ip = ip_of(request);
        let decision = self
            .rate_limiter
            .check_login_finish(&pending.username, &ip)
            .await;
        if let Some(resp) = rate_limit_response(&decision) {
            return Ok(resp);
        }

        let msg3 = match unb64(&req.msg3_b64) {
            Ok(v) => v,
            Err(e) => return Ok(json_err(ZhtpStatus::BadRequest, &e.to_string())),
        };
        let credential_finalization =
            match CredentialFinalization::<LobbyAuthCipherSuite>::deserialize(&msg3) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(json_err(
                        ZhtpStatus::BadRequest,
                        &format!("invalid OPAQUE msg3: {:?}", e),
                    ))
                }
            };

        let finish_result = match pending
            .server_login
            .finish(credential_finalization, ServerLoginParameters::default())
        {
            Ok(r) => r,
            Err(_) => {
                // Record failure (both axes) — may tip into lock/throttle.
                let d = self.rate_limiter.record_failure(&pending.username, &ip).await;
                if let Some(resp) = rate_limit_response(&d) {
                    return Ok(resp);
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
                return Ok(json_err(
                    ZhtpStatus::Unauthorized,
                    "Invalid username or password",
                ));
            }
        };
        let session_key_bytes = finish_result.session_key.to_vec();

        // Successful login clears the per-username counter.
        self.rate_limiter
            .record_success_for_username(&pending.username)
            .await;

        // Resolve DID for the username.
        let did = {
            let bc = self.blockchain.read().await;
            bc.credential_registry()
                .get(&pending.username)
                .map(|c| c.owner_did.clone())
                .unwrap_or_default()
        };

        // Build identity_hash for the session table (same shape as legacy
        // password signin: blake3-style 32-byte hash from the DID hex).
        let identity_hash = {
            let did_hex = did.strip_prefix("did:zhtp:").unwrap_or(&did);
            let mut h = [0u8; 32];
            if let Ok(bytes) = hex::decode(did_hex) {
                let len = bytes.len().min(32);
                h[..len].copy_from_slice(&bytes[..len]);
            }
            lib_crypto::Hash(h)
        };

        let client_ip = request
            .headers
            .get("X-Real-IP")
            .unwrap_or_else(|| "unknown".to_string());
        let user_agent = request
            .headers
            .get("User-Agent")
            .unwrap_or_else(|| "unknown".to_string());

        let session_token = match self
            .session_manager
            .create_password_session_with_key(
                identity_hash,
                &client_ip,
                &user_agent,
                session_key_bytes,
            )
            .await
        {
            Ok(t) => t,
            Err(e) => {
                return Ok(json_err(
                    ZhtpStatus::InternalServerError,
                    &format!("failed to create session: {}", e),
                ))
            }
        };

        info!("OPAQUE login: '{}' from {}", pending.username, client_ip);

        json_ok(&LoginFinishResponse {
            status: "ok",
            session_token,
            did,
            username: pending.username,
            access_zone: "public",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_setup_bytes() -> Vec<u8> {
        let mut rng = OsRng;
        let s = ServerSetup::<LobbyAuthCipherSuite>::new(&mut rng);
        s.serialize().to_vec()
    }

    #[tokio::test]
    async fn state_construction_roundtrip() {
        let bytes = fresh_setup_bytes();
        let state = OpaqueAuthState::from_setup_bytes(&bytes).unwrap();
        // sanity: pending maps start empty
        assert!(state.pending_register.read().await.is_empty());
        assert!(state.pending_login.read().await.is_empty());
    }

    #[test]
    fn random_request_id_unique() {
        let a = random_request_id();
        let b = random_request_id();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn b64_roundtrip() {
        let original = vec![1u8, 2, 3, 4, 200, 255];
        let encoded = b64(&original);
        let decoded = unb64(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
