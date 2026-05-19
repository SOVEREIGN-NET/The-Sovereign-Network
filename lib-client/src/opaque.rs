//! Lobby auth — client-side OPAQUE (RFC 9497 / IETF CFRG draft) helpers.
//!
//! Locked cipher suite for the whole network (matches `opaque-ke` 4.x;
//! reviewer #2570 noted earlier draft scope said `opaque-ke = "3"` — we
//! shipped 4 to pick up the cleaner `KeyExchange` separation):
//! - OPRF group: Ristretto255
//! - Key-exchange: TripleDh<Ristretto255, Sha512>
//! - KSF: Argon2id with m_cost = 65_536 KiB (= 64 MiB), t_cost = 3, p_cost = 4
//!
//! These parameters MUST match the server's exactly. Changing any of them is
//! a hard breaking change that requires every existing user to re-register.
//!
//! This module is the client half. It produces protocol messages to send to
//! the server and consumes the server's responses. State handles are exposed
//! via FFI as opaque pointers; mobile/native callers hold them between the
//! `start` and `finish` calls of each flow.
//!
//! # FFI surface (reviewer #2570)
//!
//! The 6 exported `extern "C"` symbols form a paired (start, finish, free)
//! triplet for each flow:
//!
//! - `zhtp_opaque_register_start(password, out_request) -> *mut OpaqueRegisterState`
//! - `zhtp_opaque_register_finish(state, password, server_response, server_response_len, out_record, out_export_key) -> i32`
//! - `zhtp_opaque_register_state_free(state)`
//! - `zhtp_opaque_login_start(password, out_request) -> *mut OpaqueLoginState`
//! - `zhtp_opaque_login_finish(state, password, server_response, server_response_len, out_msg3, out_session_key, out_export_key) -> i32`
//! - `zhtp_opaque_login_state_free(state)`
//!
//! Naming note (reviewer #2570): the epic spec said
//! `zhtp_opaque_state_free`. Register-state and login-state are distinct
//! Rust types and must not be cross-passed; collapsing them into one C
//! symbol would erase the type safety that catches "register the state,
//! then login_free it" mistakes in mobile/web bindings. The split symbol
//! names are deliberate.
//!
//! ## Buffer ownership
//!
//! All `*mut ByteBuffer` out-params are populated by the callee with bytes
//! that the caller MUST free via the existing `zhtp_byte_buffer_free`
//! helper (or platform equivalent) once consumed. Inputs (`password`,
//! `server_response`) are read-only and not stored beyond the call.
//!
//! ## State-handle lifecycle
//!
//! Each `_start` returns either a non-null `*mut Opaque{Register,Login}State`
//! or a null pointer on failure. The caller has two valid disposal paths:
//!
//! 1. Pass it into the matching `_finish` — the call CONSUMES the handle
//!    and the caller MUST NOT free it afterward (do not double-free).
//! 2. Cancel via the matching `_state_free` — safe to pass null; the call
//!    is a no-op for null inputs (reviewer #2570 acceptance criterion).
//!
//! ## Error codes (`_finish` return values; reviewer #2570)
//!
//! - `0` — success
//! - `ZHTP_OPAQUE_ERR_INVALID_ARGS` (-1) — null pointer or bad CStr
//! - `ZHTP_OPAQUE_ERR_DESERIALIZE` (-2) — `server_response` couldn't be
//!   parsed as the expected protocol message
//! - `ZHTP_OPAQUE_ERR_OPAQUE_FINISH` (-3) — protocol-level rejection.
//!   For `login_finish` this is the "wrong password" signal that mobile
//!   should surface as the auth failure (and feed into the lockout
//!   counter). For `register_finish` it usually means the server's
//!   response was mismatched against the in-flight state.

use std::ffi::{c_char, CStr};

use anyhow::{anyhow, Result};
use generic_array::{ArrayLength, GenericArray};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::InternalError;
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;

// ─────────────────────────────────────────────────────────────────────────────
// Locked cipher suite
// ─────────────────────────────────────────────────────────────────────────────

/// Argon2id parameters used by the lobby-auth KSF. Network-locked.
///
/// Unit pinned (reviewer #2570): `m_cost` value is in **KiB** to match the
/// `argon2::Params::new` API contract. `65_536 KiB = 64 MiB`. Do not change
/// the units / value without coordinating a network-wide migration: a
/// factor-of-1024 mistake here silently produces a much weaker (or much
/// slower) KSF that mismatches the server.
pub const ARGON2_M_COST_KIB: u32 = 65_536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;

// ─── FFI error codes (negative; 0 = success) ────────────────────────────────
pub const ZHTP_OPAQUE_ERR_INVALID_ARGS: i32 = -1;
pub const ZHTP_OPAQUE_ERR_DESERIALIZE: i32 = -2;
pub const ZHTP_OPAQUE_ERR_OPAQUE_FINISH: i32 = -3;
/// Fixed salt baked into the KSF. Per-record randomness comes from OPAQUE's
/// envelope nonce; this salt only differentiates the KSF binding from other
/// argon2 contexts on the network.
pub const KSF_SALT: &[u8] = b"zhtp-lobby-auth-v1";

/// The lobby-auth KSF: Argon2id with the locked parameters above.
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

/// The locked lobby-auth cipher suite.
#[derive(Debug, Clone, Copy)]
pub struct LobbyAuthCipherSuite;

impl CipherSuite for LobbyAuthCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = LobbyArgon2id;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust-level helpers (called by FFI exports below)
// ─────────────────────────────────────────────────────────────────────────────

/// `ClientRegistration::start` — produces the first message and a state to
/// carry into `register_finish`.
pub fn client_register_start(
    password: &[u8],
) -> Result<(Vec<u8>, ClientRegistration<LobbyAuthCipherSuite>)> {
    let mut rng = OsRng;
    let result = ClientRegistration::<LobbyAuthCipherSuite>::start(&mut rng, password)
        .map_err(|e| anyhow!("OPAQUE register_start failed: {:?}", e))?;
    let msg_bytes = result.message.serialize().to_vec();
    Ok((msg_bytes, result.state))
}

/// Error returned by the `*_finish` Rust helpers, distinguishing wire-level
/// failures from OPAQUE protocol-level rejection (the latter is the
/// "wrong password" branch on login). The FFI layer maps these to the
/// `ZHTP_OPAQUE_ERR_*` codes — see the module-level FFI docs.
#[derive(Debug)]
pub enum OpaqueFinishError {
    Deserialize(String),
    OpaqueFinish(String),
}

impl std::fmt::Display for OpaqueFinishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deserialize(s) => write!(f, "deserialize: {}", s),
            Self::OpaqueFinish(s) => write!(f, "opaque finish: {}", s),
        }
    }
}

impl std::error::Error for OpaqueFinishError {}

/// `ClientRegistration::finish` — given the server's response, derives the
/// envelope (registration record), the session key, and the export key.
pub fn client_register_finish(
    state: ClientRegistration<LobbyAuthCipherSuite>,
    password: &[u8],
    server_response: &[u8],
) -> std::result::Result<RegisterFinishOutput, OpaqueFinishError> {
    let mut rng = OsRng;
    let server_msg = RegistrationResponse::<LobbyAuthCipherSuite>::deserialize(server_response)
        .map_err(|e| OpaqueFinishError::Deserialize(format!("{:?}", e)))?;
    let result = state
        .finish(
            &mut rng,
            password,
            server_msg,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| OpaqueFinishError::OpaqueFinish(format!("{:?}", e)))?;
    Ok(RegisterFinishOutput {
        record: result.message.serialize().to_vec(),
        export_key: result.export_key.to_vec(),
    })
}

pub struct RegisterFinishOutput {
    /// Registration record to upload to the server (`RegistrationUpload` bytes).
    pub record: Vec<u8>,
    /// Per-user "export key" — a stable 64-byte secret the user derives from
    /// their password each time. Useful for client-side encryption of
    /// secondary material (not used by the lobby flow itself).
    pub export_key: Vec<u8>,
}

/// `ClientLogin::start` — produces the first login message and a state.
pub fn client_login_start(
    password: &[u8],
) -> Result<(Vec<u8>, ClientLogin<LobbyAuthCipherSuite>)> {
    let mut rng = OsRng;
    let result = ClientLogin::<LobbyAuthCipherSuite>::start(&mut rng, password)
        .map_err(|e| anyhow!("OPAQUE login_start failed: {:?}", e))?;
    let msg_bytes = result.message.serialize().to_vec();
    Ok((msg_bytes, result.state))
}

/// `ClientLogin::finish` — produces the third login message and the
/// session_key. The session_key is the per-session shared secret used for
/// HMAC-based channel binding on subsequent requests.
///
/// `OpaqueFinishError::OpaqueFinish` is the protocol-level rejection branch —
/// for this entry point that's the "wrong password" signal.
pub fn client_login_finish(
    state: ClientLogin<LobbyAuthCipherSuite>,
    password: &[u8],
    server_response: &[u8],
) -> std::result::Result<LoginFinishOutput, OpaqueFinishError> {
    let mut rng = OsRng;
    let server_msg = CredentialResponse::<LobbyAuthCipherSuite>::deserialize(server_response)
        .map_err(|e| OpaqueFinishError::Deserialize(format!("{:?}", e)))?;
    let result = state
        .finish(
            &mut rng,
            password,
            server_msg,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|e| OpaqueFinishError::OpaqueFinish(format!("{:?}", e)))?;
    Ok(LoginFinishOutput {
        msg3: result.message.serialize().to_vec(),
        session_key: result.session_key.to_vec(),
        export_key: result.export_key.to_vec(),
    })
}

pub struct LoginFinishOutput {
    /// Third (final) login message — sent to the server to complete the flow.
    pub msg3: Vec<u8>,
    /// 64-byte session key — same on both sides after a successful login.
    /// Used as the HMAC key for `X-OPAQUE-Mac` request binding.
    pub session_key: Vec<u8>,
    /// 64-byte export key (deterministic from password — same as register's).
    pub export_key: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// FFI — state handles + 6 exports per epic ticket #2562
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque handle to in-flight registration state (between start and finish).
pub struct OpaqueRegisterState {
    inner: ClientRegistration<LobbyAuthCipherSuite>,
}

/// Opaque handle to in-flight login state (between start and finish).
pub struct OpaqueLoginState {
    inner: ClientLogin<LobbyAuthCipherSuite>,
}

unsafe fn write_buf(out: *mut crate::ByteBuffer, src: Vec<u8>) {
    // Match the existing ByteBuffer/forget pattern used elsewhere in lib-client.
    let mut boxed = src.into_boxed_slice();
    let buf = crate::ByteBuffer {
        data: boxed.as_mut_ptr(),
        len: boxed.len(),
    };
    std::mem::forget(boxed);
    *out = buf;
}

/// Step 1 of registration. Caller supplies a UTF-8 password. On success:
/// `*out_request` carries the bytes to POST to `/opaque/register/start`,
/// and the function returns a non-null state handle to feed into
/// `register_finish`. Returns null on failure; caller can interpret nullity
/// as "bad password or internal error".
#[no_mangle]
pub extern "C" fn zhtp_opaque_register_start(
    password: *const c_char,
    out_request: *mut crate::ByteBuffer,
) -> *mut OpaqueRegisterState {
    if password.is_null() || out_request.is_null() {
        return std::ptr::null_mut();
    }
    let pw = match unsafe { CStr::from_ptr(password) }.to_bytes_with_nul().split_last() {
        Some((_, body)) => body,
        None => return std::ptr::null_mut(),
    };
    match client_register_start(pw) {
        Ok((msg, state)) => {
            unsafe { write_buf(out_request, msg) };
            Box::into_raw(Box::new(OpaqueRegisterState { inner: state }))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Step 2 of registration. Consumes the state handle (caller MUST NOT free
/// it after this returns). On success writes:
/// - `out_record`: the registration record bytes to POST to the server's
///   `/opaque/register/finish`.
/// - `out_export_key`: 64-byte deterministic per-user key (optional use by
///   the caller — not required for the lobby flow itself).
///
/// Returns 0 on success, -1 on failure (wrong inputs / bad server response).
#[no_mangle]
pub extern "C" fn zhtp_opaque_register_finish(
    state: *mut OpaqueRegisterState,
    password: *const c_char,
    server_response: *const u8,
    server_response_len: usize,
    out_record: *mut crate::ByteBuffer,
    out_export_key: *mut crate::ByteBuffer,
) -> i32 {
    if state.is_null()
        || password.is_null()
        || server_response.is_null()
        || out_record.is_null()
        || out_export_key.is_null()
    {
        return ZHTP_OPAQUE_ERR_INVALID_ARGS;
    }
    let state_box = unsafe { Box::from_raw(state) };
    let pw = match unsafe { CStr::from_ptr(password) }.to_bytes_with_nul().split_last() {
        Some((_, body)) => body,
        None => return ZHTP_OPAQUE_ERR_INVALID_ARGS,
    };
    let resp = unsafe { std::slice::from_raw_parts(server_response, server_response_len) };
    match client_register_finish(state_box.inner, pw, resp) {
        Ok(out) => {
            unsafe { write_buf(out_record, out.record) };
            unsafe { write_buf(out_export_key, out.export_key) };
            0
        }
        Err(OpaqueFinishError::Deserialize(_)) => ZHTP_OPAQUE_ERR_DESERIALIZE,
        Err(OpaqueFinishError::OpaqueFinish(_)) => ZHTP_OPAQUE_ERR_OPAQUE_FINISH,
    }
}

/// Free a register-state handle without consuming it via `register_finish`.
/// Call this on cancellation paths to avoid leaks.
#[no_mangle]
pub extern "C" fn zhtp_opaque_register_state_free(state: *mut OpaqueRegisterState) {
    if !state.is_null() {
        drop(unsafe { Box::from_raw(state) });
    }
}

/// Step 1 of login. Same shape as `register_start`.
#[no_mangle]
pub extern "C" fn zhtp_opaque_login_start(
    password: *const c_char,
    out_request: *mut crate::ByteBuffer,
) -> *mut OpaqueLoginState {
    if password.is_null() || out_request.is_null() {
        return std::ptr::null_mut();
    }
    let pw = match unsafe { CStr::from_ptr(password) }.to_bytes_with_nul().split_last() {
        Some((_, body)) => body,
        None => return std::ptr::null_mut(),
    };
    match client_login_start(pw) {
        Ok((msg, state)) => {
            unsafe { write_buf(out_request, msg) };
            Box::into_raw(Box::new(OpaqueLoginState { inner: state }))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Step 2 of login. Consumes the state handle. On success writes:
/// - `out_msg3`: the third (final) login message to POST to the server.
/// - `out_session_key`: 64 bytes. The HMAC key for channel binding on every
///   subsequent lobby request.
/// - `out_export_key`: 64 bytes; identical to the one returned by register.
///
/// Returns 0 on success, -1 on failure (wrong password, bad server response,
/// etc.).
#[no_mangle]
pub extern "C" fn zhtp_opaque_login_finish(
    state: *mut OpaqueLoginState,
    password: *const c_char,
    server_response: *const u8,
    server_response_len: usize,
    out_msg3: *mut crate::ByteBuffer,
    out_session_key: *mut crate::ByteBuffer,
    out_export_key: *mut crate::ByteBuffer,
) -> i32 {
    if state.is_null()
        || password.is_null()
        || server_response.is_null()
        || out_msg3.is_null()
        || out_session_key.is_null()
        || out_export_key.is_null()
    {
        return ZHTP_OPAQUE_ERR_INVALID_ARGS;
    }
    let state_box = unsafe { Box::from_raw(state) };
    let pw = match unsafe { CStr::from_ptr(password) }.to_bytes_with_nul().split_last() {
        Some((_, body)) => body,
        None => return ZHTP_OPAQUE_ERR_INVALID_ARGS,
    };
    let resp = unsafe { std::slice::from_raw_parts(server_response, server_response_len) };
    match client_login_finish(state_box.inner, pw, resp) {
        Ok(out) => {
            unsafe { write_buf(out_msg3, out.msg3) };
            unsafe { write_buf(out_session_key, out.session_key) };
            unsafe { write_buf(out_export_key, out.export_key) };
            0
        }
        // ZHTP_OPAQUE_ERR_OPAQUE_FINISH is the "wrong password" signal here —
        // see module-level FFI docs.
        Err(OpaqueFinishError::Deserialize(_)) => ZHTP_OPAQUE_ERR_DESERIALIZE,
        Err(OpaqueFinishError::OpaqueFinish(_)) => ZHTP_OPAQUE_ERR_OPAQUE_FINISH,
    }
}

/// Free a login-state handle without consuming it via `login_finish`.
#[no_mangle]
pub extern "C" fn zhtp_opaque_login_state_free(state: *mut OpaqueLoginState) {
    if !state.is_null() {
        drop(unsafe { Box::from_raw(state) });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Channel binding — per-request HMAC over canonical request bytes (L2 #2563)
// ─────────────────────────────────────────────────────────────────────────────

/// Wrapper for the 64-byte OPAQUE-derived session key. The HMAC key for
/// per-request channel binding on every lobby request after login.
#[derive(Clone)]
pub struct LobbySessionKey(pub [u8; 64]);

impl LobbySessionKey {
    /// Build from a raw 64-byte slice (e.g. directly from `login_finish` output).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(anyhow!(
                "LobbySessionKey requires 64 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(LobbySessionKey(arr))
    }
}

/// Encode the canonical request bytes that the MAC covers.
///
/// **This format is the wire contract** — server-side verifier (S6 #2560)
/// must produce identical bytes for the same inputs or every MAC check fails.
/// Layout:
/// ```text
///   method_byte:    u8         (GET=0, POST=1, PUT=2, DELETE=3, …)
///   uri_len:        u32 BE
///   uri:            uri_len bytes UTF-8
///   body_len:       u32 BE
///   body:           body_len bytes
///   seq:            u64 BE
/// ```
pub fn canonical_request_bytes(method: u8, uri: &[u8], body: &[u8], seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + uri.len() + 4 + body.len() + 8);
    out.push(method);
    out.extend_from_slice(&(uri.len() as u32).to_be_bytes());
    out.extend_from_slice(uri);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&seq.to_be_bytes());
    out
}

/// Compute HMAC-SHA512(session_key, canonical_request_bytes). Truncated to
/// 32 bytes for use as the `X-OPAQUE-Mac` header value (hex-encoded by the
/// caller).
pub fn compute_mac(
    key: &LobbySessionKey,
    method: u8,
    uri: &[u8],
    body: &[u8],
    seq: u64,
) -> [u8; 32] {
    use hmac::Mac;
    type HmacSha512 = hmac::Hmac<sha2::Sha512>;
    let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(&key.0)
        .expect("HMAC-SHA512 accepts any key length");
    let canonical = canonical_request_bytes(method, uri, body, seq);
    mac.update(&canonical);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Constant-time comparison of two MAC bytes (for callers verifying server
/// responses — server-side has its own verification path).
pub fn verify_mac_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Method byte encoding used by `canonical_request_bytes`.
pub mod method {
    pub const GET: u8 = 0;
    pub const POST: u8 = 1;
    pub const PUT: u8 = 2;
    pub const DELETE: u8 = 3;
    pub const PATCH: u8 = 4;
    pub const HEAD: u8 = 5;
    pub const OPTIONS: u8 = 6;
}

/// Compute the HMAC for a lobby request. Mobile / native callers invoke this
/// before sending; the resulting 32 bytes go into the `X-OPAQUE-Mac` header
/// (hex-encoded), and `seq` into `X-OPAQUE-Seq`.
///
/// `session_key_ptr` MUST point to exactly 64 bytes (the session_key
/// returned by `zhtp_opaque_login_finish`).
///
/// `out_mac` is filled with exactly 32 bytes on success; do not free it
/// (it's caller-owned space, e.g. a fixed `[u8;32]` on the stack).
///
/// Returns 0 on success, -1 on invalid input.
#[no_mangle]
pub extern "C" fn zhtp_lobby_mac_compute(
    session_key_ptr: *const u8,
    session_key_len: usize,
    method: u8,
    uri: *const u8,
    uri_len: usize,
    body: *const u8,
    body_len: usize,
    seq: u64,
    out_mac: *mut u8,
) -> i32 {
    if session_key_ptr.is_null() || session_key_len != 64 || out_mac.is_null() {
        return -1;
    }
    if uri.is_null() && uri_len != 0 {
        return -1;
    }
    if body.is_null() && body_len != 0 {
        return -1;
    }
    let key_slice = unsafe { std::slice::from_raw_parts(session_key_ptr, 64) };
    let key = match LobbySessionKey::from_bytes(key_slice) {
        Ok(k) => k,
        Err(_) => return -1,
    };
    let uri_slice = if uri_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(uri, uri_len) }
    };
    let body_slice = if body_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(body, body_len) }
    };
    let mac = compute_mac(&key, method, uri_slice, body_slice, seq);
    unsafe { std::ptr::copy_nonoverlapping(mac.as_ptr(), out_mac, 32) };
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// LobbySession handle — bearer + key + seq, drives every lobby request (L3 #2564)
// ─────────────────────────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

/// A bound lobby session. Holds the bearer token, the OPAQUE session_key,
/// identity metadata, and a monotonic per-session sequence counter.
///
/// One handle drives N concurrent authenticated lobby requests safely —
/// `next_seq()` is atomic so each request gets a unique seq.
pub struct LobbySession {
    pub session_token: String,
    pub session_key: LobbySessionKey,
    pub did: String,
    pub username: String,
    next_seq: AtomicU64,
}

impl LobbySession {
    pub fn new(
        session_token: String,
        session_key: LobbySessionKey,
        did: String,
        username: String,
    ) -> Self {
        Self {
            session_token,
            session_key,
            did,
            username,
            // Start at 1 — server rejects seq <= last_seen, so first request
            // uses seq=1 and the server's last_seen starts at 0.
            next_seq: AtomicU64::new(1),
        }
    }

    /// Allocate the next sequence number for a request. Atomic; safe under
    /// concurrent use.
    pub fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Build the three headers required for a lobby request.
    /// Returns (Authorization, X-OPAQUE-Mac (hex), X-OPAQUE-Seq (decimal)).
    pub fn prepare_headers(
        &self,
        method: u8,
        uri: &[u8],
        body: &[u8],
    ) -> (String, String, String) {
        let seq = self.next_seq();
        let mac = compute_mac(&self.session_key, method, uri, body, seq);
        (
            format!("Bearer {}", self.session_token),
            hex::encode(mac),
            seq.to_string(),
        )
    }
}

/// Construct a `LobbySession` handle from raw fields.
///
/// `session_key_ptr` MUST point to exactly 64 bytes. Other pointers are
/// nul-terminated UTF-8.
///
/// Returns a handle the caller owns; free with `zhtp_lobby_session_free`.
#[no_mangle]
pub extern "C" fn zhtp_lobby_session_new(
    session_token: *const c_char,
    session_key_ptr: *const u8,
    session_key_len: usize,
    did: *const c_char,
    username: *const c_char,
) -> *mut LobbySession {
    if session_token.is_null()
        || session_key_ptr.is_null()
        || session_key_len != 64
        || did.is_null()
        || username.is_null()
    {
        return std::ptr::null_mut();
    }
    let token = match unsafe { CStr::from_ptr(session_token) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };
    let did = match unsafe { CStr::from_ptr(did) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };
    let username = match unsafe { CStr::from_ptr(username) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };
    let key_slice = unsafe { std::slice::from_raw_parts(session_key_ptr, 64) };
    let key = match LobbySessionKey::from_bytes(key_slice) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(LobbySession::new(token, key, did, username)))
}

/// Prepare the headers for one lobby request. Three NUL-terminated strings
/// returned via output `ByteBuffer`s (each containing the bytes of one
/// header value, NUL-terminated for ease of consumption by callers that
/// expect C strings).
///
/// Returns 0 on success, -1 on bad input.
///
/// Caller frees each ByteBuffer with `zhtp_client_byte_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_lobby_session_prepare(
    session: *const LobbySession,
    method: u8,
    uri: *const u8,
    uri_len: usize,
    body: *const u8,
    body_len: usize,
    out_authorization: *mut crate::ByteBuffer,
    out_mac_hex: *mut crate::ByteBuffer,
    out_seq: *mut crate::ByteBuffer,
) -> i32 {
    if session.is_null()
        || out_authorization.is_null()
        || out_mac_hex.is_null()
        || out_seq.is_null()
    {
        return -1;
    }
    if uri.is_null() && uri_len != 0 {
        return -1;
    }
    if body.is_null() && body_len != 0 {
        return -1;
    }
    let session = unsafe { &*session };
    let uri_slice = if uri_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(uri, uri_len) }
    };
    let body_slice = if body_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(body, body_len) }
    };
    let (auth, mac_hex, seq) = session.prepare_headers(method, uri_slice, body_slice);

    unsafe {
        write_buf(out_authorization, auth.into_bytes());
        write_buf(out_mac_hex, mac_hex.into_bytes());
        write_buf(out_seq, seq.into_bytes());
    }
    0
}

/// Free a LobbySession handle.
#[no_mangle]
pub extern "C" fn zhtp_lobby_session_free(session: *mut LobbySession) {
    if !session.is_null() {
        drop(unsafe { Box::from_raw(session) });
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn make_session() -> LobbySession {
        LobbySession::new(
            "deadbeef".to_string(),
            LobbySessionKey([0x42; 64]),
            "did:zhtp:abc".to_string(),
            "alice".to_string(),
        )
    }

    #[test]
    fn seqs_are_monotonic() {
        let s = make_session();
        assert_eq!(s.next_seq(), 1);
        assert_eq!(s.next_seq(), 2);
        assert_eq!(s.next_seq(), 3);
    }

    #[test]
    fn concurrent_seqs_are_unique() {
        use std::sync::Arc;
        use std::thread;
        let s = Arc::new(make_session());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = s.clone();
            handles.push(thread::spawn(move || {
                let mut local = Vec::new();
                for _ in 0..256 {
                    local.push(s.next_seq());
                }
                local
            }));
        }
        let mut all: Vec<u64> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 8 * 256, "no two requests should share a seq");
    }

    #[test]
    fn headers_format_correct() {
        let s = make_session();
        let (auth, mac_hex, seq) = s.prepare_headers(method::GET, b"/x", b"", );
        assert!(auth.starts_with("Bearer "));
        assert_eq!(auth, "Bearer deadbeef");
        assert_eq!(mac_hex.len(), 64); // 32 bytes hex
        assert_eq!(seq, "1");
    }
}

#[cfg(test)]
mod mac_tests {
    use super::*;

    fn key() -> LobbySessionKey {
        LobbySessionKey([0xab; 64])
    }

    #[test]
    fn deterministic_for_same_input() {
        let k = key();
        let a = compute_mac(&k, method::GET, b"/api/v1/chain/info", b"", 1);
        let b = compute_mac(&k, method::GET, b"/api/v1/chain/info", b"", 1);
        assert_eq!(a, b);
    }

    #[test]
    fn different_uri_different_mac() {
        let k = key();
        let a = compute_mac(&k, method::GET, b"/api/v1/chain/info", b"", 1);
        let b = compute_mac(&k, method::GET, b"/api/v1/dao/proposals", b"", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn different_body_different_mac() {
        let k = key();
        let a = compute_mac(&k, method::POST, b"/x", b"alpha", 1);
        let b = compute_mac(&k, method::POST, b"/x", b"beta", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn different_seq_different_mac() {
        let k = key();
        let a = compute_mac(&k, method::GET, b"/x", b"", 1);
        let b = compute_mac(&k, method::GET, b"/x", b"", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn different_key_different_mac() {
        let k1 = LobbySessionKey([0x11; 64]);
        let k2 = LobbySessionKey([0x22; 64]);
        let a = compute_mac(&k1, method::GET, b"/x", b"", 1);
        let b = compute_mac(&k2, method::GET, b"/x", b"", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_bytes_layout() {
        // method=POST(1), uri="/x", body="hi", seq=42
        let bytes = canonical_request_bytes(1, b"/x", b"hi", 42);
        assert_eq!(
            bytes,
            vec![
                1, // method
                0, 0, 0, 2, b'/', b'x', // uri_len=2 + uri
                0, 0, 0, 2, b'h', b'i', // body_len=2 + body
                0, 0, 0, 0, 0, 0, 0, 42, // seq=42
            ]
        );
    }

    #[test]
    fn ffi_matches_rust() {
        let k = key();
        let rust_mac = compute_mac(&k, method::POST, b"/api/v1/foo", b"bar", 7);

        let mut ffi_mac = [0u8; 32];
        let rc = zhtp_lobby_mac_compute(
            k.0.as_ptr(),
            64,
            method::POST,
            b"/api/v1/foo".as_ptr(),
            "/api/v1/foo".len(),
            b"bar".as_ptr(),
            3,
            7,
            ffi_mac.as_mut_ptr(),
        );
        assert_eq!(rc, 0);
        assert_eq!(rust_mac, ffi_mac);
    }

    #[test]
    fn ffi_rejects_wrong_key_len() {
        let k = [0u8; 32];
        let mut out = [0u8; 32];
        let rc = zhtp_lobby_mac_compute(
            k.as_ptr(),
            32,
            method::GET,
            b"/x".as_ptr(),
            2,
            std::ptr::null(),
            0,
            0,
            out.as_mut_ptr(),
        );
        assert_eq!(rc, -1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — full register + login roundtrip using the server half of opaque-ke.
// (Server side is otherwise instantiated only in the zhtp crate; we reach into
// the same library here just for the test.)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup};
    use rand::rngs::OsRng;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const USERNAME: &[u8] = b"alice";

    fn fresh_setup() -> ServerSetup<LobbyAuthCipherSuite> {
        let mut rng = OsRng;
        ServerSetup::<LobbyAuthCipherSuite>::new(&mut rng)
    }

    #[test]
    fn full_roundtrip_register_then_login() {
        let server_setup = fresh_setup();

        // ─── REGISTER ────────────────────────────────────────────────────
        let (msg1, state) = client_register_start(PASSWORD).unwrap();
        let request = opaque_ke::RegistrationRequest::deserialize(&msg1).unwrap();
        let server_response =
            ServerRegistration::<LobbyAuthCipherSuite>::start(&server_setup, request, USERNAME)
                .unwrap();
        let out = client_register_finish(state, PASSWORD, &server_response.message.serialize())
            .unwrap();
        let record = opaque_ke::RegistrationUpload::deserialize(&out.record).unwrap();
        let server_record =
            ServerRegistration::<LobbyAuthCipherSuite>::finish(record);

        // ─── LOGIN ───────────────────────────────────────────────────────
        let (msg1, state) = client_login_start(PASSWORD).unwrap();
        let request = opaque_ke::CredentialRequest::deserialize(&msg1).unwrap();
        let mut rng = OsRng;
        let server_login_start = ServerLogin::<LobbyAuthCipherSuite>::start(
            &mut rng,
            &server_setup,
            Some(server_record),
            request,
            USERNAME,
            ServerLoginParameters::default(),
        )
        .unwrap();
        let login_out =
            client_login_finish(state, PASSWORD, &server_login_start.message.serialize()).unwrap();
        let credential_finalization =
            opaque_ke::CredentialFinalization::deserialize(&login_out.msg3).unwrap();
        let server_login_finish = server_login_start
            .state
            .finish(credential_finalization, ServerLoginParameters::default())
            .unwrap();

        assert_eq!(login_out.session_key, server_login_finish.session_key.to_vec());
        assert_eq!(login_out.session_key.len(), 64);
        assert_eq!(login_out.export_key.len(), 64);
        // Reviewer #2570: the OPAQUE export_key IS deterministic across
        // register and login for the same (password, envelope). That's its
        // entire point — clients use it to encrypt secondary material that
        // survives across login sessions. Pin the invariant here:
        assert_eq!(
            out.export_key, login_out.export_key,
            "export_key must match across register and login for same password"
        );
    }

    /// Reviewer #2570 acceptance criterion: `*_state_free(null_mut())` must
    /// be a no-op. Both register-state and login-state free fns.
    #[test]
    fn free_null_state_is_noop() {
        zhtp_opaque_register_state_free(std::ptr::null_mut());
        zhtp_opaque_login_state_free(std::ptr::null_mut());
    }

    /// Reviewer #2570: end-to-end FFI roundtrip exercises every `unsafe`
    /// path (CStr decode, ByteBuffer write, Box::from_raw, state handle
    /// lifecycle) at least once.
    #[test]
    fn ffi_register_then_login_roundtrip() {
        use std::ffi::CString;
        let server_setup = fresh_setup();
        let pw = CString::new(PASSWORD).unwrap();

        // ─── REGISTER via FFI ────────────────────────────────────────────
        let mut req_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let state = zhtp_opaque_register_start(pw.as_ptr(), &mut req_buf as *mut _);
        assert!(!state.is_null(), "register_start must return non-null handle");
        assert!(req_buf.len > 0 && !req_buf.data.is_null());

        let msg1 = unsafe { std::slice::from_raw_parts(req_buf.data, req_buf.len).to_vec() };
        let request = opaque_ke::RegistrationRequest::deserialize(&msg1).unwrap();
        let server_response =
            ServerRegistration::<LobbyAuthCipherSuite>::start(&server_setup, request, USERNAME)
                .unwrap();
        let server_msg = server_response.message.serialize();

        let mut record_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let mut export_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let rc = zhtp_opaque_register_finish(
            state,
            pw.as_ptr(),
            server_msg.as_ptr(),
            server_msg.len(),
            &mut record_buf as *mut _,
            &mut export_buf as *mut _,
        );
        assert_eq!(rc, 0, "register_finish must succeed");
        let record_bytes =
            unsafe { std::slice::from_raw_parts(record_buf.data, record_buf.len).to_vec() };
        let register_export =
            unsafe { std::slice::from_raw_parts(export_buf.data, export_buf.len).to_vec() };
        let server_record = ServerRegistration::<LobbyAuthCipherSuite>::finish(
            opaque_ke::RegistrationUpload::deserialize(&record_bytes).unwrap(),
        );

        // ─── LOGIN via FFI ───────────────────────────────────────────────
        let mut login_req_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let login_state = zhtp_opaque_login_start(pw.as_ptr(), &mut login_req_buf as *mut _);
        assert!(!login_state.is_null());
        let login_msg1 = unsafe {
            std::slice::from_raw_parts(login_req_buf.data, login_req_buf.len).to_vec()
        };
        let request = opaque_ke::CredentialRequest::deserialize(&login_msg1).unwrap();
        let mut rng = OsRng;
        let sls = ServerLogin::<LobbyAuthCipherSuite>::start(
            &mut rng,
            &server_setup,
            Some(server_record),
            request,
            USERNAME,
            ServerLoginParameters::default(),
        )
        .unwrap();
        let server_msg2 = sls.message.serialize();

        let mut msg3_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let mut sk_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let mut ek_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let rc = zhtp_opaque_login_finish(
            login_state,
            pw.as_ptr(),
            server_msg2.as_ptr(),
            server_msg2.len(),
            &mut msg3_buf as *mut _,
            &mut sk_buf as *mut _,
            &mut ek_buf as *mut _,
        );
        assert_eq!(rc, 0, "login_finish must succeed");
        let session_key = unsafe { std::slice::from_raw_parts(sk_buf.data, sk_buf.len).to_vec() };
        let login_export = unsafe { std::slice::from_raw_parts(ek_buf.data, ek_buf.len).to_vec() };
        assert_eq!(session_key.len(), 64);
        assert_eq!(register_export, login_export, "export_key deterministic");
    }

    /// Reviewer #2570: cancel path — `_start` returns a handle, caller
    /// invokes `_state_free` instead of `_finish`. Must not leak / segfault.
    #[test]
    fn ffi_cancel_register_via_free() {
        use std::ffi::CString;
        let pw = CString::new(PASSWORD).unwrap();
        let mut req_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let state = zhtp_opaque_register_start(pw.as_ptr(), &mut req_buf as *mut _);
        assert!(!state.is_null());
        zhtp_opaque_register_state_free(state);
    }

    #[test]
    fn ffi_cancel_login_via_free() {
        use std::ffi::CString;
        let pw = CString::new(PASSWORD).unwrap();
        let mut req_buf = crate::ByteBuffer { data: std::ptr::null_mut(), len: 0 };
        let state = zhtp_opaque_login_start(pw.as_ptr(), &mut req_buf as *mut _);
        assert!(!state.is_null());
        zhtp_opaque_login_state_free(state);
    }

    /// Reviewer #2570: FFI must reject null args with the documented code,
    /// not segfault.
    #[test]
    fn ffi_null_args_return_invalid() {
        let rc = zhtp_opaque_register_finish(
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rc, ZHTP_OPAQUE_ERR_INVALID_ARGS);
        let rc = zhtp_opaque_login_finish(
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rc, ZHTP_OPAQUE_ERR_INVALID_ARGS);
    }

    #[test]
    fn wrong_password_login_fails() {
        let server_setup = fresh_setup();

        // Register with correct password
        let (msg1, state) = client_register_start(PASSWORD).unwrap();
        let request = opaque_ke::RegistrationRequest::deserialize(&msg1).unwrap();
        let server_response =
            ServerRegistration::<LobbyAuthCipherSuite>::start(&server_setup, request, USERNAME)
                .unwrap();
        let out = client_register_finish(state, PASSWORD, &server_response.message.serialize())
            .unwrap();
        let record = opaque_ke::RegistrationUpload::deserialize(&out.record).unwrap();
        let server_record =
            ServerRegistration::<LobbyAuthCipherSuite>::finish(record);

        // Try to log in with WRONG password
        let (msg1, state) = client_login_start(b"WRONG").unwrap();
        let request = opaque_ke::CredentialRequest::deserialize(&msg1).unwrap();
        let mut rng = OsRng;
        let server_login_start = ServerLogin::<LobbyAuthCipherSuite>::start(
            &mut rng,
            &server_setup,
            Some(server_record),
            request,
            USERNAME,
            ServerLoginParameters::default(),
        )
        .unwrap();
        let result =
            client_login_finish(state, b"WRONG", &server_login_start.message.serialize());
        assert!(result.is_err(), "login with wrong password must fail");
    }
}
