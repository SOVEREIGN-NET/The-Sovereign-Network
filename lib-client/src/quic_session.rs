//! Persistent QUIC session FFI — handles, multiplexed RPC, server-push inbound stream.
//!
//! Implements T1/T2/T3 of messaging push epic. Wraps the existing
//! `lib_network::client::ZhtpClient` so the FFI inherits the UHP handshake,
//! auth context, and wire framing without re-implementing transport.
//!
//! Threading: each handle owns a worker thread that drives connect, handshake,
//! RPC, and inbound work on the shared `CLIENT_ENDPOINT_RUNTIME` from
//! lib-network. FFI callers may call from any thread; commands route through
//! a tokio mpsc queue.
//!
//! # MSG-NODE-001 — errors + handshake parity
//!
//! `zhtp_quic_session_open` uses the **canonical** UHP initiator
//! (`quic_handshake::handshake_as_initiator` / `quic_uhp_capabilities`).
//! On failure it returns null and stores a structured last-error string
//! (`stage=…: message`) retrievable via `zhtp_quic_session_last_error`.
//!
//! Last-error storage is **process-global** (mutex, last-writer-wins) so
//! mobile can read it from a different OS thread than the one that called
//! `open` (Dart isolates / JNI pools). Concurrent opens can overwrite each
//! other's error — that is intentional and safer than a silent empty read.
//!
//! `zhtp_quic_session_open` **blocks** the caller until connect + UHP finish;
//! mobile must not call it on the UI thread.

#![cfg(not(target_arch = "wasm32"))]

use std::ffi::{c_char, CStr, CString};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::oneshot;
use tracing::debug;

use lib_identity::types::IdentityType;
use lib_identity::ZhtpIdentity;
use lib_network::client::{ZhtpClient, ZhtpClientConfig};
use lib_network::web4::trust::TrustConfig;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest};
use lib_protocols::wire::read_response;

use crate::identity::Identity;

// =============================================================================
// LAST ERROR (process-global for FFI — any thread may read)
// =============================================================================

/// Canonical stage tokens + NUL-terminated C strings (single source of truth).
/// Order is stable for `classify_stage` scans; keep longest names first only
/// if a shorter name were a prefix of a longer one (none are today).
const STAGES: &[(&str, &[u8])] = &[
    ("resolve", b"resolve\0"),
    ("quic", b"quic\0"),
    ("tls", b"tls\0"),
    ("uhp_handshake", b"uhp_handshake\0"),
    ("trust", b"trust\0"),
    ("session_keys", b"session_keys\0"),
    ("config", b"config\0"),
    ("identity", b"identity\0"),
    ("alpn", b"alpn\0"),
    ("runtime", b"runtime\0"),
    ("client_init", b"client_init\0"),
    ("inbound", b"inbound\0"),
    ("rpc", b"rpc\0"),
    ("args", b"args\0"),
];

const STAGE_NONE: &[u8] = b"none\0";

struct LastErrorState {
    stage: &'static str,
    message: Option<String>,
}

fn last_error_slot() -> &'static Mutex<LastErrorState> {
    static SLOT: OnceLock<Mutex<LastErrorState>> = OnceLock::new();
    SLOT.get_or_init(|| {
        Mutex::new(LastErrorState {
            stage: "none",
            message: None,
        })
    })
}

fn clear_last_error() {
    if let Ok(mut g) = last_error_slot().lock() {
        g.stage = "none";
        g.message = None;
    }
}

fn set_last_error(stage: &'static str, message: impl AsRef<str>) {
    let msg = message.as_ref().to_string();
    // Debug only — avoid noisy stderr / leaking dial details on mobile release.
    debug!(stage, error = %msg, "zhtp_quic_session last_error");
    if let Ok(mut g) = last_error_slot().lock() {
        g.stage = stage;
        g.message = Some(format!("stage={}: {}", stage, msg));
    }
}

fn set_last_error_from_anyhow(fallback_stage: &'static str, err: &anyhow::Error) {
    let full = format!("{:#}", err);
    let stage = classify_stage(&full).unwrap_or(fallback_stage);
    set_last_error(stage, full);
}

fn current_stage() -> &'static str {
    last_error_slot().lock().map(|g| g.stage).unwrap_or("none")
}

fn current_error_message() -> Option<String> {
    last_error_slot()
        .lock()
        .ok()
        .and_then(|g| g.message.clone())
}

/// Parse `stage=foo` markers embedded in error chains (from ZhtpClient).
fn classify_stage(msg: &str) -> Option<&'static str> {
    for (stage, _) in STAGES {
        if msg.contains(&format!("stage={}", stage)) {
            return Some(*stage);
        }
    }
    // Heuristic fallbacks for older error strings.
    let lower = msg.to_ascii_lowercase();
    if lower.contains("uhp") || lower.contains("handshake") || lower.contains("length prefix") {
        return Some("uhp_handshake");
    }
    if lower.contains("resolve") || lower.contains("dns") {
        return Some("resolve");
    }
    if lower.contains("quic connection") || lower.contains("connection failed") {
        return Some("quic");
    }
    if lower.contains("alpn") {
        return Some("alpn");
    }
    if lower.contains("identity") || lower.contains("public_key") || lower.contains("private_key") {
        return Some("identity");
    }
    None
}

fn stage_as_c_str(stage: &str) -> *const c_char {
    for (name, cstr) in STAGES {
        if *name == stage {
            return cstr.as_ptr() as *const c_char;
        }
    }
    STAGE_NONE.as_ptr() as *const c_char
}

// =============================================================================
// HANDLES
// =============================================================================

/// Opaque handle to a persistent QUIC session.
pub struct QuicSessionHandle {
    tx: tokio::sync::mpsc::Sender<SessionCmd>,
    _worker: Option<thread::JoinHandle<()>>,
}

/// Opaque handle to a server-push inbound stream.
pub struct InboundStreamHandle {
    rx: std::sync::Mutex<tokio::sync::mpsc::Receiver<InboundEvent>>,
    _stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

/// One RPC response, owned by the caller.
pub struct RpcResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

// =============================================================================
// WORKER
// =============================================================================

enum SessionCmd {
    Rpc {
        method: ZhtpMethod,
        path: String,
        body: Vec<u8>,
        reply: oneshot::Sender<Result<RpcResponse>>,
    },
    InboundOpen {
        path: String,
        reply: oneshot::Sender<Result<InboundStreamHandle>>,
    },
    Close,
}

enum InboundEvent {
    Frame(Vec<u8>),
    Closed,
    Error(String),
}

/// Spawn the per-session worker thread. The thread drives the QUIC connect,
/// UHP handshake, RPC loop, and inbound streams on the shared
/// `CLIENT_ENDPOINT_RUNTIME` before signalling readiness. Quinn ties the
/// endpoint driver to the runtime that created it; a per-session
/// current-thread runtime caused iOS `EPERM` on `Endpoint::connect`.
fn spawn_session_worker(
    addr: String,
    server_name: String,
    session_alpn: u8,
    identity: ZhtpIdentity,
    rx: tokio::sync::mpsc::Receiver<SessionCmd>,
    ready: oneshot::Sender<Result<()>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Quinn ties the endpoint driver to the runtime that created it.
        // Run the whole session (connect, handshake, RPC, inbound) on the
        // shared `CLIENT_ENDPOINT_RUNTIME` — a per-session current-thread
        // runtime causes iOS EPERM on `Endpoint::connect`.
        let runtime = match lib_network::client::client_endpoint_runtime() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = ready.send(Err(e.context("client_endpoint_runtime (stage=runtime)")));
                return;
            }
        };
        let handle = runtime.handle().clone();
        handle.block_on(async move {
            let trust = TrustConfig::bootstrap();
            let config = ZhtpClientConfig {
                allow_bootstrap: true,
                session_alpn,
            };
            let mut client = match ZhtpClient::new_with_config(identity, trust, config).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = ready.send(Err(
                        e.context("ZhtpClient::new_with_config (stage=client_init)")
                    ));
                    return;
                }
            };
            if let Err(e) = client.connect_with_sni(&addr, &server_name).await {
                let _ = ready.send(Err(e.context(format!(
                    "ZhtpClient::connect_with_sni addr={} sni={} alpn={}",
                    addr, server_name, session_alpn
                ))));
                return;
            }
            // Hand the open client to the loop and signal the caller
            // that the session is usable.
            let _ = ready.send(Ok(()));
            session_loop(client, rx).await;
        });
    })
}

async fn session_loop(client: ZhtpClient, mut rx: tokio::sync::mpsc::Receiver<SessionCmd>) {
    let client = Arc::new(client);
    while let Some(cmd) = rx.recv().await {
        match cmd {
            SessionCmd::Rpc {
                method,
                path,
                body,
                reply,
            } => {
                let c = client.clone();
                tokio::spawn(async move {
                    let r = do_rpc(&c, method, path, body).await;
                    let _ = reply.send(r);
                });
            }
            SessionCmd::InboundOpen { path, reply } => {
                let c = client.clone();
                tokio::spawn(async move {
                    let r = do_inbound_open(&c, path).await;
                    let _ = reply.send(r);
                });
            }
            SessionCmd::Close => break,
        }
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn do_rpc(
    client: &Arc<ZhtpClient>,
    method: ZhtpMethod,
    path: String,
    body: Vec<u8>,
) -> Result<RpcResponse> {
    let requester = Some(client.identity().id.clone());
    let request = build_request(method, path, body, requester)?;
    let response = client.request(request).await?;
    Ok(RpcResponse {
        status: response.status.code() as u16,
        body: response.body,
    })
}

async fn do_inbound_open(client: &Arc<ZhtpClient>, path: String) -> Result<InboundStreamHandle> {
    let requester = Some(client.identity().id.clone());
    let request = ZhtpRequest::get(path, requester)?;
    let (_send, mut recv, expected_id) = client
        .open_authenticated_stream(request)
        .await
        .context("open authenticated stream (stage=inbound)")?;

    let wire_response = read_response(&mut recv)
        .await
        .context("Failed to read inbound stream header (stage=inbound)")?;
    if wire_response.request_id != expected_id {
        return Err(anyhow!(
            "inbound stream: request_id mismatch (expected {}, got {}) (stage=inbound)",
            hex::encode(expected_id),
            wire_response.request_id_hex()
        ));
    }
    let status = wire_response.response.status.code() as u16;
    if !(200..300).contains(&status) {
        return Err(anyhow!(
            "inbound stream: server returned status {} (stage=inbound)",
            status
        ));
    }

    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<InboundEvent>(64);
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => return,
                frame = read_frame(&mut recv) => match frame {
                    Ok(Some(payload)) => {
                        if event_tx.send(InboundEvent::Frame(payload)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = event_tx.send(InboundEvent::Closed).await;
                        return;
                    }
                    Err(e) => {
                        let _ = event_tx.send(InboundEvent::Error(e.to_string())).await;
                        return;
                    }
                }
            }
        }
    });

    Ok(InboundStreamHandle {
        rx: std::sync::Mutex::new(event_rx),
        _stop_tx: Some(stop_tx),
    })
}

async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(_) => return Ok(None),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        return Err(anyhow!("invalid frame length {}", len));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

fn build_request(
    method: ZhtpMethod,
    path: String,
    body: Vec<u8>,
    requester: Option<lib_identity::IdentityId>,
) -> Result<ZhtpRequest> {
    match method {
        ZhtpMethod::Get => ZhtpRequest::get(path, requester),
        ZhtpMethod::Post => {
            ZhtpRequest::post(path, body, "application/json".to_string(), requester)
        }
        ZhtpMethod::Delete => ZhtpRequest::delete(path, requester),
        _ => Err(anyhow!("Unsupported method")),
    }
}

// =============================================================================
// Identity bridge
// =============================================================================

fn to_zhtp_identity(id: &Identity) -> Result<ZhtpIdentity> {
    let dilithium_pk: [u8; 2592] = id.public_key.as_slice().try_into().map_err(|_| {
        anyhow!(
            "public_key must be 2592 bytes, got {} (stage=identity)",
            id.public_key.len()
        )
    })?;
    let dilithium_sk: [u8; 4896] = if id.private_key.len() == 4896 {
        id.private_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("private_key 4896-byte conversion failed (stage=identity)"))?
    } else if id.private_key.len() == 4864 {
        // crystals-dilithium format; pad to pqcrypto's 4896-byte layout.
        let mut arr = [0u8; 4896];
        arr[..4864].copy_from_slice(&id.private_key);
        arr
    } else {
        return Err(anyhow!(
            "private_key must be 4864 or 4896 bytes, got {} (stage=identity)",
            id.private_key.len()
        ));
    };
    let kyber_pk: [u8; 1568] = id.kyber_public_key.as_slice().try_into().map_err(|_| {
        anyhow!(
            "kyber_public_key must be 1568 bytes, got {} (stage=identity)",
            id.kyber_public_key.len()
        )
    })?;
    let kyber_sk: [u8; 3168] = id.kyber_secret_key.as_slice().try_into().map_err(|_| {
        anyhow!(
            "kyber_secret_key must be 3168 bytes, got {} (stage=identity)",
            id.kyber_secret_key.len()
        )
    })?;

    // Device type matches mobile operational keys used for transport auth.
    // DID is derived from the Dilithium public key inside from_raw_keys.
    ZhtpIdentity::from_raw_keys(
        IdentityType::Device,
        dilithium_pk,
        dilithium_sk,
        kyber_pk,
        kyber_sk,
        id.device_id.clone(),
    )
    .map_err(|e| anyhow!("from_raw_keys: {} (stage=identity)", e))
}

// =============================================================================
// Pure Rust open (shared by FFI + tests — not a public crate API)
// =============================================================================

/// Open a persistent authenticated QUIC session (canonical UHP initiator).
///
/// **Blocking:** waits for QUIC connect + full UHP handshake on the caller
/// thread (via oneshot from the shared endpoint runtime). Callers must not
/// invoke this from a UI/main thread.
///
/// `alpn` must be `1` (`zhtp-uhp/2`). `sni` is the TLS server name (hostname);
/// dial host may be an IP after ZDNS bootstrap.
fn open_session(
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: u8,
    identity: &Identity,
) -> Result<*mut QuicSessionHandle> {
    clear_last_error();

    if host.is_empty() {
        set_last_error("args", "host is empty");
        return Err(anyhow!("host is empty (stage=args)"));
    }
    if alpn != 1 {
        set_last_error(
            "alpn",
            format!(
                "session_alpn must be 1 (zhtp-uhp/2), got {} — public ALPN has no UHP",
                alpn
            ),
        );
        return Err(anyhow!("invalid alpn {} (stage=alpn)", alpn));
    }

    let addr = format!("{}:{}", host, port);
    let server_name = match sni {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "zhtp-node".to_string(),
    };

    let zhtp_identity = match to_zhtp_identity(identity) {
        Ok(z) => z,
        Err(e) => {
            set_last_error_from_anyhow("identity", &e);
            return Err(e);
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<SessionCmd>(64);
    let (ready_tx, ready_rx) = oneshot::channel::<Result<()>>();
    let worker = spawn_session_worker(addr, server_name, alpn, zhtp_identity, rx, ready_tx);

    match ready_rx.blocking_recv() {
        Ok(Ok(())) => {
            clear_last_error();
            Ok(Box::into_raw(Box::new(QuicSessionHandle {
                tx,
                _worker: Some(worker),
            })))
        }
        Ok(Err(e)) => {
            set_last_error_from_anyhow("uhp_handshake", &e);
            drop(tx);
            let _ = worker.join();
            Err(e)
        }
        Err(_) => {
            set_last_error(
                "runtime",
                "session worker exited without reporting connect result",
            );
            drop(tx);
            let _ = worker.join();
            Err(anyhow!(
                "session worker dropped ready channel (stage=runtime)"
            ))
        }
    }
}

// =============================================================================
// FFI EXPORTS
// =============================================================================

/// Open a persistent QUIC session.
///
/// `alpn`: must be `1` (`zhtp-uhp/2`, authenticated UHP). Public ALPN (`0`)
/// is not supported here — gateways treat `zhtp-public/1` as no-UHP read-only.
///
/// **Blocking** until connect + UHP complete — call off the UI thread.
///
/// Returns null on failure — call `zhtp_quic_session_last_error` (any thread;
/// process-global last-writer-wins) for details.
#[no_mangle]
pub extern "C" fn zhtp_quic_session_open(
    host: *const c_char,
    port: u16,
    sni: *const c_char,
    _spki_pin_hex: *const c_char,
    alpn: u8,
    identity: *const crate::IdentityHandle,
) -> *mut QuicSessionHandle {
    clear_last_error();

    if host.is_null() {
        set_last_error("args", "host pointer is null");
        return std::ptr::null_mut();
    }
    if identity.is_null() {
        set_last_error("args", "identity pointer is null");
        return std::ptr::null_mut();
    }

    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("args", "host is not valid UTF-8");
            return std::ptr::null_mut();
        }
    };

    let sni_opt = if sni.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(sni) }.to_str() {
            Ok(s) if !s.is_empty() => Some(s),
            Ok(_) => None,
            Err(_) => {
                set_last_error("args", "sni is not valid UTF-8");
                return std::ptr::null_mut();
            }
        }
    };

    let id = unsafe { (*identity).inner.clone() };

    match open_session(host_str, port, sni_opt, alpn, &id) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Last structured error from session open / inbound / rpc.
///
/// Process-global (not thread-local): readable from any OS thread after a
/// failed call on another thread (Dart isolate / JNI pool safe). Concurrent
/// failures last-writer-wins.
///
/// Format: `stage=<name>: <message chain>`.
/// Returns a newly allocated C string; free with
/// `zhtp_quic_session_last_error_free`. Null if no error stored.
#[no_mangle]
pub extern "C" fn zhtp_quic_session_last_error() -> *mut c_char {
    match current_error_message() {
        Some(msg) => match CString::new(msg) {
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Stage token only (`uhp_handshake`, `quic`, `resolve`, …). Static C string
/// — do not free. Returns `"none"` when no error is stored. Same process-global
/// contract as `zhtp_quic_session_last_error`.
#[no_mangle]
pub extern "C" fn zhtp_quic_session_last_error_stage() -> *const c_char {
    stage_as_c_str(current_stage())
}

/// Free a string returned by `zhtp_quic_session_last_error`.
#[no_mangle]
pub extern "C" fn zhtp_quic_session_last_error_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

/// Issue an RPC on the session. Each call opens a new bidi stream and runs
/// concurrently with other RPCs / inbound streams.
#[no_mangle]
pub extern "C" fn zhtp_quic_session_rpc(
    session: *mut QuicSessionHandle,
    method: *const c_char,
    path: *const c_char,
    _headers_json: *const c_char,
    body_ptr: *const u8,
    body_len: usize,
) -> *mut RpcResponse {
    clear_last_error();
    if session.is_null() || method.is_null() || path.is_null() {
        set_last_error("args", "session/method/path pointer is null");
        return std::ptr::null_mut();
    }
    let session = unsafe { &*session };

    let method_str = match unsafe { CStr::from_ptr(method) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("args", "method is not valid UTF-8");
            return std::ptr::null_mut();
        }
    };
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("args", "path is not valid UTF-8");
            return std::ptr::null_mut();
        }
    };
    let method = match method_str.to_ascii_uppercase().as_str() {
        "GET" => ZhtpMethod::Get,
        "POST" => ZhtpMethod::Post,
        "DELETE" => ZhtpMethod::Delete,
        _ => {
            set_last_error("args", format!("unsupported method '{}'", method_str));
            return std::ptr::null_mut();
        }
    };

    let body: Vec<u8> = if body_ptr.is_null() || body_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(body_ptr, body_len) }.to_vec()
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    if session
        .tx
        .blocking_send(SessionCmd::Rpc {
            method,
            path: path_str,
            body,
            reply: reply_tx,
        })
        .is_err()
    {
        set_last_error("rpc", "session channel closed");
        return std::ptr::null_mut();
    }

    match reply_rx.blocking_recv() {
        Ok(Ok(resp)) => Box::into_raw(Box::new(resp)),
        Ok(Err(e)) => {
            set_last_error_from_anyhow("rpc", &e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("rpc", "rpc worker dropped reply channel");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_rpc_status(r: *const RpcResponse) -> u16 {
    if r.is_null() {
        return 0;
    }
    unsafe { (*r).status }
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_rpc_body(
    r: *const RpcResponse,
    out_len: *mut usize,
) -> *const u8 {
    if r.is_null() || out_len.is_null() {
        return std::ptr::null();
    }
    let resp = unsafe { &*r };
    unsafe { *out_len = resp.body.len() };
    resp.body.as_ptr()
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_rpc_free(r: *mut RpcResponse) {
    if !r.is_null() {
        drop(unsafe { Box::from_raw(r) });
    }
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_inbound_open(
    session: *mut QuicSessionHandle,
    path: *const c_char,
) -> *mut InboundStreamHandle {
    clear_last_error();
    if session.is_null() || path.is_null() {
        set_last_error("args", "session/path pointer is null");
        return std::ptr::null_mut();
    }
    let session = unsafe { &*session };
    let path = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("args", "path is not valid UTF-8");
            return std::ptr::null_mut();
        }
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    if session
        .tx
        .blocking_send(SessionCmd::InboundOpen {
            path,
            reply: reply_tx,
        })
        .is_err()
    {
        set_last_error("inbound", "session channel closed");
        return std::ptr::null_mut();
    }
    match reply_rx.blocking_recv() {
        Ok(Ok(h)) => Box::into_raw(Box::new(h)),
        Ok(Err(e)) => {
            set_last_error_from_anyhow("inbound", &e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("inbound", "inbound open worker dropped reply");
            std::ptr::null_mut()
        }
    }
}

/// Read one frame from the inbound stream.
/// Returns 0 ok, 1 timeout, -1 closed by peer, -2 transport error.
#[no_mangle]
pub extern "C" fn zhtp_quic_session_inbound_read(
    stream: *mut InboundStreamHandle,
    timeout_ms: u32,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    clear_last_error();
    if stream.is_null() || out_ptr.is_null() || out_len.is_null() {
        set_last_error("args", "inbound_read null pointer");
        return -2;
    }
    let stream = unsafe { &*stream };
    let mut rx = match stream.rx.lock() {
        Ok(r) => r,
        Err(_) => {
            set_last_error("inbound", "inbound stream mutex poisoned");
            return -2;
        }
    };

    let event = if timeout_ms == 0 {
        rx.blocking_recv()
    } else {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms as u64);
        loop {
            match rx.try_recv() {
                Ok(ev) => break Some(ev),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    if std::time::Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break None,
            }
        }
    };

    match event {
        Some(InboundEvent::Frame(payload)) => {
            let boxed = payload.into_boxed_slice();
            let len = boxed.len();
            let ptr = Box::into_raw(boxed) as *const u8;
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            0
        }
        Some(InboundEvent::Closed) => -1,
        Some(InboundEvent::Error(e)) => {
            set_last_error("inbound", e);
            -2
        }
        None => 1, // timeout / empty — last_error already cleared
    }
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_inbound_frame_free(ptr: *const u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr as *mut u8, len));
        }
    }
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_inbound_close(stream: *mut InboundStreamHandle) {
    if !stream.is_null() {
        drop(unsafe { Box::from_raw(stream) });
    }
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_close(session: *mut QuicSessionHandle) {
    if session.is_null() {
        return;
    }
    let handle = unsafe { Box::from_raw(session) };
    let _ = handle.tx.blocking_send(SessionCmd::Close);
    drop(handle);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity;
    use lib_network::handshake::PqcCapability;
    use lib_network::protocols::quic_handshake::quic_uhp_capabilities;

    #[test]
    fn quic_uhp_capabilities_is_minimal_production_shape() {
        let caps = quic_uhp_capabilities();
        assert_eq!(caps.protocols, vec!["quic".to_string()]);
        assert_eq!(caps.pqc_capability, PqcCapability::Kyber1024Dilithium5);
    }

    #[test]
    fn last_error_reports_bad_alpn() {
        let id = generate_identity("test-device".into()).expect("identity");
        let err = open_session("127.0.0.1", 9334, Some("g1.example"), 0, &id)
            .expect_err("public alpn must fail");
        assert!(err.to_string().contains("alpn"), "{err}");
        assert_eq!(current_stage(), "alpn");
        let msg = current_error_message().expect("last error");
        assert!(msg.starts_with("stage=alpn:"), "{msg}");
    }

    #[test]
    fn last_error_reports_identity_key_length() {
        let mut id = generate_identity("test-device".into()).expect("identity");
        id.public_key.truncate(10);
        let err = open_session("127.0.0.1", 9334, Some("g1.example"), 1, &id)
            .expect_err("bad key must fail");
        assert!(
            err.to_string().contains("2592") || err.to_string().contains("identity"),
            "{err}"
        );
        assert_eq!(current_stage(), "identity");
    }

    #[test]
    fn last_error_is_readable_across_threads() {
        // Contract: open on T1, last_error on T2 (Dart isolate / JNI pool).
        let id = generate_identity("cross-thread".into()).expect("identity");
        open_session("127.0.0.1", 9334, Some("g1.example"), 0, &id).expect_err("alpn");
        let reader = std::thread::spawn(|| {
            (
                current_stage().to_string(),
                current_error_message().expect("cross-thread last error"),
            )
        });
        let (stage, msg) = reader.join().expect("join");
        assert_eq!(stage, "alpn");
        assert!(msg.starts_with("stage=alpn:"), "{msg}");
    }

    #[test]
    fn stage_table_c_str_covers_every_token() {
        for (name, cstr) in STAGES {
            assert!(
                cstr.ends_with(&[0]),
                "stage {name} C string must be NUL-terminated"
            );
            let body = &cstr[..cstr.len() - 1];
            assert_eq!(
                std::str::from_utf8(body).expect("utf8"),
                *name,
                "C string body must match stage name"
            );
            let ptr = stage_as_c_str(name);
            let got = unsafe { CStr::from_ptr(ptr) }.to_str().expect("c str");
            assert_eq!(got, *name);
        }
        assert_eq!(
            unsafe {
                CStr::from_ptr(stage_as_c_str("not-a-stage"))
                    .to_str()
                    .unwrap()
            },
            "none"
        );
    }

    #[test]
    fn classify_stage_parses_markers() {
        assert_eq!(
            classify_stage("UHP v2 handshake failed (stage=uhp_handshake)"),
            Some("uhp_handshake")
        );
        assert_eq!(
            classify_stage("Failed to resolve address: x (stage=resolve)"),
            Some("resolve")
        );
        assert_eq!(
            classify_stage("Failed to read length prefix byte 0: connection lost"),
            Some("uhp_handshake")
        );
    }

    /// Live session open against a running node (optional).
    ///
    /// ```text
    /// ZHTP_SESSION_TEST_HOST=77.42.37.161 ZHTP_SESSION_TEST_SNI=zhtp-node \
    ///   cargo test -p lib-client live_session_open -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires reachable ZHTP node (set ZHTP_SESSION_TEST_HOST)"]
    fn live_session_open_and_health_rpc() {
        let host = std::env::var("ZHTP_SESSION_TEST_HOST").expect("ZHTP_SESSION_TEST_HOST");
        let port: u16 = std::env::var("ZHTP_SESSION_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(9334);
        let sni = std::env::var("ZHTP_SESSION_TEST_SNI").unwrap_or_else(|_| "zhtp-node".into());
        let id = generate_identity("msg-node-001-live".into()).expect("identity");

        let ptr = open_session(&host, port, Some(&sni), 1, &id).unwrap_or_else(|e| {
            panic!(
                "session open failed: {:#} last={}",
                e,
                current_error_message().unwrap_or_default()
            );
        });
        assert!(!ptr.is_null());

        let session = unsafe { &*ptr };
        let (reply_tx, reply_rx) = oneshot::channel();
        session
            .tx
            .blocking_send(SessionCmd::Rpc {
                method: ZhtpMethod::Get,
                path: "/api/v1/protocol/health".into(),
                body: Vec::new(),
                reply: reply_tx,
            })
            .expect("send rpc");
        let resp = reply_rx
            .blocking_recv()
            .expect("reply")
            .expect("health rpc");
        assert!(
            (200..300).contains(&resp.status),
            "health status {}",
            resp.status
        );

        zhtp_quic_session_close(ptr);
    }
}
