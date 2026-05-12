//! Persistent QUIC session FFI — handles, multiplexed RPC, server-push inbound stream.
//!
//! Implements T1/T2/T3 of messaging push epic. Wraps the existing
//! `lib_network::client::ZhtpClient` so the FFI inherits the UHP handshake,
//! auth context, and wire framing without re-implementing transport.
//!
//! Threading: each handle owns a dedicated Tokio current-thread runtime on a
//! worker thread. FFI callers may call from any thread; commands route through
//! a tokio mpsc queue.

#![cfg(not(target_arch = "wasm32"))]

use std::ffi::{c_char, CStr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::AsyncReadExt;
use tokio::sync::oneshot;

use lib_identity::types::IdentityType;
use lib_identity::ZhtpIdentity;
use lib_network::client::{ZhtpClient, ZhtpClientConfig};
use lib_network::web4::trust::TrustConfig;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest};
use lib_protocols::wire::read_response;

use crate::identity::Identity;

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

/// Spawn the per-session worker thread. The thread builds its own
/// tokio runtime, then **does the QUIC connect + UHP handshake on
/// that runtime** before signalling readiness. This is load-bearing:
/// Quinn's connection driver is tied to the runtime that called
/// `Endpoint::connect`, so the connect and all subsequent RPCs MUST
/// share a runtime. Previously the connect happened on a temporary
/// runtime in `zhtp_quic_session_open` that was dropped before the
/// worker started — that left the connection's I/O driver dead and
/// every subsequent `open_bi()` returned `"closed"`.
fn spawn_session_worker(
    addr: String,
    identity: ZhtpIdentity,
    rx: tokio::sync::mpsc::Receiver<SessionCmd>,
    ready: oneshot::Sender<Result<()>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = ready.send(Err(anyhow!("runtime build failed: {}", e)));
                return;
            }
        };
        runtime.block_on(async move {
            let trust = TrustConfig::bootstrap();
            let config = ZhtpClientConfig { allow_bootstrap: true };
            let mut client = match ZhtpClient::new_with_config(identity, trust, config).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = ready.send(Err(e.context("ZhtpClient::new_with_config")));
                    return;
                }
            };
            if let Err(e) = client.connect(&addr).await {
                let _ = ready.send(Err(e.context("ZhtpClient::connect")));
                return;
            }
            // Hand the open client to the loop and signal the caller
            // that the session is usable.
            let _ = ready.send(Ok(()));
            session_loop(client, rx).await;
        });
    })
}

async fn session_loop(
    client: ZhtpClient,
    mut rx: tokio::sync::mpsc::Receiver<SessionCmd>,
) {
    let client = Arc::new(client);
    while let Some(cmd) = rx.recv().await {
        match cmd {
            SessionCmd::Rpc { method, path, body, reply } => {
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

async fn do_inbound_open(
    client: &Arc<ZhtpClient>,
    path: String,
) -> Result<InboundStreamHandle> {
    let requester = Some(client.identity().id.clone());
    let request = ZhtpRequest::get(path, requester)?;
    let (_send, mut recv, expected_id) =
        client.open_authenticated_stream(request).await?;

    let wire_response = read_response(&mut recv)
        .await
        .context("Failed to read inbound stream header")?;
    if wire_response.request_id != expected_id {
        return Err(anyhow!(
            "inbound stream: request_id mismatch (expected {}, got {})",
            hex::encode(expected_id),
            wire_response.request_id_hex()
        ));
    }
    let status = wire_response.response.status.code() as u16;
    if !(200..300).contains(&status) {
        return Err(anyhow!(
            "inbound stream: server returned status {}",
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
        ZhtpMethod::Post => ZhtpRequest::post(
            path,
            body,
            "application/json".to_string(),
            requester,
        ),
        ZhtpMethod::Delete => ZhtpRequest::delete(path, requester),
        _ => Err(anyhow!("Unsupported method")),
    }
}

// =============================================================================
// Identity bridge
// =============================================================================

fn to_zhtp_identity(id: &Identity) -> Result<ZhtpIdentity> {
    let dilithium_pk: [u8; 2592] = id
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public_key must be 2592 bytes"))?;
    let dilithium_sk: [u8; 4896] = if id.private_key.len() == 4896 {
        id.private_key.as_slice().try_into().unwrap()
    } else if id.private_key.len() == 4864 {
        // crystals-dilithium format; pad to pqcrypto's 4896-byte layout.
        let mut arr = [0u8; 4896];
        arr[..4864].copy_from_slice(&id.private_key);
        arr
    } else {
        return Err(anyhow!(
            "private_key must be 4864 or 4896 bytes, got {}",
            id.private_key.len()
        ));
    };
    let kyber_pk: [u8; 1568] = id
        .kyber_public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("kyber_public_key must be 1568 bytes"))?;
    let kyber_sk: [u8; 3168] = id
        .kyber_secret_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("kyber_secret_key must be 3168 bytes"))?;

    ZhtpIdentity::from_raw_keys(
        IdentityType::Device,
        dilithium_pk,
        dilithium_sk,
        kyber_pk,
        kyber_sk,
        id.device_id.clone(),
    )
}

// =============================================================================
// FFI EXPORTS
// =============================================================================

/// Open a persistent QUIC session.
/// `alpn`: 0 = zhtp-public/1, 1 = zhtp-uhp/2 (authenticated).
/// Returns null on failure.
#[no_mangle]
pub extern "C" fn zhtp_quic_session_open(
    host: *const c_char,
    port: u16,
    _sni: *const c_char,
    _spki_pin_hex: *const c_char,
    alpn: u8,
    identity: *const crate::IdentityHandle,
) -> *mut QuicSessionHandle {
    if host.is_null() {
        return std::ptr::null_mut();
    }
    if alpn == 1 && identity.is_null() {
        return std::ptr::null_mut();
    }

    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };
    let addr = format!("{}:{}", host_str, port);

    let id = if identity.is_null() {
        match crate::identity::generate_identity("anon-device".to_string()) {
            Ok(id) => id,
            Err(_) => return std::ptr::null_mut(),
        }
    } else {
        unsafe { (*identity).inner.clone() }
    };

    let zhtp_identity = match to_zhtp_identity(&id) {
        Ok(z) => z,
        Err(_) => return std::ptr::null_mut(),
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<SessionCmd>(64);
    let (ready_tx, ready_rx) = oneshot::channel::<Result<()>>();
    let worker = spawn_session_worker(addr, zhtp_identity, rx, ready_tx);

    // Block until the worker has finished the QUIC connect + UHP
    // handshake. Returning the handle before the connection is
    // ready would race the next rpc() against an unconnected
    // client and produce the same `closed` errors the temp-runtime
    // bug used to.
    match ready_rx.blocking_recv() {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            // Worker exits naturally once we drop the tx (its rx ends).
            drop(tx);
            let _ = worker.join();
            return std::ptr::null_mut();
        }
        Err(_) => return std::ptr::null_mut(),
    }

    Box::into_raw(Box::new(QuicSessionHandle {
        tx,
        _worker: Some(worker),
    }))
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
    if session.is_null() || method.is_null() || path.is_null() {
        return std::ptr::null_mut();
    }
    let session = unsafe { &*session };

    let method_str = match unsafe { CStr::from_ptr(method) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };
    let method = match method_str.to_ascii_uppercase().as_str() {
        "GET" => ZhtpMethod::Get,
        "POST" => ZhtpMethod::Post,
        "DELETE" => ZhtpMethod::Delete,
        _ => return std::ptr::null_mut(),
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
        return std::ptr::null_mut();
    }

    match reply_rx.blocking_recv() {
        Ok(Ok(resp)) => Box::into_raw(Box::new(resp)),
        _ => std::ptr::null_mut(),
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
    if session.is_null() || path.is_null() {
        return std::ptr::null_mut();
    }
    let session = unsafe { &*session };
    let path = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    if session
        .tx
        .blocking_send(SessionCmd::InboundOpen { path, reply: reply_tx })
        .is_err()
    {
        return std::ptr::null_mut();
    }
    match reply_rx.blocking_recv() {
        Ok(Ok(h)) => Box::into_raw(Box::new(h)),
        _ => std::ptr::null_mut(),
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
    if stream.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -2;
    }
    let stream = unsafe { &*stream };
    let mut rx = match stream.rx.lock() {
        Ok(r) => r,
        Err(_) => return -2,
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
        Some(InboundEvent::Error(_)) => -2,
        None => 1,
    }
}

#[no_mangle]
pub extern "C" fn zhtp_quic_session_inbound_frame_free(ptr: *const u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                ptr as *mut u8,
                len,
            ));
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
