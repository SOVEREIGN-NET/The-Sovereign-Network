//! Cross-Platform ZHTP Client Library
//!
//! Single Rust implementation that compiles to:
//! - iOS/macOS (via UniFFI → Swift bindings)
//! - Android (via UniFFI → Kotlin bindings)
//! - Web (via wasm-bindgen → TypeScript)
//! - CLI (native Rust)
//!
//! # Features
//!
//! - **Identity Generation**: Client-side Dilithium5 + Kyber1024 key generation
//! - **UHP v2 Handshake**: 3-leg mutual authentication protocol
//! - **Session Encryption**: ChaCha20-Poly1305 authenticated encryption
//! - **ZHTP Protocol**: CBOR serialization with wire format handling
//!
//! # Security
//!
//! Private keys are generated locally and NEVER leave the device.
//! Only public keys are sent to the server for registration.
//!
//! # Example
//!
//! ```ignore
//! use lib_client::{generate_identity, HandshakeState, Session};
//!
//! // Generate identity (keys stay on device)
//! let identity = generate_identity("device-123".into())?;
//!
//! // Perform UHP v2 handshake
//! let mut handshake = HandshakeState::new(identity.clone(), channel_binding);
//! let client_hello = handshake.create_client_hello()?;
//! // send client_hello, receive server_hello
//! let client_finish = handshake.process_server_hello(&server_hello_data)?;
//! // send client_finish
//! let result = handshake.finalize()?;
//!
//! // Create encrypted session
//! let session = Session::new(result.session_key, result.peer_did)?;
//! let encrypted = session.encrypt(&plaintext)?;
//! ```

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod request;
pub mod session;
mod bip39_wordlist;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-exports for convenience
pub use crypto::{Blake3, Dilithium5, Kyber1024};
pub use error::{ClientError, Result};
pub use handshake::{HandshakeResult, HandshakeState};
pub use identity::{generate_identity, get_public_identity, get_seed_phrase, sign_registration_proof, Identity, PublicIdentity};
pub use request::{
    create_zhtp_frame, deserialize_response, parse_zhtp_frame, serialize_request, ZhtpHeaders,
    ZhtpRequest, ZhtpResponse,
};
pub use session::Session;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// UHP protocol version
pub const UHP_VERSION: u8 = 2;

/// ZHTP wire protocol version
pub const ZHTP_WIRE_VERSION: u8 = 1;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

// iOS compatibility: provide stub for ___chkstk_darwin (PQC assembly references this)
#[no_mangle]
pub extern "C" fn ___chkstk_darwin() {}

// =============================================================================
// C FFI Exports for iOS (manual FFI without uniffi-bindgen)
// =============================================================================

/// Opaque handle to an Identity
pub struct IdentityHandle {
    inner: Identity,
}

/// Generate a new identity. Returns a pointer to IdentityHandle.
/// Caller must free with `zhtp_client_identity_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_generate_identity(
    device_id: *const std::ffi::c_char,
) -> *mut IdentityHandle {
    let device_id = unsafe {
        if device_id.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(device_id).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    match generate_identity(device_id) {
        Ok(identity) => Box::into_raw(Box::new(IdentityHandle { inner: identity })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an identity handle
#[no_mangle]
pub extern "C" fn zhtp_client_identity_free(handle: *mut IdentityHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

/// Get the DID string from an identity. Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_did(handle: *const IdentityHandle) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };
    match std::ffi::CString::new(identity.did.clone()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the device ID from an identity. Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_device_id(handle: *const IdentityHandle) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };
    match std::ffi::CString::new(identity.device_id.clone()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the 24-word seed phrase from an identity. Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_seed_phrase(handle: *const IdentityHandle) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };
    match identity::get_seed_phrase(identity) {
        Ok(phrase) => match std::ffi::CString::new(phrase) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string returned by the library
#[no_mangle]
pub extern "C" fn zhtp_client_string_free(s: *mut std::ffi::c_char) {
    if !s.is_null() {
        unsafe { drop(std::ffi::CString::from_raw(s)) };
    }
}

/// Buffer for returning byte arrays
#[repr(C)]
pub struct ByteBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Free a ByteBuffer
#[no_mangle]
pub extern "C" fn zhtp_client_buffer_free(buf: ByteBuffer) {
    if !buf.data.is_null() && buf.len > 0 {
        unsafe {
            drop(Vec::from_raw_parts(buf.data, buf.len, buf.len));
        }
    }
}

/// Alias for zhtp_client_string_free (alternative naming convention)
#[no_mangle]
pub extern "C" fn zhtp_client_free_string(s: *mut std::ffi::c_char) {
    zhtp_client_string_free(s);
}

/// Alias for zhtp_client_buffer_free (alternative naming convention)
#[no_mangle]
pub extern "C" fn zhtp_client_free_bytes(buf: ByteBuffer) {
    zhtp_client_buffer_free(buf);
}

/// Get public key from identity
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_public_key(handle: *const IdentityHandle) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let identity = unsafe { &(*handle).inner };
    let mut bytes = identity.public_key.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

/// Get node ID from identity
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_node_id(handle: *const IdentityHandle) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let identity = unsafe { &(*handle).inner };
    let mut bytes = identity.node_id.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

/// Get Kyber public key from identity
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_kyber_public_key(handle: *const IdentityHandle) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let identity = unsafe { &(*handle).inner };
    let mut bytes = identity.kyber_public_key.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

/// Get created_at timestamp from identity
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_created_at(handle: *const IdentityHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    let identity = unsafe { &(*handle).inner };
    identity.created_at
}

/// Sign registration proof. Returns signature bytes.
#[no_mangle]
pub extern "C" fn zhtp_client_sign_registration_proof(
    handle: *const IdentityHandle,
    timestamp: u64,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let identity = unsafe { &(*handle).inner };
    match sign_registration_proof(identity, timestamp) {
        Ok(mut sig) => {
            let buf = ByteBuffer {
                data: sig.as_mut_ptr(),
                len: sig.len(),
            };
            std::mem::forget(sig);
            buf
        }
        Err(_) => ByteBuffer { data: std::ptr::null_mut(), len: 0 },
    }
}

/// Sign UHP handshake challenge. Returns signature bytes.
/// Private keys stay in Rust - never exposed to caller.
#[no_mangle]
pub extern "C" fn zhtp_client_sign_uhp_challenge(
    handle: *const IdentityHandle,
    challenge: *const u8,
    challenge_len: usize,
) -> ByteBuffer {
    if handle.is_null() || challenge.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }

    let identity = unsafe { &(*handle).inner };
    let challenge_bytes = unsafe { std::slice::from_raw_parts(challenge, challenge_len) };

    // Use generic message signing to sign the UHP challenge
    // The private_key stays in Rust and is never exposed
    match identity::sign_message(identity, challenge_bytes) {
        Ok(mut sig) => {
            let buf = ByteBuffer {
                data: sig.as_mut_ptr(),
                len: sig.len(),
            };
            std::mem::forget(sig);
            buf
        }
        Err(_) => ByteBuffer { data: std::ptr::null_mut(), len: 0 },
    }
}

/// Serialize identity to JSON. Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_identity_serialize(handle: *const IdentityHandle) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };
    match identity::serialize_identity(identity) {
        Ok(json) => match std::ffi::CString::new(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Deserialize identity from JSON. Returns handle or null on error.
#[no_mangle]
pub extern "C" fn zhtp_client_identity_deserialize(json: *const std::ffi::c_char) -> *mut IdentityHandle {
    let json = unsafe {
        if json.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(json).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    match identity::deserialize_identity(json) {
        Ok(identity) => Box::into_raw(Box::new(IdentityHandle { inner: identity })),
        Err(_) => std::ptr::null_mut(),
    }
}
