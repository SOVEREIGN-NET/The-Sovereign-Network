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
pub mod token_tx;
mod bip39_wordlist;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-exports for convenience
pub use crypto::{Blake3, Dilithium5, Kyber1024};
pub use error::{ClientError, Result};
pub use handshake::{HandshakeResult, HandshakeState};
pub use identity::{
    build_migrate_identity_request, build_migrate_identity_request_json,
    export_keystore_base64, generate_identity, get_public_identity, get_seed_phrase,
    restore_identity_from_phrase, sign_registration_proof, Identity, MigrateIdentityRequestPayload,
    PublicIdentity,
};
pub use request::{
    create_zhtp_frame, deserialize_response, parse_zhtp_frame, serialize_request, ZhtpHeaders,
    ZhtpRequest, ZhtpResponse,
};
pub use session::Session;
pub use token_tx::{
    // Generic contract transaction builder
    build_contract_transaction,
    // Token-specific (backward compatible)
    build_burn_tx, build_create_token_tx, build_mint_tx, build_transfer_tx,
    // Domain-specific (new JSON-based API)
    build_domain_register_request, build_domain_update_request, build_domain_transfer_request,
    // Domain-specific (deprecated, use *_request functions instead)
    build_domain_register_tx, build_domain_update_tx, build_domain_transfer_tx,
    // Param types for serialization
    CreateTokenParams, MintParams, TransferParams, BurnParams,
    DomainRegisterParams, DomainUpdateParams, DomainTransferParams, ContentMapping,
};
// Re-export ContractType for FFI callers
pub use lib_blockchain::types::ContractType;

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

/// Opaque handle to a HandshakeState
pub struct HandshakeStateHandle {
    inner: HandshakeState,
}

/// Opaque handle to a HandshakeResult
pub struct HandshakeResultHandle {
    inner: HandshakeResult,
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

/// Restore identity from a 24-word seed phrase. Returns a pointer to IdentityHandle.
/// Caller must free with `zhtp_client_identity_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_restore_identity_from_phrase(
    phrase: *const std::ffi::c_char,
    device_id: *const std::ffi::c_char,
) -> *mut IdentityHandle {
    let phrase = unsafe {
        if phrase.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(phrase).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let device_id = unsafe {
        if device_id.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(device_id).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    match restore_identity_from_phrase(&phrase, device_id) {
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

/// Get Dilithium secret key from identity (for UHP handshake)
/// SECURITY: This key should only be used for signing operations on-device.
/// It should NEVER be transmitted over any network.
#[deprecated(note = "Use zhtp_client_handshake_new() instead — keeps secret keys inside Rust")]
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_dilithium_secret_key(handle: *const IdentityHandle) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let identity = unsafe { &(*handle).inner };
    let mut bytes = identity.private_key.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

/// Get Kyber secret key from identity (for UHP handshake key exchange)
/// SECURITY: This key should only be used for decapsulation on-device.
/// It should NEVER be transmitted over any network.
#[deprecated(note = "Use zhtp_client_handshake_new() instead — keeps secret keys inside Rust")]
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_kyber_secret_key(handle: *const IdentityHandle) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let identity = unsafe { &(*handle).inner };
    let mut bytes = identity.kyber_secret_key.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

/// Get master seed from identity (for key derivation)
/// SECURITY: This seed should only be used for local key derivation.
/// It should NEVER be transmitted over any network.
#[deprecated(note = "Use zhtp_client_handshake_new() instead — keeps secret keys inside Rust")]
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_master_seed(handle: *const IdentityHandle) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let identity = unsafe { &(*handle).inner };
    // Legacy API name: returns 32-byte recovery entropy (mnemonic-encodable).
    let mut bytes = identity.recovery_entropy.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
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

/// Sign arbitrary message bytes. Returns signature bytes.
/// Use for migration, custom auth, etc. Caller must free with `zhtp_client_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_sign_message(
    handle: *const IdentityHandle,
    message: *const u8,
    message_len: usize,
) -> ByteBuffer {
    if handle.is_null() || message.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }

    let identity = unsafe { &(*handle).inner };
    let message_bytes = unsafe { std::slice::from_raw_parts(message, message_len) };

    match identity::sign_message(identity, message_bytes) {
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

/// Export identity as base64-encoded keystore tarball for CI/CD deployment.
///
/// Creates a tar.gz archive containing keystore files compatible with zhtp-cli
/// and the deploy-site GitHub Action.
///
/// SECURITY: The output contains private keys! Store as a GitHub secret.
///
/// Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_export_keystore_base64(handle: *const IdentityHandle) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };
    match identity::export_keystore_base64(identity) {
        Ok(b64) => match std::ffi::CString::new(b64) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Serialize identity to JSON format compatible with ZhtpIdentity::from_serialized().
///
/// This creates the FULL format expected by lib-identity for UHP handshakes.
/// The uhp-ffi crate calls ZhtpIdentity::from_serialized() which requires all these fields.
///
/// Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_identity_to_handshake_json(handle: *const IdentityHandle) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };

    // Compute key_id = Blake3(dilithium_public_key)
    let key_id = crypto::Blake3::hash(&identity.public_key);

    // Extract identity ID from DID (format: "did:zhtp:{id_hex}")
    let id_hex = identity.did.strip_prefix("did:zhtp:").unwrap_or(&identity.did);
    let id_bytes: Vec<u8> = hex::decode(id_hex).unwrap_or_else(|_| key_id.to_vec());

    // Generate dao_member_id from DID (deterministic)
    let dao_member_id = format!("dao:{}", id_hex);

    // NodeId in lib-identity has 3 fields: bytes, creation_nonce, network_genesis
    // We need to pad the raw node_id bytes into the proper NodeId struct format
    let node_id_bytes: [u8; 32] = if identity.node_id.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&identity.node_id[..32]);
        arr
    } else {
        let mut arr = [0u8; 32];
        arr[..identity.node_id.len()].copy_from_slice(&identity.node_id);
        arr
    };

    // Create proper NodeId struct format for serialization
    let zero_bytes: [u8; 32] = [0u8; 32];
    let node_id_struct = serde_json::json!({
        "bytes": node_id_bytes,
        "creation_nonce": zero_bytes,
        "network_genesis": zero_bytes
    });

    // Convert key_id to [u8; 32] array format
    let key_id_arr: [u8; 32] = {
        let mut arr = [0u8; 32];
        let src = key_id.as_slice();
        let len = std::cmp::min(src.len(), 32);
        arr[..len].copy_from_slice(&src[..len]);
        arr
    };

    // Build the FULL ZhtpIdentity format for from_serialized()
    // IMPORTANT: Using "Device" identity_type because "Human" requires age and jurisdiction
    // which mobile clients don't have. Device type avoids this requirement.
    let zhtp_identity = serde_json::json!({
        // Required fields
        "id": id_bytes,
        "did": identity.did,
        "identity_type": "Device",  // NOT "Human" - Human requires age/jurisdiction
        "public_key": {
            "dilithium_pk": identity.public_key,
            "kyber_pk": identity.kyber_public_key,
            "key_id": key_id_arr
        },
        "node_id": node_id_struct,
        "device_node_ids": {
            identity.device_id.clone(): node_id_struct
        },
        "primary_device": identity.device_id,
        "dao_member_id": dao_member_id,
        "ownership_proof": {
            "proof_system": "dilithium-pop-placeholder-v0",
            "proof_data": [],
            "public_inputs": id_bytes.clone(),
            "verification_key": identity.public_key.clone(),
            "plonky2_proof": null,
            "proof": []
        },

        // Optional fields with defaults
        "credentials": {},
        "metadata": {},
        "attestations": [],
        "reputation": 100,  // Device default reputation
        "access_level": "Standard",
        "age": null,
        "jurisdiction": null,
        "citizenship_verified": false,
        "dao_voting_power": 0,
        "private_data_id": null,
        "created_at": identity.created_at,
        "last_active": identity.created_at,
        "recovery_keys": [],
        "did_document_hash": null,
        "owner_identity_id": null,
        "reward_wallet_id": null
    });

    match serde_json::to_string(&zhtp_identity) {
        Ok(json) => match std::ffi::CString::new(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

// =============================================================================
// Handshake FFI Exports
// =============================================================================

/// Create a new HandshakeState from an identity and channel binding.
/// Returns a pointer to HandshakeStateHandle, or null on error.
/// Caller must free with `zhtp_client_handshake_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_new(
    handle: *const IdentityHandle,
    channel_binding: *const u8,
    channel_binding_len: usize,
) -> *mut HandshakeStateHandle {
    if handle.is_null() || channel_binding.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };
    let cb = unsafe { std::slice::from_raw_parts(channel_binding, channel_binding_len) };
    Box::into_raw(Box::new(HandshakeStateHandle {
        inner: HandshakeState::new(identity.clone(), cb.to_vec()),
    }))
}

/// Step 1: Create ClientHello message.
/// Returns wire-format bytes to send to the server. Empty buffer on error.
/// Caller must free the returned ByteBuffer with `zhtp_client_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_create_client_hello(
    handle: *mut HandshakeStateHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let state = unsafe { &mut (*handle).inner };
    match state.create_client_hello() {
        Ok(mut bytes) => {
            let buf = ByteBuffer {
                data: bytes.as_mut_ptr(),
                len: bytes.len(),
            };
            std::mem::forget(bytes);
            buf
        }
        Err(_) => ByteBuffer { data: std::ptr::null_mut(), len: 0 },
    }
}

/// Step 2: Process ServerHello and create ClientFinish.
/// Returns wire-format ClientFinish bytes to send back. Empty buffer on error.
/// Caller must free the returned ByteBuffer with `zhtp_client_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_process_server_hello(
    handle: *mut HandshakeStateHandle,
    data: *const u8,
    data_len: usize,
) -> ByteBuffer {
    if handle.is_null() || data.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let state = unsafe { &mut (*handle).inner };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    match state.process_server_hello(data_slice) {
        Ok(mut bytes) => {
            let buf = ByteBuffer {
                data: bytes.as_mut_ptr(),
                len: bytes.len(),
            };
            std::mem::forget(bytes);
            buf
        }
        Err(_) => ByteBuffer { data: std::ptr::null_mut(), len: 0 },
    }
}

/// Step 3: Finalize handshake and derive session keys.
/// Returns a pointer to HandshakeResultHandle, or null on error.
/// Caller must free with `zhtp_client_handshake_result_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_finalize(
    handle: *const HandshakeStateHandle,
) -> *mut HandshakeResultHandle {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let state = unsafe { &(*handle).inner };
    match state.finalize() {
        Ok(result) => Box::into_raw(Box::new(HandshakeResultHandle { inner: result })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a HandshakeStateHandle
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_free(handle: *mut HandshakeStateHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

/// Free a HandshakeResultHandle
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_result_free(handle: *mut HandshakeResultHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

/// Get session key (32 bytes) from handshake result.
/// Caller must free with `zhtp_client_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_result_get_session_key(
    handle: *const HandshakeResultHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let result = unsafe { &(*handle).inner };
    let mut bytes = result.session_key.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

/// Get session ID (32 bytes) from handshake result.
/// Caller must free with `zhtp_client_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_result_get_session_id(
    handle: *const HandshakeResultHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let result = unsafe { &(*handle).inner };
    let mut bytes = result.session_id.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

/// Get peer DID string from handshake result.
/// Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_result_get_peer_did(
    handle: *const HandshakeResultHandle,
) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let result = unsafe { &(*handle).inner };
    match std::ffi::CString::new(result.peer_did.clone()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get peer public key from handshake result.
/// Caller must free with `zhtp_client_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_handshake_result_get_peer_public_key(
    handle: *const HandshakeResultHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer { data: std::ptr::null_mut(), len: 0 };
    }
    let result = unsafe { &(*handle).inner };
    let mut bytes = result.peer_public_key.clone();
    let buf = ByteBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    buf
}

// =============================================================================
// Token Transaction FFI Exports
// =============================================================================

/// Build a signed token transfer transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/token/transfer
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle
/// - token_id: 32-byte token ID
/// - to_pubkey: Recipient's public key bytes (2592 bytes for Dilithium5)
/// - to_pubkey_len: Length of to_pubkey
/// - amount: Amount to transfer (in smallest units)
/// - chain_id: Network chain ID (0x02=testnet, 0x03=development)
///
/// Note: SOV transfers require wallet_id; use `zhtp_client_build_sov_wallet_transfer`.
#[no_mangle]
pub extern "C" fn zhtp_client_build_token_transfer(
    handle: *const IdentityHandle,
    token_id: *const u8,
    to_pubkey: *const u8,
    to_pubkey_len: usize,
    amount: u64,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() || to_pubkey.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let to_pubkey_slice = unsafe { std::slice::from_raw_parts(to_pubkey, to_pubkey_len) };

    let mut token_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);

    match token_tx::build_transfer_tx(identity, &token_id_arr, to_pubkey_slice, amount, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed SOV wallet-based transfer transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/token/transfer
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle
/// - from_wallet_id: 32-byte wallet_id (sender)
/// - to_wallet_id: 32-byte wallet_id (recipient)
/// - amount: Amount to transfer (in smallest units)
/// - chain_id: Network chain ID (0x02=testnet, 0x03=development)
#[no_mangle]
pub extern "C" fn zhtp_client_build_sov_wallet_transfer(
    handle: *const IdentityHandle,
    from_wallet_id: *const u8,
    to_wallet_id: *const u8,
    amount: u64,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || from_wallet_id.is_null() || to_wallet_id.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let from_slice = unsafe { std::slice::from_raw_parts(from_wallet_id, 32) };
    let to_slice = unsafe { std::slice::from_raw_parts(to_wallet_id, 32) };

    let mut from_arr = [0u8; 32];
    let mut to_arr = [0u8; 32];
    from_arr.copy_from_slice(from_slice);
    to_arr.copy_from_slice(to_slice);

    match token_tx::build_sov_wallet_transfer_tx(identity, &from_arr, &to_arr, amount, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed token mint transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/token/mint
/// Caller must free with `zhtp_client_string_free`.
/// Note: Only the token creator can mint.
#[no_mangle]
pub extern "C" fn zhtp_client_build_token_mint(
    handle: *const IdentityHandle,
    token_id: *const u8,
    to_pubkey: *const u8,
    to_pubkey_len: usize,
    amount: u64,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() || to_pubkey.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let to_pubkey_slice = unsafe { std::slice::from_raw_parts(to_pubkey, to_pubkey_len) };

    let mut token_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);

    match token_tx::build_mint_tx(identity, &token_id_arr, to_pubkey_slice, amount, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed token creation transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/token/create
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (becomes token creator)
/// - name: Token name (null-terminated C string)
/// - symbol: Token symbol (null-terminated C string)
/// - initial_supply: Initial supply to mint to creator
/// - decimals: Decimal places (e.g., 8 for 8 decimal places)
/// - chain_id: Network chain ID
#[no_mangle]
pub extern "C" fn zhtp_client_build_token_create(
    handle: *const IdentityHandle,
    name: *const std::ffi::c_char,
    symbol: *const std::ffi::c_char,
    initial_supply: u64,
    decimals: u8,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || name.is_null() || symbol.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let name_str = unsafe {
        match std::ffi::CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let symbol_str = unsafe {
        match std::ffi::CStr::from_ptr(symbol).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    match token_tx::build_create_token_tx(identity, name_str, symbol_str, initial_supply, decimals, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed token burn transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/token/burn
/// Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_build_token_burn(
    handle: *const IdentityHandle,
    token_id: *const u8,
    amount: u64,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };

    let mut token_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);

    match token_tx::build_burn_tx(identity, &token_id_arr, amount, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed domain registration transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/web4/domains/register
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (becomes domain owner)
/// - domain: Domain name (e.g., "example.sov") (null-terminated C string)
/// - content_cid: Optional content CID (null-terminated C string, can be NULL)
/// - chain_id: Network chain ID
#[no_mangle]
pub extern "C" fn zhtp_client_build_domain_register(
    handle: *const IdentityHandle,
    domain: *const std::ffi::c_char,
    content_cid: *const std::ffi::c_char,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || domain.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let domain_str = unsafe {
        match std::ffi::CStr::from_ptr(domain).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let content_cid_opt = if content_cid.is_null() {
        None
    } else {
        match unsafe { std::ffi::CStr::from_ptr(content_cid).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    match token_tx::build_domain_register_tx(identity, domain_str, content_cid_opt, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed domain update transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/web4/domains/update
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (domain owner)
/// - domain: Domain name (e.g., "example.sov") (null-terminated C string)
/// - content_cid: Content CID (null-terminated C string)
/// - chain_id: Network chain ID
#[no_mangle]
pub extern "C" fn zhtp_client_build_domain_update(
    handle: *const IdentityHandle,
    domain: *const std::ffi::c_char,
    content_cid: *const std::ffi::c_char,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || domain.is_null() || content_cid.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let domain_str = unsafe {
        match std::ffi::CStr::from_ptr(domain).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let content_cid_str = unsafe {
        match std::ffi::CStr::from_ptr(content_cid).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    match token_tx::build_domain_update_tx(identity, domain_str, content_cid_str, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed domain transfer transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/web4/domains/transfer
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (current domain owner)
/// - domain: Domain name (e.g., "example.sov") (null-terminated C string)
/// - to_pubkey: New owner's public key bytes (32 bytes)
/// - chain_id: Network chain ID
#[no_mangle]
pub extern "C" fn zhtp_client_build_domain_transfer(
    handle: *const IdentityHandle,
    domain: *const std::ffi::c_char,
    to_pubkey: *const u8,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || domain.is_null() || to_pubkey.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let domain_str = unsafe {
        match std::ffi::CStr::from_ptr(domain).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let to_pubkey_slice = unsafe { std::slice::from_raw_parts(to_pubkey, 1312) };

    match token_tx::build_domain_transfer_tx(identity, domain_str, to_pubkey_slice, chain_id) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}
