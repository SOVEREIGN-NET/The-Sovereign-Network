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

mod bip39_wordlist;
pub mod bonding_curve_tx;
pub mod crypto;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod request;
pub mod session;
pub mod token_tx;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-exports for convenience
pub use crypto::{Blake3, Dilithium5, Kyber1024};
pub use error::{ClientError, Result};
pub use handshake::{HandshakeResult, HandshakeState};
pub use identity::{
    build_migrate_identity_request, build_migrate_identity_request_json, export_keystore_base64,
    generate_identity, get_public_identity, get_seed_phrase, restore_identity_from_phrase,
    sign_registration_proof, Identity, MigrateIdentityRequestPayload, PublicIdentity,
};
pub use request::{
    create_zhtp_frame, deserialize_response, parse_zhtp_frame, serialize_request, ZhtpHeaders,
    ZhtpRequest, ZhtpResponse,
};
pub use session::Session;
pub use token_tx::{
    // Token-specific
    build_burn_tx,
    // Generic contract transaction builder
    build_contract_transaction,
    build_create_token_tx,
    // Domain-specific (new JSON-based API)
    build_domain_register_request,
    build_domain_register_request_with_fee_payment,
    // Domain-specific (deprecated, use *_request functions instead)
    build_domain_register_tx,
    build_domain_transfer_request,
    build_domain_transfer_tx,
    build_domain_update_request,
    build_domain_update_tx,
    build_mint_tx,
    build_sov_wallet_transfer_tx,
    build_transfer_tx,
    BurnParams,
    ContentMapping,
    // Param types for serialization
    CreateTokenParams,
    DomainRegisterParams,
    DomainTransferParams,
    DomainUpdateParams,
    MintParams,
    TransferParams,
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
pub extern "C" fn zhtp_client_identity_get_did(
    handle: *const IdentityHandle,
) -> *mut std::ffi::c_char {
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
pub extern "C" fn zhtp_client_identity_get_device_id(
    handle: *const IdentityHandle,
) -> *mut std::ffi::c_char {
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
pub extern "C" fn zhtp_client_identity_get_seed_phrase(
    handle: *const IdentityHandle,
) -> *mut std::ffi::c_char {
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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

/// Derive wallet_id (32-byte blake3 hash) from a Dilithium public key.
///
/// Accepts either:
/// - 32 bytes: returned as-is (already a wallet_id / key_id)
/// - ≥1000 bytes: Dilithium2 (1312) or Dilithium5 (2592) public key — computes blake3(pk)
///
/// Returns empty buffer on invalid input. Caller must free with `zhtp_client_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn zhtp_client_derive_wallet_id(
    pubkey: *const u8,
    pubkey_len: usize,
) -> ByteBuffer {
    if pubkey.is_null() || pubkey_len == 0 {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
    }
    let pk_slice = std::slice::from_raw_parts(pubkey, pubkey_len);
    let key_id: [u8; 32] = if pubkey_len == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk_slice);
        arr
    } else if pubkey_len >= 1000 {
        token_tx::create_public_key(pk_slice.to_vec()).key_id
    } else {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
    };
    let mut boxed = Box::new(key_id);
    let buf = ByteBuffer {
        data: boxed.as_mut_ptr(),
        len: 32,
    };
    std::mem::forget(boxed);
    buf
}

/// Get node ID from identity
#[no_mangle]
pub extern "C" fn zhtp_client_identity_get_node_id(handle: *const IdentityHandle) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
pub extern "C" fn zhtp_client_identity_get_kyber_public_key(
    handle: *const IdentityHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
pub extern "C" fn zhtp_client_identity_get_dilithium_secret_key(
    handle: *const IdentityHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
pub extern "C" fn zhtp_client_identity_get_kyber_secret_key(
    handle: *const IdentityHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
pub extern "C" fn zhtp_client_identity_get_master_seed(
    handle: *const IdentityHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        Err(_) => ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        },
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        Err(_) => ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        },
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        Err(_) => ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        },
    }
}

// ---------------------------------------------------------------------------
// PoUW receipt signing — canonical bincode path
// ---------------------------------------------------------------------------
//
// The server validates receipt signatures by calling bincode::serialize on the
// Receipt struct (with hex_bytes serde annotations on Vec<u8> fields).  Swift
// has no bincode implementation, so rather than porting bincode to Swift we
// expose this FFI that accepts the receipt as compact JSON and handles the
// JSON → Receipt → bincode → Dilithium5 signature pipeline internally.

/// Canonical proof-type variants — must stay in the same declaration order as
/// `zhtp::pouw::types::ProofType` so bincode emits matching discriminants.
/// The `rename_all = "lowercase"` mirrors the server serde attribute so JSON
/// values like `"hash"`, `"signature"`, `"web4manifestroute"` round-trip correctly.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum PouwProofType {
    Hash,
    Merkle,
    Signature,
    Web4ManifestRoute,
    Web4ContentServed,
}

/// Receipt shape for signing — field layout must match
/// `zhtp::pouw::types::Receipt` exactly (same order, same serde attributes).
#[derive(serde::Serialize, serde::Deserialize)]
struct PouwReceipt {
    pub version: u32,
    #[serde(with = "pouw_hex")]
    pub task_id: Vec<u8>,
    pub client_did: String,
    #[serde(with = "pouw_hex")]
    pub client_node_id: Vec<u8>,
    #[serde(with = "pouw_hex")]
    pub provider_id: Vec<u8>,
    #[serde(with = "pouw_hex")]
    pub content_id: Vec<u8>,
    pub proof_type: PouwProofType,
    pub bytes_verified: u64,
    pub result_ok: bool,
    pub started_at: u64,
    pub finished_at: u64,
    #[serde(with = "pouw_hex")]
    pub receipt_nonce: Vec<u8>,
    #[serde(with = "pouw_hex")]
    pub challenge_nonce: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aux: Option<String>,
}

/// Serde helper: hex string ↔ Vec<u8> (mirrors the server-side hex_bytes module).
mod pouw_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Sign a PoUW receipt using the server's canonical bincode serialization.
///
/// Accepts the receipt as compact JSON (UTF-8).  Internally:
///   1. Parses JSON → `PouwReceipt` (hex strings decoded to bytes via serde).
///   2. `bincode::serialize(&receipt)` — same call the server makes during
///      signature verification, so the byte sequences are identical.
///   3. Signs those bytes with the identity's Dilithium5 key.
///   4. Returns raw signature bytes in a `ByteBuffer`.
///
/// Returns an empty buffer on any error (bad JSON, invalid fields, or sign failure).
/// Caller must free the returned buffer with `zhtp_client_buffer_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_sign_pouw_receipt_json(
    handle: *const IdentityHandle,
    receipt_json_ptr: *const u8,
    receipt_json_len: usize,
) -> ByteBuffer {
    if handle.is_null() || receipt_json_ptr.is_null() {
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
    }

    let identity = unsafe { &(*handle).inner };
    let json_bytes = unsafe { std::slice::from_raw_parts(receipt_json_ptr, receipt_json_len) };

    let receipt: PouwReceipt = match serde_json::from_slice(json_bytes) {
        Ok(r) => r,
        Err(_) => {
            return ByteBuffer {
                data: std::ptr::null_mut(),
                len: 0,
            }
        }
    };

    let canonical_bytes = match bincode::serialize(&receipt) {
        Ok(b) => b,
        Err(_) => {
            return ByteBuffer {
                data: std::ptr::null_mut(),
                len: 0,
            }
        }
    };

    match identity::sign_message(identity, &canonical_bytes) {
        Ok(mut sig) => {
            let buf = ByteBuffer {
                data: sig.as_mut_ptr(),
                len: sig.len(),
            };
            std::mem::forget(sig);
            buf
        }
        Err(_) => ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        },
    }
}

/// Serialize identity to JSON. Caller must free with `zhtp_client_string_free`.
#[no_mangle]
pub extern "C" fn zhtp_client_identity_serialize(
    handle: *const IdentityHandle,
) -> *mut std::ffi::c_char {
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
pub extern "C" fn zhtp_client_identity_deserialize(
    json: *const std::ffi::c_char,
) -> *mut IdentityHandle {
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
pub extern "C" fn zhtp_client_export_keystore_base64(
    handle: *const IdentityHandle,
) -> *mut std::ffi::c_char {
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
pub extern "C" fn zhtp_client_identity_to_handshake_json(
    handle: *const IdentityHandle,
) -> *mut std::ffi::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let identity = unsafe { &(*handle).inner };

    // Compute key_id = Blake3(dilithium_public_key)
    let key_id = crypto::Blake3::hash(&identity.public_key);

    // Extract identity ID from DID (format: "did:zhtp:{id_hex}")
    let id_hex = identity
        .did
        .strip_prefix("did:zhtp:")
        .unwrap_or(&identity.did);
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        Err(_) => ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        },
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        Err(_) => ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        },
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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
        return ByteBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
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

/// Build a signed token transfer transaction with nonce for replay protection.
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
/// - nonce: Transfer nonce for replay protection (query /api/v1/token/nonce/{token_id}/{address})
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
    nonce: u64,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() || to_pubkey.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let to_pubkey_slice = unsafe { std::slice::from_raw_parts(to_pubkey, to_pubkey_len) };

    let mut token_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);

    match token_tx::build_transfer_tx(
        identity,
        &token_id_arr,
        to_pubkey_slice,
        amount,
        chain_id,
        nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed SOV wallet-based transfer transaction with nonce for replay protection.
/// Returns hex-encoded transaction ready to POST to /api/v1/token/transfer
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle
/// - from_wallet_id: 32-byte wallet_id (sender)
/// - to_wallet_id: 32-byte wallet_id (recipient)
/// - amount: Amount to transfer (in smallest units)
/// - chain_id: Network chain ID (0x02=testnet, 0x03=development)
/// - nonce: Transfer nonce for replay protection (query /api/v1/token/nonce/{token_id}/{address})
#[no_mangle]
pub extern "C" fn zhtp_client_build_sov_wallet_transfer(
    handle: *const IdentityHandle,
    from_wallet_id: *const u8,
    to_wallet_id: *const u8,
    amount: u64,
    chain_id: u8,
    nonce: u64,
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

    match token_tx::build_sov_wallet_transfer_tx(
        identity, &from_arr, &to_arr, amount, chain_id, nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Override fee parameters used by client-side fee calculation.
/// This should be called after fetching the fee config from the node.
#[no_mangle]
pub extern "C" fn zhtp_client_set_fee_config(base_fee: u64, bytes_per_sov: u64, witness_cap: u32) {
    token_tx::set_fee_config(base_fee, bytes_per_sov, witness_cap);
}

/// Set fee config from JSON (response of /api/v1/blockchain/fee-config).
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn zhtp_client_set_fee_config_json(json: *const std::ffi::c_char) -> i32 {
    if json.is_null() {
        return 0;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(json) };
    match c_str.to_str() {
        Ok(s) => token_tx::set_fee_config_from_json(s)
            .map(|_| 1)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Set fee config from JSON and return updated heights via out params.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn zhtp_client_set_fee_config_json_ex(
    json: *const std::ffi::c_char,
    out_updated_at_height: *mut u64,
    out_chain_height: *mut u64,
) -> i32 {
    if json.is_null() {
        return 0;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(json) };
    let res = match c_str.to_str() {
        Ok(s) => token_tx::set_fee_config_from_json_with_meta(s),
        Err(_) => return 0,
    };
    match res {
        Ok(meta) => {
            unsafe {
                if !out_updated_at_height.is_null() {
                    *out_updated_at_height = meta.updated_at_height;
                }
                if !out_chain_height.is_null() {
                    *out_chain_height = meta.chain_height;
                }
            }
            1
        }
        Err(_) => 0,
    }
}

/// Quote minimum fee for a hex-encoded bincode transaction using cached fee config.
/// Returns 0 on failure.
#[no_mangle]
pub extern "C" fn zhtp_client_quote_fee_for_tx_hex(tx_hex: *const std::ffi::c_char) -> u64 {
    if tx_hex.is_null() {
        return 0;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(tx_hex) };
    match c_str.to_str() {
        Ok(s) => token_tx::calculate_min_fee_for_tx_hex(s).unwrap_or(0),
        Err(_) => 0,
    }
}

// ============================================================================
// Android JNI Export
// ============================================================================

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_sovereignnetworkmobile_Identity_nativeBuildSovWalletTransfer(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    handle: jni::sys::jlong,
    from_wallet_id: jni::objects::JByteArray,
    to_wallet_id: jni::objects::JByteArray,
    amount: jni::sys::jlong,
    chain_id: jni::sys::jint,
    nonce: jni::sys::jlong,
) -> jni::sys::jstring {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let from_vec = match env.convert_byte_array(from_wallet_id) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };
    let to_vec = match env.convert_byte_array(to_wallet_id) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };
    if from_vec.len() != 32 || to_vec.len() != 32 {
        return std::ptr::null_mut();
    }

    let hex_ptr = zhtp_client_build_sov_wallet_transfer(
        handle as *const IdentityHandle,
        from_vec.as_ptr(),
        to_vec.as_ptr(),
        amount as u64,
        chain_id as u8,
        nonce as u64,
    );
    if hex_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(hex_ptr) };
    let hex_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            unsafe { zhtp_client_string_free(hex_ptr) };
            return std::ptr::null_mut();
        }
    };

    let jstr = match env.new_string(hex_str) {
        Ok(s) => s,
        Err(_) => {
            unsafe { zhtp_client_string_free(hex_ptr) };
            return std::ptr::null_mut();
        }
    };

    unsafe { zhtp_client_string_free(hex_ptr) };
    jstr.into_raw()
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_sovereignnetworkmobile_Identity_nativeSetFeeConfig(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    base_fee: jni::sys::jlong,
    bytes_per_sov: jni::sys::jlong,
    witness_cap: jni::sys::jint,
) {
    zhtp_client_set_fee_config(base_fee as u64, bytes_per_sov as u64, witness_cap as u32);
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_sovereignnetworkmobile_Identity_nativeSetFeeConfigJson(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    json: jni::objects::JString,
) -> jni::sys::jint {
    let json_str = match env.get_string(&json) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_str = std::ffi::CString::new(json_str.to_bytes()).unwrap_or_default();
    zhtp_client_set_fee_config_json(c_str.as_ptr()) as jni::sys::jint
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_sovereignnetworkmobile_Identity_nativeSetFeeConfigJsonEx(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    json: jni::objects::JString,
    out_heights: jni::objects::JLongArray,
) -> jni::sys::jint {
    let json_str = match env.get_string(&json) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_str = std::ffi::CString::new(json_str.to_bytes()).unwrap_or_default();

    let mut updated_at_height: u64 = 0;
    let mut chain_height: u64 = 0;
    let ok = zhtp_client_set_fee_config_json_ex(
        c_str.as_ptr(),
        &mut updated_at_height as *mut u64,
        &mut chain_height as *mut u64,
    );
    if ok == 0 {
        return 0;
    }

    let arr = [
        updated_at_height as jni::sys::jlong,
        chain_height as jni::sys::jlong,
    ];
    if env.set_long_array_region(out_heights, 0, &arr).is_err() {
        return 0;
    }
    1
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_sovereignnetworkmobile_Identity_nativeQuoteFeeForTxHex(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    tx_hex: jni::objects::JString,
) -> jni::sys::jlong {
    let tx_str = match env.get_string(&tx_hex) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_str = std::ffi::CString::new(tx_str.to_bytes()).unwrap_or_default();
    zhtp_client_quote_fee_for_tx_hex(c_str.as_ptr()) as jni::sys::jlong
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
/// - treasury_recipient: 32-byte key_id of treasury allocation recipient (must differ from creator)
/// - chain_id: Network chain ID
#[no_mangle]
pub extern "C" fn zhtp_client_build_token_create(
    handle: *const IdentityHandle,
    name: *const std::ffi::c_char,
    symbol: *const std::ffi::c_char,
    initial_supply: u64,
    decimals: u8,
    treasury_recipient: *const u8,
    chain_id: u8,
) -> *mut std::ffi::c_char {
    if handle.is_null() || name.is_null() || symbol.is_null() || treasury_recipient.is_null() {
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
    let treasury_recipient_slice = unsafe { std::slice::from_raw_parts(treasury_recipient, 32) };
    let mut treasury_recipient_arr = [0u8; 32];
    treasury_recipient_arr.copy_from_slice(treasury_recipient_slice);

    match token_tx::build_create_token_tx(
        identity,
        name_str,
        symbol_str,
        initial_supply,
        decimals,
        treasury_recipient_arr,
        chain_id,
    ) {
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

// ============================================================================
// Bonding Curve FFI Functions
// ============================================================================

/// Build a signed bonding curve deploy transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/curve/deploy
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (becomes token creator)
/// - name: Token name (null-terminated C string)
/// - symbol: Token symbol, max 10 chars (null-terminated C string)
/// - curve_type: 0=Linear, 1=Exponential, 2=Sigmoid
/// - base_price: Base price in stablecoin atomic units
/// - curve_param: Slope/growth rate/steepness depending on curve type
/// - midpoint_supply: Midpoint supply for sigmoid (0 for other types)
/// - threshold_type: 0=ReserveAmount, 1=SupplyAmount, 2=TimeAndReserve, 3=TimeAndSupply
/// - threshold_value: Threshold amount (reserve or supply)
/// - threshold_time_seconds: Time threshold for TimeAnd* types (0 if not used)
/// - sell_enabled: 1 to enable selling, 0 to disable
/// - chain_id: Network chain ID
/// - nonce: Nonce for replay protection
#[no_mangle]
pub extern "C" fn zhtp_client_build_bonding_curve_deploy(
    handle: *const IdentityHandle,
    name: *const std::ffi::c_char,
    symbol: *const std::ffi::c_char,
    curve_type: u8,
    base_price: u64,
    curve_param: u64,
    midpoint_supply: u64,
    threshold_type: u8,
    threshold_value: u64,
    threshold_time_seconds: u64,
    sell_enabled: u8,
    chain_id: u8,
    nonce: u64,
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

    let midpoint = if midpoint_supply > 0 {
        Some(midpoint_supply)
    } else {
        None
    };
    let threshold_time = if threshold_time_seconds > 0 {
        Some(threshold_time_seconds)
    } else {
        None
    };
    let sell = sell_enabled != 0;

    match bonding_curve_tx::build_bonding_curve_deploy_tx(
        identity,
        name_str,
        symbol_str,
        curve_type,
        base_price,
        curve_param,
        midpoint,
        threshold_type,
        threshold_value,
        threshold_time,
        sell,
        chain_id,
        nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed bonding curve buy transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/curve/buy
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (becomes buyer)
/// - token_id: Token ID bytes (32 bytes)
/// - stable_amount: Amount of stablecoin to spend
/// - min_tokens_out: Minimum tokens expected (slippage protection)
/// - chain_id: Network chain ID
/// - nonce: Nonce for replay protection
#[no_mangle]
pub extern "C" fn zhtp_client_build_bonding_curve_buy(
    handle: *const IdentityHandle,
    token_id: *const u8,
    stable_amount: u64,
    min_tokens_out: u64,
    chain_id: u8,
    nonce: u64,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let mut token_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);

    match bonding_curve_tx::build_bonding_curve_buy_tx(
        identity,
        &token_id_arr,
        stable_amount,
        min_tokens_out,
        chain_id,
        nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed bonding curve sell transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/curve/sell
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (becomes seller)
/// - token_id: Token ID bytes (32 bytes)
/// - token_amount: Amount of tokens to sell
/// - min_stable_out: Minimum stablecoin expected (slippage protection)
/// - chain_id: Network chain ID
/// - nonce: Nonce for replay protection
#[no_mangle]
pub extern "C" fn zhtp_client_build_bonding_curve_sell(
    handle: *const IdentityHandle,
    token_id: *const u8,
    token_amount: u64,
    min_stable_out: u64,
    chain_id: u8,
    nonce: u64,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let mut token_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);

    match bonding_curve_tx::build_bonding_curve_sell_tx(
        identity,
        &token_id_arr,
        token_amount,
        min_stable_out,
        chain_id,
        nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed AMM swap transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/swap
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (swapper)
/// - token_id: Token ID bytes (32 bytes)
/// - pool_id: AMM Pool ID bytes (32 bytes)
/// - amount_in: Input amount
/// - min_amount_out: Minimum output (slippage protection)
/// - token_to_sov: 1 for token->SOV, 0 for SOV->token
/// - chain_id: Network chain ID
/// - nonce: Nonce for replay protection
#[no_mangle]
pub extern "C" fn zhtp_client_build_swap(
    handle: *const IdentityHandle,
    token_id: *const u8,
    pool_id: *const u8,
    amount_in: u64,
    min_amount_out: u64,
    token_to_sov: u8,
    chain_id: u8,
    nonce: u64,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() || pool_id.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let pool_id_slice = unsafe { std::slice::from_raw_parts(pool_id, 32) };
    let mut token_id_arr = [0u8; 32];
    let mut pool_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);
    pool_id_arr.copy_from_slice(pool_id_slice);

    match bonding_curve_tx::build_swap_tx(
        identity,
        &token_id_arr,
        &pool_id_arr,
        amount_in,
        min_amount_out,
        token_to_sov != 0,
        chain_id,
        nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed add liquidity transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/swap/liquidity/add
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (liquidity provider)
/// - token_id: Token ID bytes (32 bytes)
/// - pool_id: AMM Pool ID bytes (32 bytes)
/// - token_amount: Token amount to add
/// - sov_amount: SOV amount to add
/// - chain_id: Network chain ID
/// - nonce: Nonce for replay protection
#[no_mangle]
pub extern "C" fn zhtp_client_build_add_liquidity(
    handle: *const IdentityHandle,
    token_id: *const u8,
    pool_id: *const u8,
    token_amount: u64,
    sov_amount: u64,
    chain_id: u8,
    nonce: u64,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() || pool_id.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let pool_id_slice = unsafe { std::slice::from_raw_parts(pool_id, 32) };
    let mut token_id_arr = [0u8; 32];
    let mut pool_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);
    pool_id_arr.copy_from_slice(pool_id_slice);

    match bonding_curve_tx::build_add_liquidity_tx(
        identity,
        &token_id_arr,
        &pool_id_arr,
        token_amount,
        sov_amount,
        chain_id,
        nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build a signed remove liquidity transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/swap/liquidity/remove
/// Caller must free with `zhtp_client_string_free`.
///
/// # Parameters
/// - handle: Identity handle (liquidity provider)
/// - token_id: Token ID bytes (32 bytes)
/// - pool_id: AMM Pool ID bytes (32 bytes)
/// - lp_amount: LP tokens to burn
/// - chain_id: Network chain ID
/// - nonce: Nonce for replay protection
#[no_mangle]
pub extern "C" fn zhtp_client_build_remove_liquidity(
    handle: *const IdentityHandle,
    token_id: *const u8,
    pool_id: *const u8,
    lp_amount: u64,
    chain_id: u8,
    nonce: u64,
) -> *mut std::ffi::c_char {
    if handle.is_null() || token_id.is_null() || pool_id.is_null() {
        return std::ptr::null_mut();
    }

    let identity = unsafe { &(*handle).inner };
    let token_id_slice = unsafe { std::slice::from_raw_parts(token_id, 32) };
    let pool_id_slice = unsafe { std::slice::from_raw_parts(pool_id, 32) };
    let mut token_id_arr = [0u8; 32];
    let mut pool_id_arr = [0u8; 32];
    token_id_arr.copy_from_slice(token_id_slice);
    pool_id_arr.copy_from_slice(pool_id_slice);

    match bonding_curve_tx::build_remove_liquidity_tx(
        identity,
        &token_id_arr,
        &pool_id_arr,
        lp_amount,
        chain_id,
        nonce,
    ) {
        Ok(hex_tx) => match std::ffi::CString::new(hex_tx) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}
