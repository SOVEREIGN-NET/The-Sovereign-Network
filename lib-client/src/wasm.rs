//! WebAssembly bindings for ZHTP Client
//!
//! Provides JavaScript/TypeScript API for web browsers.
//!
//! # Usage (JavaScript/TypeScript)
//!
//! ```typescript
//! import init, {
//!     generateIdentity,
//!     getPublicIdentity,
//!     signRegistrationProof,
//!     WasmHandshakeState,
//!     WasmSession,
//!     serializeRequest,
//!     deserializeResponse,
//!     createZhtpFrame,
//!     parseZhtpFrame,
//! } from 'zhtp-client';
//!
//! await init();
//!
//! // Generate identity
//! const identity = generateIdentity('device-123');
//! const publicIdentity = getPublicIdentity(identity);
//!
//! // Perform handshake
//! const handshake = new WasmHandshakeState(identity, channelBinding);
//! const clientHello = handshake.createClientHello();
//! // send clientHello...
//! const clientFinish = handshake.processServerHello(serverHelloData);
//! // send clientFinish...
//! const result = handshake.finalize();
//!
//! // Create encrypted session
//! const session = new WasmSession(result.sessionKey, result.sessionId, result.peerDid);
//! const encrypted = session.encrypt(plaintext);
//! ```

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use crate::handshake::HandshakeState;
use crate::identity::{Identity, PublicIdentity};
use crate::request::{ZhtpHeaders, ZhtpRequest, ZhtpResponse};
use crate::session::Session;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the WASM module (call once at startup)
#[wasm_bindgen(start)]
pub fn wasm_init() {
    // Set up better panic messages in browser console
    console_error_panic_hook::set_once();
}

// Helper to convert JsValue error to JsError
fn js_err(msg: &str) -> JsError {
    JsError::new(msg)
}

// Helper macro to set property on JS object (ignores result)
macro_rules! js_set {
    ($obj:expr, $key:expr, $val:expr) => {
        let _ = Reflect::set($obj, &$key.into(), $val);
    };
}

// ============================================================================
// Identity Functions
// ============================================================================

/// Generate a new ZHTP identity with post-quantum keys
/// Keys are generated locally and private keys NEVER leave the browser
#[wasm_bindgen(js_name = generateIdentity)]
pub fn generate_identity_wasm(device_id: &str) -> Result<JsValue, JsError> {
    let identity = crate::identity::generate_identity(device_id.to_string())
        .map_err(|e| js_err(&e.to_string()))?;

    identity_to_js(&identity)
}

/// Restore identity from master seed (for recovery)
#[wasm_bindgen(js_name = restoreIdentityFromSeed)]
pub fn restore_identity_from_seed_wasm(
    master_seed: &[u8],
    device_id: &str,
) -> Result<JsValue, JsError> {
    let identity =
        crate::identity::restore_identity_from_seed(master_seed.to_vec(), device_id.to_string())
            .map_err(|e| js_err(&e.to_string()))?;

    identity_to_js(&identity)
}

/// Get public portion of identity (safe to send to server)
#[wasm_bindgen(js_name = getPublicIdentity)]
pub fn get_public_identity_wasm(identity: &JsValue) -> Result<JsValue, JsError> {
    let identity = js_to_identity(identity)?;
    let public_identity = crate::identity::get_public_identity(&identity);

    public_identity_to_js(&public_identity)
}

/// Sign a registration proof for server registration
#[wasm_bindgen(js_name = signRegistrationProof)]
pub fn sign_registration_proof_wasm(
    identity: &JsValue,
    timestamp: u64,
) -> Result<Uint8Array, JsError> {
    let identity = js_to_identity(identity)?;
    let signature = crate::identity::sign_registration_proof(&identity, timestamp)
        .map_err(|e| js_err(&e.to_string()))?;

    Ok(Uint8Array::from(&signature[..]))
}

/// Sign an arbitrary message
#[wasm_bindgen(js_name = signMessage)]
pub fn sign_message_wasm(identity: &JsValue, message: &[u8]) -> Result<Uint8Array, JsError> {
    let identity = js_to_identity(identity)?;
    let signature =
        crate::identity::sign_message(&identity, message).map_err(|e| js_err(&e.to_string()))?;

    Ok(Uint8Array::from(&signature[..]))
}

/// Verify a signature
#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature_wasm(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    crate::identity::verify_signature(public_key, message, signature)
        .map_err(|e| js_err(&e.to_string()))
}

/// Serialize identity to JSON for storage
#[wasm_bindgen(js_name = serializeIdentity)]
pub fn serialize_identity_wasm(identity: &JsValue) -> Result<String, JsError> {
    let identity = js_to_identity(identity)?;
    crate::identity::serialize_identity(&identity).map_err(|e| js_err(&e.to_string()))
}

/// Deserialize identity from JSON
#[wasm_bindgen(js_name = deserializeIdentity)]
pub fn deserialize_identity_wasm(json: &str) -> Result<JsValue, JsError> {
    let identity =
        crate::identity::deserialize_identity(json).map_err(|e| js_err(&e.to_string()))?;

    identity_to_js(&identity)
}

// ============================================================================
// Handshake State Machine
// ============================================================================

/// UHP v2 Handshake state machine for WASM
#[wasm_bindgen]
pub struct WasmHandshakeState {
    inner: HandshakeState,
}

#[wasm_bindgen]
impl WasmHandshakeState {
    /// Create new handshake state
    #[wasm_bindgen(constructor)]
    pub fn new(identity: &JsValue, channel_binding: &[u8]) -> Result<WasmHandshakeState, JsError> {
        let identity = js_to_identity(identity)?;
        Ok(WasmHandshakeState {
            inner: HandshakeState::new(identity, channel_binding.to_vec()),
        })
    }

    /// Step 1: Create ClientHello message
    /// Returns wire-format bytes to send
    #[wasm_bindgen(js_name = createClientHello)]
    pub fn create_client_hello(&mut self) -> Result<Uint8Array, JsError> {
        let bytes = self
            .inner
            .create_client_hello()
            .map_err(|e| js_err(&e.to_string()))?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    /// Step 2: Process ServerHello and create ClientFinish
    /// Returns ClientFinish bytes to send
    #[wasm_bindgen(js_name = processServerHello)]
    pub fn process_server_hello(&mut self, data: &[u8]) -> Result<Uint8Array, JsError> {
        let bytes = self
            .inner
            .process_server_hello(data)
            .map_err(|e| js_err(&e.to_string()))?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    /// Step 3: Finalize and get session key
    /// Returns: { sessionKey: Uint8Array, sessionId: Uint8Array, peerDid: string, peerPublicKey: Uint8Array }
    #[wasm_bindgen]
    pub fn finalize(&self) -> Result<JsValue, JsError> {
        let result = self.inner.finalize().map_err(|e| js_err(&e.to_string()))?;

        let obj = Object::new();
        js_set!(
            &obj,
            "sessionKey",
            &Uint8Array::from(&result.session_key[..])
        );
        js_set!(&obj, "sessionId", &Uint8Array::from(&result.session_id[..]));
        js_set!(&obj, "peerDid", &JsValue::from_str(&result.peer_did));
        js_set!(
            &obj,
            "peerPublicKey",
            &Uint8Array::from(&result.peer_public_key[..])
        );

        Ok(obj.into())
    }

    /// Get the challenge nonce (for debugging)
    #[wasm_bindgen(js_name = challengeNonce)]
    pub fn challenge_nonce(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.challenge_nonce()[..])
    }
}

// ============================================================================
// Session (Encrypted Communication)
// ============================================================================

/// Encrypted session for authenticated communication
#[wasm_bindgen]
pub struct WasmSession {
    inner: Session,
}

#[wasm_bindgen]
impl WasmSession {
    /// Create new session from handshake result
    #[wasm_bindgen(constructor)]
    pub fn new(
        session_key: &[u8],
        session_id: &[u8],
        peer_did: &str,
    ) -> Result<WasmSession, JsError> {
        let session = Session::new(
            session_key.to_vec(),
            session_id.to_vec(),
            peer_did.to_string(),
        )
        .map_err(|e| js_err(&e.to_string()))?;

        Ok(WasmSession { inner: session })
    }

    /// Encrypt a message
    /// Returns: [nonce (12)] [ciphertext + tag]
    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Uint8Array, JsError> {
        let ciphertext = self
            .inner
            .encrypt(plaintext)
            .map_err(|e| js_err(&e.to_string()))?;
        Ok(Uint8Array::from(&ciphertext[..]))
    }

    /// Decrypt a message
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Uint8Array, JsError> {
        let plaintext = self
            .inner
            .decrypt(ciphertext)
            .map_err(|e| js_err(&e.to_string()))?;
        Ok(Uint8Array::from(&plaintext[..]))
    }

    /// Get peer's DID
    #[wasm_bindgen(js_name = peerDid)]
    pub fn peer_did(&self) -> String {
        self.inner.peer_did().to_string()
    }

    /// Get session ID
    #[wasm_bindgen(js_name = sessionId)]
    pub fn session_id(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.session_id()[..])
    }

    /// Check if session is valid
    #[wasm_bindgen(js_name = isValid)]
    pub fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }
}

// ============================================================================
// Request/Response Functions
// ============================================================================

/// Serialize a ZHTP request to CBOR bytes
#[wasm_bindgen(js_name = serializeRequest)]
pub fn serialize_request_wasm(request: &JsValue) -> Result<Uint8Array, JsError> {
    let req = js_to_zhtp_request(request)?;
    let bytes = crate::request::serialize_request(&req).map_err(|e| js_err(&e.to_string()))?;
    Ok(Uint8Array::from(&bytes[..]))
}

/// Deserialize a ZHTP response from CBOR bytes
#[wasm_bindgen(js_name = deserializeResponse)]
pub fn deserialize_response_wasm(data: &[u8]) -> Result<JsValue, JsError> {
    let response =
        crate::request::deserialize_response(data).map_err(|e| js_err(&e.to_string()))?;
    zhtp_response_to_js(&response)
}

/// Create ZHTP wire frame from payload
/// Format: [ZHTP (4)] [version (1)] [length BE (4)] [payload]
#[wasm_bindgen(js_name = createZhtpFrame)]
pub fn create_zhtp_frame_wasm(payload: &[u8]) -> Uint8Array {
    let frame = crate::request::create_zhtp_frame(payload);
    Uint8Array::from(&frame[..])
}

/// Parse ZHTP wire frame and extract payload
#[wasm_bindgen(js_name = parseZhtpFrame)]
pub fn parse_zhtp_frame_wasm(data: &[u8]) -> Result<Uint8Array, JsError> {
    let payload = crate::request::parse_zhtp_frame(data).map_err(|e| js_err(&e.to_string()))?;
    Ok(Uint8Array::from(&payload[..]))
}

/// Compute channel binding from socket addresses
#[wasm_bindgen(js_name = computeChannelBinding)]
pub fn compute_channel_binding_wasm(local_addr: &str, peer_addr: &str) -> Uint8Array {
    let binding = crate::handshake::compute_channel_binding(local_addr, peer_addr);
    Uint8Array::from(&binding[..])
}

// ============================================================================
// Crypto Functions (low-level)
// ============================================================================

/// Generate random bytes
#[wasm_bindgen(js_name = randomBytes)]
pub fn random_bytes_wasm(len: u32) -> Uint8Array {
    let bytes = crate::crypto::random_bytes(len as usize);
    Uint8Array::from(&bytes[..])
}

/// Compute Blake3 hash
#[wasm_bindgen(js_name = blake3Hash)]
pub fn blake3_hash_wasm(data: &[u8]) -> Uint8Array {
    let hash = crate::crypto::Blake3::hash_vec(data);
    Uint8Array::from(&hash[..])
}

/// One-shot encryption (for data at rest)
#[wasm_bindgen(js_name = encryptOneshot)]
pub fn encrypt_oneshot_wasm(key: &[u8], plaintext: &[u8]) -> Result<Uint8Array, JsError> {
    let ciphertext =
        crate::session::encrypt_oneshot(key, plaintext).map_err(|e| js_err(&e.to_string()))?;
    Ok(Uint8Array::from(&ciphertext[..]))
}

/// One-shot decryption
#[wasm_bindgen(js_name = decryptOneshot)]
pub fn decrypt_oneshot_wasm(key: &[u8], ciphertext: &[u8]) -> Result<Uint8Array, JsError> {
    let plaintext =
        crate::session::decrypt_oneshot(key, ciphertext).map_err(|e| js_err(&e.to_string()))?;
    Ok(Uint8Array::from(&plaintext[..]))
}

// ============================================================================
// Helper Functions (JS <-> Rust conversions)
// ============================================================================

fn identity_to_js(identity: &Identity) -> Result<JsValue, JsError> {
    let obj = Object::new();
    js_set!(&obj, "did", &JsValue::from_str(&identity.did));
    js_set!(
        &obj,
        "publicKey",
        &Uint8Array::from(&identity.public_key[..])
    );
    js_set!(
        &obj,
        "privateKey",
        &Uint8Array::from(&identity.private_key[..])
    );
    js_set!(
        &obj,
        "kyberPublicKey",
        &Uint8Array::from(&identity.kyber_public_key[..])
    );
    js_set!(
        &obj,
        "kyberSecretKey",
        &Uint8Array::from(&identity.kyber_secret_key[..])
    );
    js_set!(&obj, "nodeId", &Uint8Array::from(&identity.node_id[..]));
    js_set!(&obj, "deviceId", &JsValue::from_str(&identity.device_id));
    // Legacy field name: 32-byte recovery entropy (mnemonic-encodable).
    js_set!(
        &obj,
        "masterSeed",
        &Uint8Array::from(&identity.recovery_entropy[..])
    );
    js_set!(
        &obj,
        "createdAt",
        &JsValue::from_f64(identity.created_at as f64)
    );
    Ok(obj.into())
}

fn js_to_identity(js: &JsValue) -> Result<Identity, JsError> {
    let did = get_string(js, "did")?;
    let public_key = get_bytes(js, "publicKey")?;
    let private_key = get_bytes(js, "privateKey")?;
    let kyber_public_key = get_bytes(js, "kyberPublicKey")?;
    let kyber_secret_key = get_bytes(js, "kyberSecretKey")?;
    let node_id = get_bytes(js, "nodeId")?;
    let device_id = get_string(js, "deviceId")?;
    let master_seed = get_bytes(js, "masterSeed")?;
    let created_at = get_u64(js, "createdAt")?;

    Ok(Identity {
        did,
        public_key,
        private_key,
        kyber_public_key,
        kyber_secret_key,
        node_id,
        device_id,
        recovery_entropy: master_seed,
        created_at,
    })
}

fn public_identity_to_js(identity: &PublicIdentity) -> Result<JsValue, JsError> {
    let obj = Object::new();
    js_set!(&obj, "did", &JsValue::from_str(&identity.did));
    js_set!(
        &obj,
        "publicKey",
        &Uint8Array::from(&identity.public_key[..])
    );
    js_set!(
        &obj,
        "kyberPublicKey",
        &Uint8Array::from(&identity.kyber_public_key[..])
    );
    js_set!(&obj, "nodeId", &Uint8Array::from(&identity.node_id[..]));
    js_set!(&obj, "deviceId", &JsValue::from_str(&identity.device_id));
    js_set!(
        &obj,
        "createdAt",
        &JsValue::from_f64(identity.created_at as f64)
    );
    Ok(obj.into())
}

fn js_to_zhtp_request(js: &JsValue) -> Result<ZhtpRequest, JsError> {
    let method = get_string(js, "method")?;
    let uri = get_string(js, "uri")?;
    let version = get_string_or(js, "version", "ZHTP/1.0");
    let body = get_bytes_or(js, "body", Vec::new());
    let timestamp = get_u64_or(js, "timestamp", current_timestamp());
    let requester = get_string_opt(js, "requester");

    // Parse headers
    let headers_js = Reflect::get(js, &"headers".into()).unwrap_or(JsValue::UNDEFINED);

    let headers = if headers_js.is_undefined() || headers_js.is_null() {
        ZhtpHeaders::default()
    } else {
        ZhtpHeaders {
            content_type: get_string_opt(&headers_js, "contentType"),
            content_length: get_u64_or(&headers_js, "contentLength", body.len() as u64),
            privacy_level: get_u8_or(&headers_js, "privacyLevel", 0),
            encryption: get_string_or(&headers_js, "encryption", "chacha20-poly1305"),
            dao_fee: get_u64_or(&headers_js, "daoFee", 0),
            network_fee: get_u64_or(&headers_js, "networkFee", 0),
            cache_control: get_string_opt(&headers_js, "cacheControl"),
            custom: std::collections::HashMap::new(),
        }
    };

    Ok(ZhtpRequest {
        method,
        uri,
        version,
        headers,
        body,
        timestamp,
        requester,
    })
}

fn zhtp_response_to_js(response: &ZhtpResponse) -> Result<JsValue, JsError> {
    let obj = Object::new();
    js_set!(&obj, "status", &JsValue::from_f64(response.status as f64));
    js_set!(
        &obj,
        "statusText",
        &JsValue::from_str(&response.status_text)
    );
    js_set!(&obj, "version", &JsValue::from_str(&response.version));
    js_set!(&obj, "body", &Uint8Array::from(&response.body[..]));
    js_set!(
        &obj,
        "timestamp",
        &JsValue::from_f64(response.timestamp as f64)
    );

    // Headers
    let headers_obj = Object::new();
    if let Some(ref ct) = response.headers.content_type {
        js_set!(&headers_obj, "contentType", &JsValue::from_str(ct));
    }
    js_set!(
        &headers_obj,
        "contentLength",
        &JsValue::from_f64(response.headers.content_length as f64)
    );
    js_set!(
        &headers_obj,
        "privacyLevel",
        &JsValue::from_f64(response.headers.privacy_level as f64)
    );
    js_set!(
        &headers_obj,
        "encryption",
        &JsValue::from_str(&response.headers.encryption)
    );
    js_set!(
        &headers_obj,
        "daoFee",
        &JsValue::from_f64(response.headers.dao_fee as f64)
    );
    js_set!(
        &headers_obj,
        "networkFee",
        &JsValue::from_f64(response.headers.network_fee as f64)
    );
    if let Some(ref cc) = response.headers.cache_control {
        js_set!(&headers_obj, "cacheControl", &JsValue::from_str(cc));
    }
    js_set!(&obj, "headers", &headers_obj);

    Ok(obj.into())
}

// Helper to get string from JS object
fn get_string(obj: &JsValue, key: &str) -> Result<String, JsError> {
    let val =
        Reflect::get(obj, &key.into()).map_err(|_| js_err(&format!("Missing field: {}", key)))?;
    val.as_string()
        .ok_or_else(|| js_err(&format!("Field {} is not a string", key)))
}

fn get_string_or(obj: &JsValue, key: &str, default: &str) -> String {
    Reflect::get(obj, &key.into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| default.to_string())
}

fn get_string_opt(obj: &JsValue, key: &str) -> Option<String> {
    Reflect::get(obj, &key.into())
        .ok()
        .and_then(|v| v.as_string())
}

// Helper to get bytes from JS object (Uint8Array)
fn get_bytes(obj: &JsValue, key: &str) -> Result<Vec<u8>, JsError> {
    let val =
        Reflect::get(obj, &key.into()).map_err(|_| js_err(&format!("Missing field: {}", key)))?;
    let arr = Uint8Array::new(&val);
    Ok(arr.to_vec())
}

fn get_bytes_or(obj: &JsValue, key: &str, default: Vec<u8>) -> Vec<u8> {
    Reflect::get(obj, &key.into())
        .ok()
        .map(|v| Uint8Array::new(&v).to_vec())
        .unwrap_or(default)
}

// Helper to get u64 from JS object
fn get_u64(obj: &JsValue, key: &str) -> Result<u64, JsError> {
    let val =
        Reflect::get(obj, &key.into()).map_err(|_| js_err(&format!("Missing field: {}", key)))?;
    val.as_f64()
        .map(|f| f as u64)
        .ok_or_else(|| js_err(&format!("Field {} is not a number", key)))
}

fn get_u64_or(obj: &JsValue, key: &str, default: u64) -> u64 {
    Reflect::get(obj, &key.into())
        .ok()
        .and_then(|v| v.as_f64())
        .map(|f| f as u64)
        .unwrap_or(default)
}

fn get_u8_or(obj: &JsValue, key: &str, default: u8) -> u8 {
    Reflect::get(obj, &key.into())
        .ok()
        .and_then(|v| v.as_f64())
        .map(|f| f as u8)
        .unwrap_or(default)
}

fn current_timestamp() -> u64 {
    // In WASM, we can use js_sys::Date
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_random_bytes() {
        let bytes = random_bytes_wasm(32);
        assert_eq!(bytes.length(), 32);
    }

    #[wasm_bindgen_test]
    fn test_blake3_hash() {
        let data = b"test data";
        let hash = blake3_hash_wasm(data);
        assert_eq!(hash.length(), 32);
    }
}
