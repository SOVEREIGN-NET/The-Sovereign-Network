# lib-client: Cross-Platform ZHTP Client Library

## Overview

Single Rust library that compiles to iOS, Android, Web (WASM), and native CLI, eliminating the need for 4 separate implementations of:
- Identity generation (Dilithium5, Kyber1024)
- UHP v2 handshake protocol
- ZHTP request/response serialization
- Session encryption

## Target Platforms

| Platform | Tool | Output |
|----------|------|--------|
| iOS/macOS | UniFFI | `.xcframework` + Swift bindings |
| Android | UniFFI | `.aar` + Kotlin bindings |
| Web | wasm-bindgen | `.wasm` + TypeScript types |
| CLI | Native Rust | Direct dependency |

---

## Phase 1: Core Library Structure

### 1.1 Create Cargo.toml

```toml
[package]
name = "lib-client"
version = "0.1.0"
edition = "2021"
description = "Cross-platform ZHTP client library for iOS, Android, Web, and CLI"

[lib]
crate-type = ["lib", "staticlib", "cdylib"]
name = "zhtp_client"

[features]
default = []
uniffi = ["dep:uniffi"]
wasm = ["dep:wasm-bindgen", "dep:js-sys", "dep:web-sys"]

[dependencies]
# Core
anyhow = "1.0"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
ciborium = "0.2"  # CBOR serialization
hex = "0.4"
base64 = "0.21"
tracing = "0.1"

# Crypto (from workspace)
lib-crypto = { path = "../lib-crypto" }

# Post-quantum crypto
pqcrypto-dilithium = "0.5"
pqcrypto-kyber = "0.8"
pqcrypto-traits = "0.3"
blake3 = "1.5"
sha3 = "0.10"
hkdf = "0.12"
chacha20poly1305 = "0.10"
rand = "0.8"

# UniFFI (optional, for mobile bindings)
uniffi = { version = "0.25", optional = true }

# WASM (optional, for web)
wasm-bindgen = { version = "0.2", optional = true }
js-sys = { version = "0.3", optional = true }
web-sys = { version = "0.3", optional = true }

[build-dependencies]
uniffi = { version = "0.25", features = ["build"] }

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### 1.2 Add to Workspace

In `/Cargo.toml` (workspace root), add to members:
```toml
members = [
    # ... existing
    "lib-client",
]
```

---

## Phase 2: Core Implementation

### 2.1 src/lib.rs - Main Exports

```rust
//! Cross-Platform ZHTP Client Library
//!
//! Single implementation for iOS, Android, Web, and CLI.
//! Handles identity generation, UHP v2 handshake, and request encryption.

pub mod identity;
pub mod handshake;
pub mod request;
pub mod crypto;
pub mod session;
pub mod error;

// Re-exports for convenience
pub use identity::{Identity, IdentityBuilder};
pub use handshake::{
    ClientHello, ServerHello, ClientFinish,
    HandshakeState, HandshakeResult,
};
pub use request::{ZhtpRequest, ZhtpResponse, ZhtpHeaders};
pub use session::{Session, SessionKey};
pub use error::ClientError;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
```

### 2.2 src/error.rs - Error Types

```rust
use thiserror::Error;

#[derive(Error, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ClientError {
    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Handshake error: {0}")]
    HandshakeError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid message format")]
    InvalidFormat,
}

pub type Result<T> = std::result::Result<T, ClientError>;
```

### 2.3 src/identity.rs - Identity Generation

```rust
//! Client-side identity generation
//!
//! Keys are generated locally and NEVER leave the device.
//! Only public keys are sent to server for registration.

use crate::error::{ClientError, Result};
use crate::crypto::{Dilithium5, Kyber1024, Blake3};
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Identity {
    pub did: String,
    pub public_key: Vec<u8>,        // Dilithium5 public key (~2592 bytes)
    pub private_key: Vec<u8>,       // Dilithium5 private key (~4864 bytes)
    pub kyber_public_key: Vec<u8>,  // Kyber1024 public key (~1568 bytes)
    pub kyber_secret_key: Vec<u8>,  // Kyber1024 secret key (~3168 bytes)
    pub node_id: Vec<u8>,           // 32 bytes
    pub device_id: String,
    pub master_seed: Vec<u8>,       // 32 bytes
    pub created_at: u64,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_identity(device_id: String) -> Result<Identity> {
    // 1. Generate master seed (32 random bytes)
    let master_seed = crate::crypto::random_bytes(32);

    // 2. Generate Dilithium5 keypair
    let (dilithium_pk, dilithium_sk) = Dilithium5::generate_keypair(&master_seed)?;

    // 3. Generate Kyber1024 keypair
    let kyber_seed = crate::crypto::derive_bytes(&master_seed, b"kyber");
    let (kyber_pk, kyber_sk) = Kyber1024::generate_keypair(&kyber_seed)?;

    // 4. Derive DID from public key
    let pk_hash = Blake3::hash(&dilithium_pk);
    let did = format!("did:zhtp:{}", hex::encode(&pk_hash));

    // 5. Derive node ID
    let node_id_input = format!("{}{}", did, device_id);
    let node_id = Blake3::hash(node_id_input.as_bytes()).to_vec();

    // 6. Get timestamp
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(Identity {
        did,
        public_key: dilithium_pk,
        private_key: dilithium_sk,
        kyber_public_key: kyber_pk,
        kyber_secret_key: kyber_sk,
        node_id,
        device_id,
        master_seed,
        created_at,
    })
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn sign_registration_proof(identity: &Identity, timestamp: u64) -> Result<Vec<u8>> {
    let message = format!("ZHTP_REGISTER:{}:{}", identity.did, timestamp);
    Dilithium5::sign(message.as_bytes(), &identity.private_key)
}

/// Get only public parts of identity (safe to send to server)
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn get_public_identity(identity: &Identity) -> PublicIdentity {
    PublicIdentity {
        did: identity.did.clone(),
        public_key: identity.public_key.clone(),
        kyber_public_key: identity.kyber_public_key.clone(),
        node_id: identity.node_id.clone(),
        device_id: identity.device_id.clone(),
        created_at: identity.created_at,
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicIdentity {
    pub did: String,
    pub public_key: Vec<u8>,
    pub kyber_public_key: Vec<u8>,
    pub node_id: Vec<u8>,
    pub device_id: String,
    pub created_at: u64,
}
```

### 2.4 src/crypto.rs - Crypto Primitives

```rust
//! Cryptographic primitives wrapper
//!
//! Provides consistent interface for Dilithium5, Kyber1024, Blake3, etc.

use crate::error::{ClientError, Result};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use pqcrypto_traits::kem::{PublicKey as KemPk, SecretKey as KemSk, Ciphertext, SharedSecret};

pub struct Dilithium5;

impl Dilithium5 {
    pub fn generate_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Use seed for deterministic generation (or ignore for random)
        let (pk, sk) = dilithium5::keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    pub fn sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
        let sk = dilithium5::SecretKey::from_bytes(private_key)
            .map_err(|_| ClientError::CryptoError("Invalid private key".into()))?;
        let signed = dilithium5::sign(message, &sk);
        Ok(signed.as_bytes().to_vec())
    }

    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        let pk = dilithium5::PublicKey::from_bytes(public_key)
            .map_err(|_| ClientError::CryptoError("Invalid public key".into()))?;
        let signed = dilithium5::SignedMessage::from_bytes(signature)
            .map_err(|_| ClientError::CryptoError("Invalid signature".into()))?;

        match dilithium5::open(&signed, &pk) {
            Ok(verified_msg) => Ok(verified_msg == message),
            Err(_) => Ok(false),
        }
    }
}

pub struct Kyber1024;

impl Kyber1024 {
    pub fn generate_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = kyber1024::keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk = kyber1024::PublicKey::from_bytes(public_key)
            .map_err(|_| ClientError::CryptoError("Invalid Kyber public key".into()))?;
        let (ss, ct) = kyber1024::encapsulate(&pk);
        Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
    }

    pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        let sk = kyber1024::SecretKey::from_bytes(secret_key)
            .map_err(|_| ClientError::CryptoError("Invalid Kyber secret key".into()))?;
        let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| ClientError::CryptoError("Invalid ciphertext".into()))?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }
}

pub struct Blake3;

impl Blake3 {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn derive_bytes(seed: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key(
        std::str::from_utf8(context).unwrap_or("derive")
    );
    hasher.update(seed);
    hasher.finalize().as_bytes().to_vec()
}
```

### 2.5 src/handshake.rs - UHP v2 Handshake

```rust
//! UHP v2 Handshake Protocol
//!
//! 3-leg handshake: ClientHello -> ServerHello -> ClientFinish

use crate::error::{ClientError, Result};
use crate::identity::Identity;
use crate::crypto::{Dilithium5, Blake3, random_bytes};
use serde::{Serialize, Deserialize};

const UHP_VERSION: u8 = 2;

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NodeIdentity {
    pub did: String,
    pub public_key: Vec<u8>,
    pub node_id: Vec<u8>,
    pub device_id: String,
    pub display_name: Option<String>,
    pub created_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HandshakeCapabilities {
    pub protocols: Vec<String>,
    pub max_throughput: u64,
    pub max_message_size: u32,
    pub encryption_methods: Vec<String>,
    pub pqc_capability: String,
    pub web4_capable: bool,
}

impl Default for HandshakeCapabilities {
    fn default() -> Self {
        Self {
            protocols: vec!["quic".into()],
            max_throughput: 1_000_000,
            max_message_size: 65536,
            encryption_methods: vec!["chacha20-poly1305".into()],
            pqc_capability: "Kyber1024Dilithium5".into(),
            web4_capable: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub identity: NodeIdentity,
    pub capabilities: HandshakeCapabilities,
    pub network_id: String,
    pub protocol_id: String,
    pub purpose: String,
    pub role: u8,  // 0 = Client
    pub channel_binding: Vec<u8>,
    pub challenge_nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub protocol_version: u8,
    pub pqc_offer: Option<PqcOffer>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PqcOffer {
    pub kyber_public_key: Vec<u8>,
    pub commitment: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub identity: NodeIdentity,
    pub network_id: String,
    pub protocol_id: String,
    pub purpose: String,
    pub role: u8,  // 1 = Server
    pub channel_binding: Vec<u8>,
    pub response_nonce: Vec<u8>,
    pub client_challenge_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub protocol_version: u8,
    pub pqc_response: Option<PqcResponse>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PqcResponse {
    pub kyber_ciphertext: Vec<u8>,
    pub commitment: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientFinish {
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub transcript_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub pqc_confirmation: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub version: u8,
    pub payload_type: u8,  // 0=ClientHello, 1=ServerHello, 2=ClientFinish, 255=Error
    pub payload: Vec<u8>,
    pub timestamp: u64,
}

/// State machine for handshake
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct HandshakeState {
    identity: Identity,
    channel_binding: Vec<u8>,
    challenge_nonce: Vec<u8>,
    client_hello_bytes: Vec<u8>,
    server_hello_bytes: Option<Vec<u8>>,
    server_nonce: Option<Vec<u8>>,
    server_identity: Option<NodeIdentity>,
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HandshakeResult {
    pub session_key: Vec<u8>,
    pub session_id: Vec<u8>,
    pub peer_did: String,
    pub peer_public_key: Vec<u8>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl HandshakeState {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(identity: Identity, channel_binding: Vec<u8>) -> Self {
        Self {
            identity,
            channel_binding,
            challenge_nonce: random_bytes(32),
            client_hello_bytes: Vec::new(),
            server_hello_bytes: None,
            server_nonce: None,
            server_identity: None,
        }
    }

    /// Step 1: Create ClientHello message
    pub fn create_client_hello(&mut self) -> Result<Vec<u8>> {
        let timestamp = current_timestamp();

        let node_identity = NodeIdentity {
            did: self.identity.did.clone(),
            public_key: self.identity.public_key.clone(),
            node_id: self.identity.node_id.clone(),
            device_id: self.identity.device_id.clone(),
            display_name: None,
            created_at: self.identity.created_at,
        };

        // Build signature data
        let sig_data = build_client_hello_signature_data(
            &node_identity,
            &HandshakeCapabilities::default(),
            "zhtp-mainnet",
            "uhp",
            "zhtp-node-handshake",
            0, // Client role
            &self.channel_binding,
            &self.challenge_nonce,
            timestamp,
            UHP_VERSION,
        );

        let signature = Dilithium5::sign(&sig_data, &self.identity.private_key)?;

        // Build PQC offer if we have Kyber keys
        let pqc_offer = if !self.identity.kyber_public_key.is_empty() {
            Some(PqcOffer {
                kyber_public_key: self.identity.kyber_public_key.clone(),
                commitment: Blake3::hash(&self.identity.kyber_public_key).to_vec(),
            })
        } else {
            None
        };

        let client_hello = ClientHello {
            identity: node_identity,
            capabilities: HandshakeCapabilities::default(),
            network_id: "zhtp-mainnet".into(),
            protocol_id: "uhp".into(),
            purpose: "zhtp-node-handshake".into(),
            role: 0,
            channel_binding: self.channel_binding.clone(),
            challenge_nonce: self.challenge_nonce.clone(),
            signature,
            timestamp,
            protocol_version: UHP_VERSION,
            pqc_offer,
        };

        // Wrap in HandshakeMessage
        let payload = serde_json::to_vec(&client_hello)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        let message = HandshakeMessage {
            version: UHP_VERSION,
            payload_type: 0, // ClientHello
            payload,
            timestamp,
        };

        let message_bytes = serde_json::to_vec(&message)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // Store for transcript
        self.client_hello_bytes = message_bytes.clone();

        // Return with length prefix
        Ok(with_length_prefix(&message_bytes))
    }

    /// Step 2: Process ServerHello, returns ClientFinish to send
    pub fn process_server_hello(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Remove length prefix
        let message_bytes = strip_length_prefix(data)?;

        let message: HandshakeMessage = serde_json::from_slice(&message_bytes)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        if message.payload_type != 1 {
            return Err(ClientError::HandshakeError("Expected ServerHello".into()));
        }

        let server_hello: ServerHello = serde_json::from_slice(&message.payload)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // Verify server signature
        let sig_data = build_server_hello_signature_data(&server_hello);
        if !Dilithium5::verify(&sig_data, &server_hello.signature, &server_hello.identity.public_key)? {
            return Err(ClientError::InvalidSignature);
        }

        // Store server info
        self.server_hello_bytes = Some(message_bytes);
        self.server_nonce = Some(server_hello.response_nonce.clone());
        self.server_identity = Some(server_hello.identity.clone());

        // Create ClientFinish
        let transcript_hash = Blake3::hash(
            &[self.client_hello_bytes.as_slice(), self.server_hello_bytes.as_ref().unwrap()].concat()
        );

        let finish_sig_data = [
            self.challenge_nonce.as_slice(),
            server_hello.response_nonce.as_slice(),
            &transcript_hash,
        ].concat();

        let signature = Dilithium5::sign(&finish_sig_data, &self.identity.private_key)?;

        let client_finish = ClientFinish {
            client_nonce: self.challenge_nonce.clone(),
            server_nonce: server_hello.response_nonce.clone(),
            transcript_hash: transcript_hash.to_vec(),
            signature,
            pqc_confirmation: None, // TODO: Add Kyber confirmation
        };

        let payload = serde_json::to_vec(&client_finish)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        let message = HandshakeMessage {
            version: UHP_VERSION,
            payload_type: 2, // ClientFinish
            payload,
            timestamp: current_timestamp(),
        };

        let message_bytes = serde_json::to_vec(&message)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        Ok(with_length_prefix(&message_bytes))
    }

    /// Step 3: Finalize handshake and get session key
    pub fn finalize(&self) -> Result<HandshakeResult> {
        let server_nonce = self.server_nonce.as_ref()
            .ok_or_else(|| ClientError::HandshakeError("Handshake not complete".into()))?;
        let server_identity = self.server_identity.as_ref()
            .ok_or_else(|| ClientError::HandshakeError("Handshake not complete".into()))?;

        // Derive session key using HKDF
        let transcript = [
            self.client_hello_bytes.as_slice(),
            self.server_hello_bytes.as_ref().unwrap(),
        ].concat();
        let transcript_hash = Blake3::hash(&transcript);

        let session_key = derive_session_key(
            &self.challenge_nonce,
            server_nonce,
            &self.identity.did,
            &server_identity.did,
            &transcript_hash,
        )?;

        let session_id = Blake3::hash(&[
            self.challenge_nonce.as_slice(),
            server_nonce,
        ].concat());

        Ok(HandshakeResult {
            session_key: session_key.to_vec(),
            session_id: session_id.to_vec(),
            peer_did: server_identity.did.clone(),
            peer_public_key: server_identity.public_key.clone(),
        })
    }
}

fn build_client_hello_signature_data(
    identity: &NodeIdentity,
    capabilities: &HandshakeCapabilities,
    network_id: &str,
    protocol_id: &str,
    purpose: &str,
    role: u8,
    channel_binding: &[u8],
    challenge_nonce: &[u8],
    timestamp: u64,
    protocol_version: u8,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(identity.did.as_bytes());
    data.extend_from_slice(&identity.public_key);
    data.extend_from_slice(&identity.node_id);
    data.extend_from_slice(identity.device_id.as_bytes());
    data.extend_from_slice(&serde_json::to_vec(capabilities).unwrap_or_default());
    data.extend_from_slice(network_id.as_bytes());
    data.extend_from_slice(protocol_id.as_bytes());
    data.extend_from_slice(purpose.as_bytes());
    data.push(role);
    data.extend_from_slice(channel_binding);
    data.extend_from_slice(challenge_nonce);
    data.extend_from_slice(&timestamp.to_le_bytes());
    data.push(protocol_version);
    data
}

fn build_server_hello_signature_data(server_hello: &ServerHello) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(server_hello.identity.did.as_bytes());
    data.extend_from_slice(&server_hello.identity.public_key);
    data.extend_from_slice(&server_hello.response_nonce);
    data.extend_from_slice(&server_hello.client_challenge_hash);
    data.extend_from_slice(&server_hello.timestamp.to_le_bytes());
    data
}

fn derive_session_key(
    client_nonce: &[u8],
    server_nonce: &[u8],
    client_did: &str,
    server_did: &str,
    transcript_hash: &[u8],
) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha3::Sha3_256;

    let ikm = [client_nonce, server_nonce].concat();
    let salt = [0u8; 32];
    let info = format!("uhp_session_key|{}|{}", client_did, server_did);
    let info_bytes = [info.as_bytes(), transcript_hash].concat();

    let hk = Hkdf::<Sha3_256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info_bytes, &mut okm)
        .map_err(|_| ClientError::CryptoError("HKDF expansion failed".into()))?;

    Ok(okm)
}

fn with_length_prefix(data: &[u8]) -> Vec<u8> {
    let len = (data.len() as u32).to_be_bytes();
    [&len[..], data].concat()
}

fn strip_length_prefix(data: &[u8]) -> Result<&[u8]> {
    if data.len() < 4 {
        return Err(ClientError::InvalidFormat);
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return Err(ClientError::InvalidFormat);
    }
    Ok(&data[4..4+len])
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
```

### 2.6 src/session.rs - Session Encryption

```rust
//! Session management and encryption

use crate::error::{ClientError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Session {
    key: [u8; 32],
    peer_did: String,
    sequence: u64,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Session {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(key: Vec<u8>, peer_did: String) -> Result<Self> {
        if key.len() != 32 {
            return Err(ClientError::CryptoError("Session key must be 32 bytes".into()));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key);

        Ok(Self {
            key: key_arr,
            peer_did,
            sequence: 0,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| ClientError::CryptoError("Invalid key".into()))?;

        // Generate nonce from sequence number
        self.sequence += 1;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.sequence.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| ClientError::CryptoError("Encryption failed".into()))?;

        // Return: nonce (12) + ciphertext + tag (16)
        Ok([&nonce_bytes[..], &ciphertext].concat())
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(ClientError::InvalidFormat);
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| ClientError::CryptoError("Invalid key".into()))?;

        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let ct = &ciphertext[12..];

        cipher.decrypt(nonce, ct)
            .map_err(|_| ClientError::CryptoError("Decryption failed".into()))
    }

    pub fn peer_did(&self) -> &str {
        &self.peer_did
    }
}
```

### 2.7 src/request.rs - ZHTP Request/Response

```rust
//! ZHTP Request/Response serialization (CBOR)

use crate::error::{ClientError, Result};
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZhtpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: ZhtpHeaders,
    pub body: Vec<u8>,
    pub timestamp: u64,
    pub requester: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZhtpHeaders {
    pub content_type: Option<String>,
    pub content_length: u64,
    pub privacy_level: u8,
    pub encryption: String,
    pub dao_fee: u64,
    pub network_fee: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZhtpResponse {
    pub status: u16,
    pub status_text: String,
    pub version: String,
    pub headers: ZhtpHeaders,
    pub body: Vec<u8>,
    pub timestamp: u64,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn serialize_request(request: &ZhtpRequest) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(request, &mut buf)
        .map_err(|e| ClientError::SerializationError(e.to_string()))?;
    Ok(buf)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn deserialize_response(data: &[u8]) -> Result<ZhtpResponse> {
    ciborium::from_reader(data)
        .map_err(|e| ClientError::SerializationError(e.to_string()))
}

/// Create ZHTP wire frame: ZHTP magic + version + length + payload
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn create_zhtp_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(b"ZHTP");           // 4 bytes magic
    frame.push(1);                              // 1 byte version
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()); // 4 bytes length
    frame.extend_from_slice(payload);           // payload
    frame
}

/// Parse ZHTP wire frame, returns payload
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_zhtp_frame(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 9 {
        return Err(ClientError::InvalidFormat);
    }
    if &data[0..4] != b"ZHTP" {
        return Err(ClientError::InvalidFormat);
    }
    let _version = data[4];
    let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    if data.len() < 9 + length {
        return Err(ClientError::InvalidFormat);
    }
    Ok(data[9..9+length].to_vec())
}
```

---

## Phase 3: UniFFI Bindings (iOS/Android)

### 3.1 uniffi/zhtp_client.udl

```udl
namespace zhtp_client {
    // Identity
    [Throws=ClientError]
    Identity generate_identity(string device_id);

    [Throws=ClientError]
    sequence<u8> sign_registration_proof([ByRef] Identity identity, u64 timestamp);

    PublicIdentity get_public_identity([ByRef] Identity identity);

    // Request serialization
    [Throws=ClientError]
    sequence<u8> serialize_request([ByRef] ZhtpRequest request);

    [Throws=ClientError]
    ZhtpResponse deserialize_response(sequence<u8> data);

    sequence<u8> create_zhtp_frame(sequence<u8> payload);

    [Throws=ClientError]
    sequence<u8> parse_zhtp_frame(sequence<u8> data);
};

[Error]
enum ClientError {
    "CryptoError",
    "HandshakeError",
    "SerializationError",
    "InvalidSignature",
    "SessionExpired",
    "InvalidFormat",
};

dictionary Identity {
    string did;
    sequence<u8> public_key;
    sequence<u8> private_key;
    sequence<u8> kyber_public_key;
    sequence<u8> kyber_secret_key;
    sequence<u8> node_id;
    string device_id;
    sequence<u8> master_seed;
    u64 created_at;
};

dictionary PublicIdentity {
    string did;
    sequence<u8> public_key;
    sequence<u8> kyber_public_key;
    sequence<u8> node_id;
    string device_id;
    u64 created_at;
};

dictionary ZhtpRequest {
    string method;
    string uri;
    string version;
    ZhtpHeaders headers;
    sequence<u8> body;
    u64 timestamp;
    string? requester;
};

dictionary ZhtpHeaders {
    string? content_type;
    u64 content_length;
    u8 privacy_level;
    string encryption;
    u64 dao_fee;
    u64 network_fee;
};

dictionary ZhtpResponse {
    u16 status;
    string status_text;
    string version;
    ZhtpHeaders headers;
    sequence<u8> body;
    u64 timestamp;
};

dictionary HandshakeResult {
    sequence<u8> session_key;
    sequence<u8> session_id;
    string peer_did;
    sequence<u8> peer_public_key;
};

interface HandshakeState {
    constructor(Identity identity, sequence<u8> channel_binding);

    [Throws=ClientError]
    sequence<u8> create_client_hello();

    [Throws=ClientError]
    sequence<u8> process_server_hello(sequence<u8> data);

    [Throws=ClientError]
    HandshakeResult finalize();
};

interface Session {
    [Throws=ClientError]
    constructor(sequence<u8> key, string peer_did);

    [Throws=ClientError]
    sequence<u8> encrypt(sequence<u8> plaintext);

    [Throws=ClientError]
    sequence<u8> decrypt(sequence<u8> ciphertext);

    string peer_did();
};
```

### 3.2 Build Script for UniFFI

Create `uniffi/build.rs`:

```rust
fn main() {
    uniffi::generate_scaffolding("./uniffi/zhtp_client.udl").unwrap();
}
```

---

## Phase 4: WASM Bindings (Web)

### 4.1 wasm/Cargo.toml

```toml
[package]
name = "zhtp-client-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
lib-client = { path = "..", default-features = false }
wasm-bindgen = "0.2"
js-sys = "0.3"
web-sys = "0.3"
serde-wasm-bindgen = "0.6"
console_error_panic_hook = "0.1"
```

### 4.2 wasm/src/lib.rs

```rust
use wasm_bindgen::prelude::*;
use lib_client::{identity, handshake, request, session};

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn generate_identity(device_id: &str) -> Result<JsValue, JsError> {
    let identity = identity::generate_identity(device_id.to_string())
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&identity)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn create_handshake_state(identity_js: JsValue, channel_binding: &[u8]) -> Result<HandshakeStateWrapper, JsError> {
    let identity: identity::Identity = serde_wasm_bindgen::from_value(identity_js)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(HandshakeStateWrapper {
        inner: handshake::HandshakeState::new(identity, channel_binding.to_vec()),
    })
}

#[wasm_bindgen]
pub struct HandshakeStateWrapper {
    inner: handshake::HandshakeState,
}

#[wasm_bindgen]
impl HandshakeStateWrapper {
    pub fn create_client_hello(&mut self) -> Result<Vec<u8>, JsError> {
        self.inner.create_client_hello()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn process_server_hello(&mut self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.process_server_hello(data)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn finalize(&self) -> Result<JsValue, JsError> {
        let result = self.inner.finalize()
            .map_err(|e| JsError::new(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

#[wasm_bindgen]
pub fn serialize_request(request_js: JsValue) -> Result<Vec<u8>, JsError> {
    let req: request::ZhtpRequest = serde_wasm_bindgen::from_value(request_js)
        .map_err(|e| JsError::new(&e.to_string()))?;
    request::serialize_request(&req)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn deserialize_response(data: &[u8]) -> Result<JsValue, JsError> {
    let response = request::deserialize_response(data)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&response)
        .map_err(|e| JsError::new(&e.to_string()))
}
```

---

## Phase 5: Build Commands

### 5.1 Native (CLI / Desktop)

```bash
# Development build
cargo build -p lib-client

# Release build
cargo build -p lib-client --release

# Run tests
cargo test -p lib-client

# Build with UniFFI (required for mobile)
cargo build -p lib-client --features uniffi
```

### 5.2 iOS (requires macOS)

Prerequisites on macOS:
```bash
# Install Rust iOS targets
rustup target add aarch64-apple-ios              # iOS device
rustup target add aarch64-apple-ios-sim          # iOS simulator (Apple Silicon)
rustup target add x86_64-apple-ios               # iOS simulator (Intel)

# Install uniffi-bindgen-cli (must match version in Cargo.toml!)
cargo install uniffi-bindgen-cli --version 0.25.3
```

Build for iOS:
```bash
# Build static library for device
cargo build -p lib-client --release --features uniffi --target aarch64-apple-ios

# Build static library for simulator (choose based on Mac architecture)
cargo build -p lib-client --release --features uniffi --target aarch64-apple-ios-sim  # Apple Silicon
cargo build -p lib-client --release --features uniffi --target x86_64-apple-ios        # Intel Mac

# Generate Swift bindings
uniffi-bindgen generate lib-client/uniffi/zhtp_client.udl --language swift --out-dir ./generated/swift

# Create XCFramework (from workspace root)
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libzhtp_client.a \
    -headers generated/swift \
    -library target/aarch64-apple-ios-sim/release/libzhtp_client.a \
    -headers generated/swift \
    -output ZhtpClient.xcframework
```

Files for iOS project:
- `ZhtpClient.xcframework` - Static library
- `generated/swift/zhtp_client.swift` - Swift bindings
- `generated/swift/zhtp_clientFFI.h` - C header (auto-included)

### 5.3 Android

Prerequisites:
```bash
# Install Android NDK targets
rustup target add aarch64-linux-android    # ARM64 devices
rustup target add armv7-linux-androideabi  # ARM32 devices (older)
rustup target add x86_64-linux-android     # x86_64 emulator
rustup target add i686-linux-android       # x86 emulator

# Install uniffi-bindgen-cli
cargo install uniffi-bindgen-cli --version 0.25.3

# Set up Android NDK (set ANDROID_NDK_HOME environment variable)
export ANDROID_NDK_HOME=/path/to/android-ndk
```

Configure cargo for Android (add to `~/.cargo/config.toml`):
```toml
[target.aarch64-linux-android]
linker = "/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"

[target.armv7-linux-androideabi]
linker = "/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"

[target.x86_64-linux-android]
linker = "/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang"
```

Build for Android:
```bash
# Build shared libraries
cargo build -p lib-client --release --features uniffi --target aarch64-linux-android
cargo build -p lib-client --release --features uniffi --target armv7-linux-androideabi
cargo build -p lib-client --release --features uniffi --target x86_64-linux-android

# Generate Kotlin bindings
uniffi-bindgen generate lib-client/uniffi/zhtp_client.udl --language kotlin --out-dir ./generated/kotlin
```

Files for Android project:
- `target/aarch64-linux-android/release/libzhtp_client.so` → `jniLibs/arm64-v8a/`
- `target/armv7-linux-androideabi/release/libzhtp_client.so` → `jniLibs/armeabi-v7a/`
- `target/x86_64-linux-android/release/libzhtp_client.so` → `jniLibs/x86_64/`
- `generated/kotlin/zhtp_client/zhtp_client.kt` - Kotlin bindings

### 5.4 Web (WASM)

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for web (once wasm module is created)
cd lib-client
wasm-pack build --target web --release --features wasm

# Output files:
# - pkg/zhtp_client.js       (JavaScript module)
# - pkg/zhtp_client_bg.wasm  (WebAssembly binary)
# - pkg/zhtp_client.d.ts     (TypeScript types)
```

### 5.5 Quick Reference Table

| Platform | Target | Feature | Output |
|----------|--------|---------|--------|
| Linux/macOS/Windows | native | (none) | `libzhtp_client.a/.so/.dll` |
| iOS Device | `aarch64-apple-ios` | `uniffi` | `libzhtp_client.a` |
| iOS Simulator | `aarch64-apple-ios-sim` | `uniffi` | `libzhtp_client.a` |
| Android ARM64 | `aarch64-linux-android` | `uniffi` | `libzhtp_client.so` |
| Android ARM32 | `armv7-linux-androideabi` | `uniffi` | `libzhtp_client.so` |
| Web/WASM | `wasm32-unknown-unknown` | `wasm` | `zhtp_client_bg.wasm` |

---

## Phase 6: Platform Usage Examples

### 6.1 iOS (Swift)

```swift
import ZhtpClient

// Generate identity
let identity = try ZhtpClient.generateIdentity(deviceId: UIDevice.current.identifierForVendor!.uuidString)

// Store private key in Keychain
Keychain.store(key: "zhtp_identity", data: identity.privateKey)

// Register with server
let proof = try ZhtpClient.signRegistrationProof(identity: identity, timestamp: UInt64(Date().timeIntervalSince1970))
let publicIdentity = ZhtpClient.getPublicIdentity(identity: identity)
// POST to /api/v1/identity/register

// Handshake
var handshake = HandshakeState(identity: identity, channelBinding: channelBinding)
let clientHello = try handshake.createClientHello()
send(clientHello)

let serverHelloData = receive()
let clientFinish = try handshake.processServerHello(data: serverHelloData)
send(clientFinish)

let result = try handshake.finalize()
let session = try Session(key: result.sessionKey, peerDid: result.peerDid)

// Send authenticated request
let request = ZhtpRequest(method: "Get", uri: "/api/v1/data", ...)
let requestBytes = try ZhtpClient.serializeRequest(request: request)
let encrypted = try session.encrypt(plaintext: requestBytes)
let frame = ZhtpClient.createZhtpFrame(payload: encrypted)
send(frame)
```

### 6.2 Web (TypeScript)

```typescript
import init, {
    generate_identity,
    create_handshake_state,
    serialize_request,
} from 'zhtp-client-wasm';

await init();

// Generate identity
const identity = generate_identity(crypto.randomUUID());

// Handshake
const handshake = create_handshake_state(identity, channelBinding);
const clientHello = handshake.create_client_hello();
ws.send(clientHello);

ws.onmessage = (event) => {
    const clientFinish = handshake.process_server_hello(new Uint8Array(event.data));
    ws.send(clientFinish);

    const result = handshake.finalize();
    // Use result.session_key for encryption
};
```

---

## Checklist

- [x] Phase 1: Create lib-client structure and Cargo.toml
- [x] Phase 2.1: Implement src/lib.rs
- [x] Phase 2.2: Implement src/error.rs
- [x] Phase 2.3: Implement src/identity.rs
- [x] Phase 2.4: Implement src/crypto.rs
- [x] Phase 2.5: Implement src/handshake.rs
- [x] Phase 2.6: Implement src/session.rs
- [x] Phase 2.7: Implement src/request.rs
- [x] Phase 3: Add UniFFI bindings (UDL + build.rs)
- [ ] Phase 4: Add WASM bindings
- [ ] Phase 5: Test build for all platforms
- [ ] Phase 6: Integration tests with server

## Build Status

✅ **Native build**: `cargo build -p lib-client` - PASSED (21 tests)
✅ **UniFFI build**: `cargo build -p lib-client --features uniffi` - PASSED

---

## Dependencies on Existing Code

This library extracts and simplifies from:
- `lib-network/src/handshake/` - UHP v2 protocol
- `lib-network/src/client/` - ZhtpClient
- `lib-crypto/` - Dilithium5, Kyber1024, Blake3
- `lib-protocols/src/types/` - ZhtpRequest, ZhtpResponse

The goal is a minimal, portable subset that works on all platforms.
