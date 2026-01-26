# Mobile Native ZHTP-over-QUIC Migration (iOS + Android)

This plan replaces HTTP/1.1-over-QUIC with the native ZHTP wire protocol so the server can drop the HTTP compatibility layer.

## References (server source of truth)
- Wire framing + CBOR: `lib-protocols/src/wire/mod.rs`
- Request/response structs: `lib-protocols/src/types/request.rs`, `lib-protocols/src/types/headers.rs`, `lib-protocols/src/types/method.rs`
- Control-plane auth flow: `zhtp/src/server/quic_handler.rs`

## Step-by-step implementation

### 1) Inventory current HTTP-over-QUIC usage
- iOS:
  - HTTP request strings built in `SovereignNetworkMobile/ios/SovereignNetworkMobile/NativeQuicModule.swift` and `SovereignNetworkMobile/ios/NativeQuicModule.swift`.
  - ALPNs include `zhtp/1.0` and `h3`.
- Android:
  - HTTP request strings built in `SovereignNetworkMobile/android/app/src/main/rust/quic-jni/src/quic_client.rs`.
  - ALPN currently `zhtp-public/1` but payloads are HTTP/1.1.

### 2) Add ZHTP wire model on mobile
Implement the following structs/enums to match Rust field names and types exactly:
- `ZhtpMethod` enum (names and variants match `lib-protocols/src/types/method.rs`).
- `ZhtpHeaders` struct (all fields from `lib-protocols/src/types/headers.rs`).
  - Important: `dao_fee` and `total_fees` are required `u64` fields (not optional). Default to `0` when not used.
- `ZhtpRequest` struct (from `lib-protocols/src/types/request.rs`).
- `AuthContext` struct (from `lib-protocols/src/wire/mod.rs`).
- `ZhtpRequestWire` and `ZhtpResponseWire` (from `lib-protocols/src/wire/mod.rs`).

Notes:
- CBOR encoding uses field names as map keys (serde default). Mobile must encode the same names.
- Use UTF-8 strings for all string fields.
- Byte fields (e.g., `request_id`, `session_id`, `request_mac`) are raw byte arrays in CBOR.

### 3) Implement wire framing (length prefix)
Wire format is:
```
len: u32 (big-endian) + CBOR payload bytes
```
Use the same max size limit as server: 16 MB (`MAX_MESSAGE_SIZE`).

### 4) Public (unauthenticated) request path
Use this for read-only public endpoints (e.g., Web4 content).

1) Build `ZhtpHeaders` with minimal required fields:
   - `content_type` (e.g., `application/json` or `application/octet-stream`)
   - `content_length` (bytes)
   - `dao_fee = 0`, `total_fees = 0`
2) Build `ZhtpRequest`:
   - `method`, `uri`, `headers`, `body`
   - `version = "1.0"` (matches `ZHTP_VERSION`)
   - `timestamp` = seconds since epoch (u64)
   - `requester = null`, `auth_proof = null`
3) Wrap in `ZhtpRequestWire`:
   - `version = 1`
   - `request_id = 16 random bytes`
   - `timestamp_ms = milliseconds since epoch`
   - `auth_context = null`
4) CBOR-encode, prepend 4-byte length, send on QUIC stream.
5) Read response:
   - Read 4-byte length, then payload bytes.
   - CBOR-decode `ZhtpResponseWire`.
   - Use `response.status`/`response.response` to populate client output.

### 5) Control-plane (authenticated) request path
Required for any privileged or mutating endpoints.

1) Implement UHP+Kyber handshake (client side) to get:
   - `session_id: [u8; 16]`
   - `client_did: String`
   - `master_key: [u8; 32]`
   - `peer_did` (server DID)
   - This must match server logic in `zhtp/src/server/quic_handler.rs`.
2) Derive `app_key` exactly like server:
   - `app_key = blake3("zhtp-web4-app-mac" || master_key || session_id || server_did || client_did)`
3) Compute canonical request hash (required for MAC):
   - Use the exact algorithm from `ZhtpRequestWire::compute_canonical_request_hash`:
     - `WIRE_VERSION` (u16 LE)
     - `request_id` (16 bytes)
     - `timestamp_ms` (u64 LE)
     - `method` encoded as byte (Get=0, Post=1, Put=2, Delete=3, Options=4, Head=5, Patch=6, Verify=7, Connect=8, Trace=9)
     - `uri` length (u32 LE) + bytes
     - Header fields in this fixed order and encoding:
       - `content_type` (present flag + length + bytes)
       - `content_length` (present flag + u64 LE)
       - `content_encoding` (present flag + length + bytes)
       - `cache_control` (present flag + length + bytes)
     - Body length (u32 LE) + bytes
4) Create `AuthContext`:
   - `session_id`
   - `client_did`
   - `sequence` (monotonic u64 per session)
   - `request_mac = blake3_keyed(app_key, session_id || sequence || request_hash)`
5) Set `auth_context` in `ZhtpRequestWire` and send as in step 4.

### 6) Update ALPN selection
Remove `zhtp/1.0` and `h3` from mobile clients:
- Public requests: ALPN `zhtp-public/1`
- Control-plane requests: ALPN `zhtp-uhp/1`
- Mesh connections (if needed): `zhtp-mesh/1`

### 7) Replace HTTP parsing in mobile clients
- Remove HTTP response parsing and status-line extraction.
- Convert `ZhtpResponseWire` into the mobile response object:
  - `status` = `response.status`
  - `body` = `response.response.body` (bytes or UTF-8 string)
  - `headers` = `response.response.headers` (ZHTP headers struct)

### 8) Platform-specific implementation notes

#### iOS (Swift)
- Implement a CBOR encoder/decoder that matches Rust field names.
  - Preferred: a CBOR library that supports explicit key ordering and raw bytes (e.g., SwiftCBOR).
- Add Swift models mirroring Rust structs.
- Update `NativeQuicModule.swift` and `SovereignNetworkMobile/NativeQuicModule.swift`:
  - Replace `sendHttpRequest`/`receiveHttpResponse` with ZHTP framing.
  - Update ALPN list in QUIC parameters.

#### Android (Rust JNI)
- Implement the ZHTP wire structs in `quic-jni` Rust:
  - Use `serde` + `ciborium` to encode/decode.
  - Keep QUIC transport in Rust and return parsed response to Kotlin/JS.
- Replace HTTP building/parsing in `quic_client.rs`.
- Update Kotlin bridge to map ZHTP response fields.

### 9) Validation checklist
- Public GET via QUIC returns valid ZHTP response (no HTTP status line).
- Control-plane request succeeds only after UHP handshake and valid MAC.
- Server logs show `NativeZhtp` detection (no `LegacyHttp`).
- Mobile can perform at least one read-only and one authenticated action.

### 10) Server cleanup (after mobile migration)
Once both platforms are migrated:
- Remove HTTP compatibility layer from `zhtp/src/server/zhtp/compatibility.rs`.
- Remove HTTP detection paths from `zhtp/src/server/quic_handler.rs` and `zhtp/src/server/protocol_detection.rs`.
- Remove HTTP-over-QUIC tests.
