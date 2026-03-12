# Investigation: Mobile + Web App Authentication Delegation

## Problem Statement

- **Web App**: Cannot store private keys (browser security limitations)
- **Mobile App**: Holds the keys, can sign
- **Goal**: Web app initiates actions, mobile app approves/signs
- **Challenge**: Establish authenticated session without web app ever holding keys

---

## Authentication Pattern Options

### Option 1: Challenge-Response with Session Tokens (Recommended)

```
┌──────────┐                    ┌──────────┐                    ┌──────┐
│  Web App │ ──1. init auth───▶ │  Nodes   │ ──2. challenge───▶ │Mobile│
│ (no key) │                    │          │                    │(keys)│
│          │ ◀──6. session───── │          │ ◀──3. scan QR───── │      │
│          │                    │          │                    │      │
│          │ ──7. API calls────▶│          │                    │      │
│          │  (bearer token)    │          │ ◀──4. sign─────────│      │
│          │                    │          │                    │      │
│          │ ◀──────────────────│◀──5. verify───────────────────│      │
└──────────┘                    └──────────┘                    └──────┘
```

**Flow:**
1. Web app requests authentication initiation
2. Node generates challenge + session ID, returns QR code
3. Mobile app scans QR (contains: challenge, session ID, node endpoint)
4. Mobile app signs challenge with private key
5. Mobile sends signature + pubkey to node
6. Node verifies, issues session token to web app
7. Web app uses session token for subsequent API calls

**Pros:**
- Simple, well-understood pattern
- Web app never touches keys
- Session can have limited scope/time

**Cons:**
- Requires mobile app online during auth
- Session token is a bearer token (theft risk)

---

### Option 2: Delegation Certificates (On-Chain)

Mobile app issues a time-bound delegation certificate that allows the web app to act on its behalf for specific operations.

```rust
// Delegation Certificate Structure
struct DelegationCertificate {
    delegator: DID,           // Mobile app's DID
    delegate: Option<DID>,    // Web app's DID (optional, can be session-based)
    capabilities: Vec<Capability>, // What actions are allowed
    expiry: BlockHeight,      // When delegation expires
    nonce: u64,               // Replay protection
    
    // Signature by delegator (mobile app)
    signature: Signature,
}

enum Capability {
    ReadBalance,
    SubmitTx { max_amount: u64, to_whitelist: Vec<Address> },
    VoteGovernance,
    // ... granular permissions
}
```

**Flow:**
1. Mobile app creates delegation cert with limited scope
2. Mobile shares cert with web app (via QR, link, cloud backup)
3. Web app presents cert + its own proof to nodes
4. Nodes verify cert on-chain or via state proof

**Pros:**
- No session state needed on nodes
- Audit trail on-chain
- Revocable by delegator

**Cons:**
- More complex implementation
- Certificate management overhead
- Privacy concerns (delegation visible)

---

### Option 3: MPC Threshold Signing (Advanced)

Use Multi-Party Computation where:
- Mobile app holds key share 1
- Web app (or service) holds key share 2
- Both needed to sign
- Nodes verify threshold signature

**Not recommended for this use case** - adds complexity without clear benefit over delegation.

---

### Option 4: WalletConnect-style Relay

Use a relay server (or p2p) for communication:

```
Web App ──▶ Relay Server ◀──▶ Mobile App
              (WSS/p2p)
```

**Flow:**
1. Web app generates connection request, shows QR
2. Mobile scans, establishes encrypted channel via relay
3. All signing requests go through relay to mobile
4. Mobile approves/denies, sends signature back

**Pros:**
- Real-time interaction
- No session tokens
- Can sign multiple transactions

**Cons:**
- Requires persistent connection
- Relay server dependency (or complex p2p)
- Mobile must stay online during entire session

---

## Recommended Architecture: Hybrid Approach

Combine **Option 1 (Session Tokens)** for auth with **Option 2 (Delegation)** for transaction signing.

### Phase 1: Authentication (Session Establishment)

```rust
// Node API Endpoints

// 1. Initiate authentication
POST /auth/challenge
Request:  { "client_type": "web", "requested_capabilities": ["read", "send_tx"] }
Response: { 
    "session_id": "uuid",
    "challenge": "base64(32_bytes_random)",
    "expires_at": "timestamp",
    "qr_data": "zhtp://auth?sid=xxx&ch=xxx&node=xxx"  // For mobile scanning
}

// 2. Mobile submits signed challenge
POST /auth/verify
Request: {
    "session_id": "uuid",
    "public_key": "base64",
    "signature": "base64(sign(challenge))",
    "device_attestation": "optional"
}
Response: {
    "session_token": "jwt_or_opaque_token",
    "refresh_token": "for_long_lived_sessions",
    "expires_in": 3600,
    "granted_capabilities": ["read", "send_tx"]
}
```

### Phase 2: Transaction Signing (Delegation)

For sensitive operations, use delegated signing:

```rust
// Web app wants to send a transaction
POST /tx/prepare
Authorization: Bearer <session_token>
Request: {
    "to": "address",
    "amount": 1000,
    "token": "SOV"
}

// Node responds with unsigned transaction + signing request
Response: {
    "tx_hash": "hash_of_unsigned_tx",
    "unsigned_tx": "base64",
    "signing_request": {
        "request_id": "uuid",
        "payload_to_sign": "hash",
        "expires_in": 300
    }
}

// Web app shows QR or sends push notification to mobile
// Mobile signs and submits
POST /tx/submit-delegated
Request: {
    "request_id": "uuid",
    "signature": "base64",
    "pubkey": "base64"
}
```

---

## What Nodes Need to Provide

### 1. Challenge Generation Service

```rust
// lib-blockchain/src/auth/mod.rs

pub struct AuthChallenge {
    pub session_id: Uuid,
    pub challenge: [u8; 32],      // Random nonce
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub requested_capabilities: Vec<Capability>,
    pub status: ChallengeStatus,
}

impl AuthChallenge {
    pub fn generate(capabilities: Vec<Capability>) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            challenge: rand::random(),
            created_at: now(),
            expires_at: now() + CHALLENGE_TTL,
            requested_capabilities: capabilities,
            status: ChallengeStatus::Pending,
        }
    }
    
    pub fn verify_signature(&self, pubkey: &PublicKey, signature: &Signature) -> bool {
        // Verify the challenge was signed by the claimed key
        verify(&self.challenge, signature, pubkey)
    }
}
```

### 2. Session Management

```rust
// Session store (in-memory LRU + persistent for recovery)
pub struct AuthSession {
    pub session_id: Uuid,
    pub user_did: DID,
    pub public_key: PublicKey,
    pub capabilities: Vec<Capability>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub last_used: Timestamp,
    pub session_token_hash: [u8; 32], // Hash only, never store token plaintext
}

// Token format (JWT or opaque)
pub struct SessionToken {
    header: TokenHeader,
    payload: TokenPayload,
    signature: Signature,  // Signed by node's key
}

struct TokenPayload {
    sid: Uuid,           // Session ID
    sub: DID,            // User DID
    cap: Vec<Capability>,
    iat: Timestamp,
    exp: Timestamp,
}
```

### 3. Delegation Verification

```rust
// On-chain or state-based delegation verification
pub fn verify_delegation(
    delegator: &DID,
    delegate_proof: &DelegateProof,
    action: &Action,
) -> Result<(), AuthError> {
    // 1. Check if delegation exists and is not expired
    let delegation = get_delegation(delegator, &delegate_proof.certificate_id)?;
    
    // 2. Verify certificate signature
    if !verify_cert(&delegation, delegator) {
        return Err(AuthError::InvalidCertificate);
    }
    
    // 3. Check if action is within delegated capabilities
    if !delegation.capabilities.contains(&action.to_capability()) {
        return Err(AuthError::CapabilityNotGranted);
    }
    
    // 4. Verify delegate proof (web app's attestation)
    if !verify_delegate_proof(delegate_proof, &delegation) {
        return Err(AuthError::InvalidDelegateProof);
    }
    
    Ok(())
}
```

### 4. API Middleware

```rust
// zhtp/src/api/middleware/auth.rs

pub async fn auth_middleware(
    req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // Extract bearer token
    let token = extract_bearer_token(&req)?;
    
    // Verify token signature (node-signed)
    let payload = verify_session_token(&token)?;
    
    // Check expiration
    if payload.exp < now() {
        return Err(AuthError::TokenExpired);
    }
    
    // Lookup session in store (anti-replay)
    let session = session_store.get(&payload.sid).await?;
    
    // Check capabilities for this endpoint
    let required_cap = req.route().required_capability();
    if !session.capabilities.contains(&required_cap) {
        return Err(AuthError::InsufficientCapabilities);
    }
    
    // Attach user context to request
    req.extensions_mut().insert(UserContext {
        did: payload.sub,
        session_id: payload.sid,
        capabilities: session.capabilities.clone(),
    });
    
    // Update last_used
    session_store.touch(&payload.sid).await;
    
    Ok(next.run(req).await)
}
```

### 5. Push Notification / QR Relay (Optional)

```rust
// For real-time signing requests
pub struct SigningRequestRelay {
    // WebSocket connections by session
    connections: Arc<DashMap<Uuid, WebSocketConnection>>,
    // Pending requests
    pending: Arc<DashMap<Uuid, PendingRequest>>,
}

impl SigningRequestRelay {
    // Web app subscribes to responses
    pub async fn subscribe(&self, session_id: Uuid, ws: WebSocket) {
        self.connections.insert(session_id, ws);
    }
    
    // Mobile app publishes signature
    pub async fn publish_response(&self, request_id: Uuid, signature: Signature) {
        if let Some((_, pending)) = self.pending.remove(&request_id) {
            pending.resolve(signature);
        }
    }
    
    // Web app awaits response
    pub async fn await_response(&self, request_id: Uuid, timeout: Duration) -> Result<Signature, Error> {
        // Returns when mobile publishes or timeout
    }
}
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Session token theft | Short expiry, HTTPS only, secure httpOnly cookies for web |
| Challenge replay | Single-use challenges, short TTL |
| Man-in-the-middle | TLS everywhere, certificate pinning in mobile app |
| Phishing (fake web app) | Mobile app shows clear human-readable authorization details |
| Session hijacking | Bind token to TLS channel, device fingerprinting |
| Mobile app compromise | Biometric auth in mobile app, key in secure enclave |

### Recommended Security Measures

```rust
// Session binding to prevent token export
pub struct SessionBinding {
    // Cryptographic binding of session to TLS channel
    tls_channel_id: [u8; 32],
    // Device fingerprint
    device_hash: [u8; 32],
}

// In middleware: verify binding matches
if !session.verify_binding(&request.binding_proof()) {
    return Err(AuthError::BindingMismatch);
}
```

---

## Implementation Phases

### Phase 1: Basic Session Auth (MVP)
- [ ] Challenge generation endpoint
- [ ] Signature verification
- [ ] Session token issuance (JWT)
- [ ] Auth middleware
- [ ] QR code generation for mobile scanning

### Phase 2: Enhanced Security
- [ ] Session binding
- [ ] Refresh token rotation
- [ ] Rate limiting on auth endpoints
- [ ] Audit logging

### Phase 3: Delegation (Advanced)
- [ ] On-chain delegation registry
- [ ] Delegation certificate format
- [ ] Revocation mechanism
- [ ] Granular capabilities

### Phase 4: Real-time (Optional)
- [ ] WebSocket relay for signing
- [ ] Push notification integration
- [ ] Biometric approval in mobile app

---

## Open Questions

1. **Session Duration**: How long should sessions live? (recommend: 1 hour access token, 7 day refresh)

2. **Revocation**: Should sessions be revocable before expiry? (recommend: yes, with revocation list)

3. **Concurrent Sessions**: Allow multiple web sessions per mobile key? (recommend: yes, with limits)

4. **Offline Mobile**: Support async signing (mobile offline during request)? (recommend: Phase 3 only)

5. **Key Recovery**: What if mobile app is lost? (recommend: social recovery via guardian DIDs)

---

## Related Standards

- **SIOPv2** (Self-Issued OpenID Provider v2) - DID-based auth
- **OIDC4VP** - OpenID Connect for Verifiable Presentations
- **CAIP-122** (WalletConnect) - Sign-in with Ethereum pattern
- **Aries RFC 0028** - DIDComm Introductions
- **W3C WebAuthn** - FIDO2 hardware key pattern (similar UX flow)

---

## Summary

**Recommended approach**: **Session-based auth (Option 1)** for MVP, with **delegation certificates (Option 2)** for advanced use cases.

**Node requirements**:
1. Challenge generation & verification service
2. Session store (ephemeral + persistent)
3. JWT or opaque token issuance/validation
4. Capability-based auth middleware
5. (Optional) Real-time relay for signing

This provides secure mobile→web delegation without the web app ever holding private keys, while keeping the implementation complexity manageable.
