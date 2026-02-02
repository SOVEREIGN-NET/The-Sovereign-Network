# PoUW Threat Model

This document describes the security threat model for the Proof-of-Useful-Work (PoUW) protocol implementation.

## Overview

The PoUW protocol allows clients to earn rewards by performing computational work. The node validates work receipts and distributes rewards. This creates several attack surfaces that must be addressed.

## Assets to Protect

1. **Reward Pool** - Token reserves used for payouts
2. **Challenge Tokens** - Cryptographic challenges issued to clients
3. **Receipt Validation** - Integrity of work verification
4. **Rate Limit State** - Prevents abuse of the system
5. **Node Resources** - CPU, memory, network bandwidth

## Threat Actors

### 1. Malicious Client
- **Goal**: Obtain rewards without performing valid work
- **Capabilities**: Can forge receipts, replay attacks, submit invalid proofs
- **Access**: Authenticated client with valid DID

### 2. External Attacker
- **Goal**: Disrupt service, exhaust resources, steal tokens
- **Capabilities**: Network-level attacks, DDoS, IP spoofing
- **Access**: Network access to node endpoints

### 3. Colluding Clients
- **Goal**: Game the reward system through coordination
- **Capabilities**: Share challenges, coordinate submissions
- **Access**: Multiple authenticated client accounts

### 4. Compromised Node
- **Goal**: Steal rewards, manipulate validation
- **Capabilities**: Full access to node state
- **Access**: Root/admin on node system

## Threats and Mitigations

### T1: Receipt Replay Attack
**Description**: Client resubmits a previously validated receipt to claim multiple rewards.

**Likelihood**: High
**Impact**: High (token drain)

**Mitigations**:
- [x] Nonce deduplication check in `validation.rs`
- [x] Challenge tokens have unique task_ids
- [x] Receipts bound to specific challenge tokens
- [ ] Persistent nonce storage with TTL

### T2: Challenge Token Forgery
**Description**: Attacker creates fake challenge tokens to submit fraudulent receipts.

**Likelihood**: Medium
**Impact**: High

**Mitigations**:
- [x] Ed25519/Dilithium signatures on challenge tokens
- [x] Challenge tokens verified against issued tokens in storage
- [x] Short expiry times (default 5 minutes)

### T3: Signature Bypass
**Description**: Attacker submits receipts with invalid or missing signatures.

**Likelihood**: Low
**Impact**: High

**Mitigations**:
- [x] Constant-time signature verification
- [x] Reject all unsigned receipts
- [x] Support for post-quantum Dilithium5 signatures

### T4: DoS via Receipt Flooding
**Description**: Attacker floods the endpoint with receipt submissions to exhaust resources.

**Likelihood**: High
**Impact**: Medium

**Mitigations**:
- [x] Per-IP rate limiting (`rate_limiter.rs`)
- [x] Per-DID rate limiting
- [x] Batch size limits (max 100 receipts per request)
- [x] Request timeout (30 seconds default)
- [ ] Connection limits per IP

### T5: Proof Type Manipulation
**Description**: Client claims higher-value proof types (SIGNATURE) when performing lower-value work (HASH).

**Likelihood**: Medium
**Impact**: Medium

**Mitigations**:
- [x] Proof type verification in policy enforcement
- [x] Random spot-checking of proof validity
- [ ] Statistical anomaly detection for clients with unusual proof type distributions

### T6: Challenge Hoarding
**Description**: Client requests many challenges but doesn't submit work, depleting challenge pool.

**Likelihood**: Medium
**Impact**: Low

**Mitigations**:
- [x] Challenge expiry (5 minute TTL)
- [x] Rate limiting on challenge requests
- [x] Metrics tracking for expired vs used challenges

### T7: Reward Calculation Manipulation
**Description**: Attacker manipulates inputs to reward calculation to inflate payouts.

**Likelihood**: Low
**Impact**: High

**Mitigations**:
- [x] Immutable receipt storage after validation
- [x] Row locking during payout to prevent double-spend
- [x] Idempotent payout mechanism
- [x] Per-epoch reward caps

### T8: Client Impersonation
**Description**: Attacker submits receipts using another client's DID.

**Likelihood**: Medium
**Impact**: Medium

**Mitigations**:
- [x] Receipt signatures must match client DID
- [x] DID validation against known identities
- [ ] Additional authentication layer for high-value operations

### T9: Timing Attacks
**Description**: Attacker measures response times to infer validation logic or signature comparison.

**Likelihood**: Low
**Impact**: Low

**Mitigations**:
- [x] Constant-time signature verification (crypto library)
- [x] Uniform response times for rejection reasons
- [ ] Jitter on response timing

### T10: Memory Exhaustion
**Description**: Attacker sends malformed/oversized messages to exhaust node memory.

**Likelihood**: Medium
**Impact**: Medium

**Mitigations**:
- [x] Batch size limits
- [x] Request body size limits
- [ ] Streaming processing for large batches
- [ ] Memory limits per connection

## Security Monitoring

### Metrics to Watch
- `pouw_receipts_rejected_total{reason="*"}` - Spike indicates attack attempt
- `pouw_rate_limit_denials_total` - High rate indicates DoS attempt
- `pouw_signature_verification_duration_microseconds` - Unusually long times indicate resource exhaustion
- `pouw_disputes_logged` - Increases may indicate fraud

### Alerting Thresholds
| Metric | Warning | Critical |
|--------|---------|----------|
| Rejection rate | > 10% | > 50% |
| Rate limit denials/min | > 100 | > 1000 |
| Signature verification p99 | > 10ms | > 100ms |
| Disputes/hour | > 5 | > 20 |

### Incident Response
1. **Detection**: Automated alerting on metrics
2. **Containment**: Rate limiting, IP blocking
3. **Investigation**: Dispute service, log analysis
4. **Recovery**: Payout reversal if needed
5. **Post-mortem**: Update threat model

## Compliance

### Data Protection
- Client DIDs are pseudonymous
- Receipt data stored with minimal PII
- Dispute records may contain investigation notes (access controlled)

### Audit Trail
- All receipts logged with timestamps
- Validation decisions logged with reasons
- Reward calculations logged with inputs/outputs
- Disputes fully tracked from filing to resolution

## Security Checklist

Before production deployment:

- [ ] All signature verification uses constant-time comparisons
- [ ] Rate limiting tested under load
- [ ] Nonce deduplication persistent across restarts
- [ ] Challenge expiry enforced
- [ ] Payout idempotency tested
- [ ] Metrics endpoints secured (authentication)
- [ ] Dispute API authenticated
- [ ] Log levels appropriate (no secrets in logs)
- [ ] TLS enabled on all endpoints
- [ ] Key material stored securely

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-31 | Initial threat model |

## References

- [PoUW Protocol Specification](../dapps_auth/pouw-protocol-spec.md)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
