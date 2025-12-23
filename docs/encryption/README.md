# ZHTP Encryption Architecture Documentation

**Complete documentation for ZHTP's defense-in-depth encryption system combining classical (TLS 1.3) and post-quantum (Kyber512) cryptography.**

---

## 📚 Documentation Index

### 1. **Architecture Decision Record (ADR)**
📄 [`ADR_QUIC_ENCRYPTION.md`](./ADR_QUIC_ENCRYPTION.md)

**For:** Architects, decision makers, security reviewers
**Length:** ~1700 lines | **Time:** 30 minutes

**Covers:**
- Why defense-in-depth encryption? (Threat model analysis)
- Classical vs quantum threats and how each layer mitigates
- Trade-off analysis: Performance vs Security guarantees
- Comparison to industry standards (TLS 1.3 hybrid mode)
- Risk assessment and mitigation strategies
- Testing and validation approach
- Future upgrade path for post-quantum era

**Key Question:** "Why not just use TLS 1.3 or just Kyber?"

---

### 2. **Protocol Specification**
📄 [`QUIC_ENCRYPTION_PROTOCOL.md`](./QUIC_ENCRYPTION_PROTOCOL.md)

**For:** Protocol engineers, implementers, security testers
**Length:** ~1400 lines | **Time:** 45 minutes

**Covers:**
- Complete two-layer encryption model with diagrams
- Detailed handshake flow (Phase 1: UHP Auth, Phase 2: Kyber KEM, Phase 3: Master Key)
- Message encryption/decryption process step-by-step
- Key derivation formula: `HKDF(UHP || Kyber || Hash || NodeId)`
- Nonce management and randomness properties
- Security properties: Confidentiality, Integrity, Authentication, Forward Secrecy, Replay Protection
- Configuration parameters and constants
- Code examples (encryption, decryption, key derivation)

**Key Question:** "How does the protocol actually work?"

---

### 3. **Complete Guide**
📄 [`QUIC_ENCRYPTION_GUIDE.md`](./QUIC_ENCRYPTION_GUIDE.md)

**For:** All developers, new team members, security auditors
**Length:** ~1200 lines | **Time:** 1 hour

**Covers:**
- Quick reference table (FAQ format)
- Architecture overview with layer responsibilities
- Handshake overview and master key composition
- Key derivation deep dive with attack scenarios
- Performance implications and benchmarks
- Security properties checklist
- Per-layer security analysis
- Future upgrade strategies
- Testing strategy (unit, integration, security tests)
- Troubleshooting guide

**Key Question:** "How do I understand and work with this system?"

---

## 🎯 Quick Start by Role

### I'm a...

**Architect/Decision Maker**
→ Read: [ADR](./ADR_QUIC_ENCRYPTION.md) (30 min)
→ Why: Understand business/security trade-offs

**Protocol Engineer**
→ Read: [Protocol Spec](./QUIC_ENCRYPTION_PROTOCOL.md) (45 min)
→ Why: Understand exact implementation details

**Security Reviewer**
→ Read: [ADR](./ADR_QUIC_ENCRYPTION.md) + [Guide](./QUIC_ENCRYPTION_GUIDE.md) (1.5 hours)
→ Why: Verify threat model and security properties

**New Team Member**
→ Read: [Guide](./QUIC_ENCRYPTION_GUIDE.md) (1 hour)
→ Then: Code files (30 min)
→ Why: Get complete mental model

**Implementer/Debugger**
→ Read: [Protocol Spec](./QUIC_ENCRYPTION_PROTOCOL.md) (45 min)
→ Reference: Code examples section
→ Why: Understand exact behavior for debugging

---

## 🔗 Related Code Files

### Encryption Implementation
- `lib-network/src/protocols/quic_mesh.rs` - QUIC transport with ChaCha20+Kyber
- `lib-network/src/protocols/quic_handshake.rs` - UHP + Kyber handshake
- `lib-crypto/src/symmetric/chacha20.rs` - ChaCha20Poly1305 AEAD

### Related Issues & PRs
- **Issue #492** - Document QUIC encryption architecture (this work)
- **Issue #498** - Multi-node communication failure (security fix using this encryption)
- **PR #499** - Fix Issue #498
- **Issue #161** - Unify encryption across protocols
- **Issue #486** - Security audit fixes

---

## 🔐 Security Properties at a Glance

| Property | Transport (TLS 1.3) | Application (ChaCha20+Kyber) | Combined |
|----------|-------------------|------------------------------|----------|
| **Confidentiality** | ✅ Classical | ✅ Classical + Quantum-Resistant | ✅ Dual-Protected |
| **Integrity** | ✅ HMAC | ✅ Poly1305 MAC | ✅ Dual-Checked |
| **Authentication** | ✅ X.509 Certs | ✅ Dilithium Signatures + NodeId Binding | ✅ Multi-Factor |
| **Forward Secrecy** | ✅ Ephemeral ECDHE | ✅ Random nonces per message | ✅ Complete |
| **Quantum-Resistant** | ❌ No | ✅ Yes (Kyber512) | ✅ Yes |
| **Identity Binding** | ❌ No | ✅ Yes (NodeId) | ✅ Yes |

---

## 📊 Architecture Diagram

```
┌─────────────────────────────────────────────┐
│         Application Layer Messages          │
│         (ZHTP Mesh Protocol)                │
└─────────────────────────────────────────────┘
                      ↓
        ┌──────────────────────────────┐
        │ APPLICATION LAYER ENCRYPTION │
        │ ChaCha20Poly1305 + Kyber512  │
        │ Post-Quantum Confidentiality │
        │ Identity Binding (NodeId)    │
        └──────────────────────────────┘
                      ↓
        ┌──────────────────────────────┐
        │  TRANSPORT LAYER ENCRYPTION  │
        │  TLS 1.3 via Quinn (QUIC)    │
        │  Classical Security + MitM   │
        │  Connection-Level Auth       │
        └──────────────────────────────┘
                      ↓
        ┌──────────────────────────────┐
        │        Network Layer         │
        │   UDP/IPv4 (Unencrypted)    │
        │   (Firewall Traversal)       │
        └──────────────────────────────┘
```

---

## ⚡ Key Facts

| Fact | Details |
|------|---------|
| **Handshake Time** | ~3 RTTs (~150ms at 50ms/RTT) |
| **Per-Message Overhead** | 12-byte nonce + 16-byte MAC = 28 bytes |
| **Per-Message Latency** | <1 microsecond (negligible) |
| **Forward Secrecy** | Yes - Different nonce per message |
| **Replay Protection** | Yes - Random nonce + sequence numbers |
| **Quantum-Ready** | Yes - Kyber upgrade path exists |
| **Master Key Inputs** | 4: UHP + Kyber + Hash + NodeId |
| **Nonce Randomness** | 96-bit per message |
| **Max Session Duration** | 1 hour (then rehandshake) |

---

## 🚀 Getting Started

### For Code Review
1. Read [Protocol Spec](./QUIC_ENCRYPTION_PROTOCOL.md) "Complete Handshake Flow" section
2. Review `lib-network/src/protocols/quic_handshake.rs` Phase 1-3
3. Check master key derivation in `quic_mesh.rs`

### For Security Audit
1. Read [ADR](./ADR_QUIC_ENCRYPTION.md) "Threat Model" and "Security Properties"
2. Read [Guide](./QUIC_ENCRYPTION_GUIDE.md) "Security Properties Checklist"
3. Review code files mentioned above
4. Run security tests: `cargo test --test quic_security_tests`

### For Implementation
1. Read [Protocol Spec](./QUIC_ENCRYPTION_PROTOCOL.md) complete flow
2. Reference code examples at end of document
3. Check configuration section for parameters
4. Refer to troubleshooting guide if issues arise

---

## 📖 Table of Contents by Document

### ADR_QUIC_ENCRYPTION.md
1. Executive Summary
2. Problem Statement (Previous Approaches)
3. Threat Model (Classical + Quantum Threats)
4. Architectural Design
5. Master Key Derivation
6. Trade-offs Analysis
7. Implementation Details
8. Comparison to Industry Standards
9. Risks and Mitigations
10. Testing Strategy
11. Future Considerations
12. Decision Rationale
13. Approval and Sign-off

### QUIC_ENCRYPTION_PROTOCOL.md
1. Overview
2. Encryption Layers (Transport + Application)
3. Complete Handshake Flow (Phase 1-3)
4. Message Encryption/Decryption
5. Key Derivation
6. Nonce Management
7. Security Properties
8. Configuration
9. Examples (Code)

### QUIC_ENCRYPTION_GUIDE.md
1. Quick Reference
2. Documentation Map by Role
3. Architecture Overview
4. Handshake Overview
5. Message Encryption Flow
6. Key Derivation Deep Dive
7. Security Properties Checklist
8. Performance Implications
9. Future Upgrade Path
10. Testing Strategy
11. Troubleshooting
12. References

---

## 🔍 Common Questions

**Q: Is this defense-in-depth or wasteful redundancy?**
A: Defense-in-depth. Each layer serves distinct security purpose. See [ADR](./ADR_QUIC_ENCRYPTION.md) "Decision Rationale".

**Q: What if TLS 1.3 is broken by quantum computers?**
A: ChaCha20+Kyber layer still protects data (post-quantum secure). See [Threat Model](./ADR_QUIC_ENCRYPTION.md#threat-model).

**Q: What if Kyber is broken?**
A: TLS 1.3 still protects data (proven classical security). See [Threat Model](./ADR_QUIC_ENCRYPTION.md#threat-model).

**Q: How do peers agree on the same master key?**
A: Via UHP (Dilithium authentication) + Kyber (KEM) + HKDF derivation. See [Protocol Spec](./QUIC_ENCRYPTION_PROTOCOL.md#complete-handshake-flow).

**Q: What are the four inputs to master key?**
A: UHP session key + Kyber shared secret + Handshake transcript hash + Peer NodeId. See [Protocol Spec](./QUIC_ENCRYPTION_PROTOCOL.md#master-key-derivation).

**Q: Performance impact?**
A: Handshake ~150ms (one-time), per-message <1μs. Acceptable. See [Performance Analysis](./QUIC_ENCRYPTION_GUIDE.md#performance-implications).

---

## 📝 Document Status

| Document | Status | Lines | Last Updated |
|----------|--------|-------|--------------|
| ADR_QUIC_ENCRYPTION.md | ✅ Complete | 1700+ | 2025-12-23 |
| QUIC_ENCRYPTION_PROTOCOL.md | ✅ Complete | 1400+ | 2025-12-23 |
| QUIC_ENCRYPTION_GUIDE.md | ✅ Complete | 1200+ | 2025-12-23 |
| README.md (this file) | ✅ Complete | 300+ | 2025-12-23 |

---

## 🎓 Learning Path

```
Start Here (30 min)
    ↓
[Quick Reference] + [Architecture Overview]
    ↓
Choose Your Path:
    │
    ├─→ [Decision Maker] → Read ADR (30 min) → Done
    │
    ├─→ [Engineer] → Read Protocol Spec (45 min) → Code Review (30 min) → Done
    │
    ├─→ [Auditor] → Read Guide (1 hour) → Read ADR (30 min) → Code Review (1 hour) → Done
    │
    └─→ [New Member] → Read Guide (1 hour) → Handshake Overview (20 min) → Code examples (30 min) → Done

Total Time: 30 min - 2.5 hours depending on role
```

---

## 📧 Questions or Issues?

- **Technical Questions:** Review relevant section in [Guide](./QUIC_ENCRYPTION_GUIDE.md#troubleshooting)
- **Protocol Issues:** Check [Protocol Spec](./QUIC_ENCRYPTION_PROTOCOL.md) for exact behavior
- **Architecture Questions:** See [ADR](./ADR_QUIC_ENCRYPTION.md) for rationale
- **Bug Reports:** Check code comments in `lib-network/src/protocols/quic_*.rs`

---

**Last Updated:** December 23, 2025
**Authors:** ZHTP Security & Architecture Team
**Status:** Production-Ready Documentation
