# MrCakes931 Decentralization Audit Report

## 🕵️ Overview
Audit of network architecture to identify centralization risks and single points of failure.

### Hardcoded IPs/Nodes
⚠️ Found 156 potential risks:
- **lib-consensus/src/validators/genesis.rs** (Line 274): `.endpoint("tcp://127.0.0.1:9333".to_string())`
- **lib-consensus/src/validators/validator_discovery.rs** (Line 689): `address: "1.2.3.4:1234".into(),`
- **lib-consensus/src/validators/validator_discovery.rs** (Line 736): `address: "1.2.3.4:1234".into(),`
- **lib-consensus/src/validators/validator_discovery.rs** (Line 753): `assert_eq!(ep.address, "1.2.3.4:1234");`
- **lib-consensus/src/validators/validator_discovery.rs** (Line 766): `address: "1.2.3.4:1234".into(),`
- **lib-consensus/src/validators/validator_discovery.rs** (Line 771): `address: "1.2.3.4:4321".into(),`
- **lib-consensus/src/validators/validator_discovery.rs** (Line 798): `address: "1.2.3.4:1234".into(),`
- **lib-consensus/src/validators/validator_discovery.rs** (Line 814): `assert_eq!(route.1, "1.2.3.4:1234");`
- **lib-consensus/src/validators/validator_protocol.rs** (Line 1248): `address: "127.0.0.1:0".to_string(),`
- **lib-consensus/src/validators/validator_protocol.rs** (Line 1353): `address: "127.0.0.1:0".to_string(),`
- ... and 146 more instances.

### Hardcoded Validator Addresses
✅ No immediate risks identified in this category.

### Superuser/Admin Logic
⚠️ Found 70 potential risks:
- **lib-network/src/constants.rs** (Line 13): `// - zhtp-uhp/1|2: Control plane with UHP handshake (CLI, Web4 deploy, admin)`
- **lib-network/src/constants.rs** (Line 20): `/// ALPN for control plane connections v1 (CLI, Web4 deploy, admin APIs)`
- **lib-network/src/constants.rs** (Line 34): `/// Rejects: deploy, domain registration, admin operations, any mutations.`
- **lib-network/src/peer_registry/mod.rs** (Line 647): `/// - Prevents malicious DIDs like "admin" or "system" from being indexed`
- **lib-network/src/peer_registry/mod.rs** (Line 1786): `assert!(PeerRegistry::validate_did("admin").is_err());`
- **lib-network/src/protocols/wifi_direct.rs** (Line 522): `let _ = Command::new("sudo")`
- **lib-network/src/protocols/wifi_direct.rs** (Line 3674): `// Modify MAC for P2P: Set locally administered bit and derive from network name`
- **lib-network/src/protocols/wifi_direct.rs** (Line 3715): `// Set locally administered bit and incorporate network name`
- **lib-network/src/protocols/wifi_direct.rs** (Line 3738): `// Set locally administered bit and incorporate network name`
- **lib-network/src/protocols/bluetooth/common.rs** (Line 43): `/// Falls back to generating a deterministic locally-administered MAC if detection fails.`
- ... and 60 more instances.

### Kill-Switch/Pause Mechanisms
⚠️ Found 64 potential risks:
- **lib-consensus/src/invariants.rs** (Line 194): `/// and must halt the node to prevent further state corruption.`
- **lib-consensus/src/invariants.rs** (Line 213): `msg.push_str("The node must halt to prevent further state corruption.");`
- **lib-consensus/src/types/mod.rs** (Line 504): `///   **fatal error**: it halts this node to prevent it from voting on a stale`
- **lib-consensus/src/types/mod.rs** (Line 509): `/// - Commit failure is **not** best-effort — a failed commit halts the node.`
- **lib-consensus/src/engines/consensus_engine/state_machine.rs** (Line 1228): `// We must NOT continue. Return an error so the consensus engine halts this`
- **lib-consensus/src/engines/consensus_engine/state_machine.rs** (Line 1233): `Local chain state has diverged from consensus. Halting to prevent network deadlock.",`
- **lib-consensus/src/engines/consensus_engine/state_machine.rs** (Line 1240): `locally: {}. Node halted to prevent network deadlock. Recovery: \`
- **lib-consensus/src/engines/consensus_engine/state_machine.rs** (Line 2212): `// swallowed — errors must propagate so the node halts rather than continuing`
- **lib-consensus/src/engines/consensus_engine/state_machine.rs** (Line 2215): `async fn test_commit_failure_halts_consensus() {`
- **lib-consensus/src/network/liveness_monitor.rs** (Line 63): `//! - It does not pause or resume consensus`
- ... and 54 more instances.

