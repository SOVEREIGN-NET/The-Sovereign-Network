# ZhtpUnifiedServer Refactoring: NodeRuntime Architecture

## Problem Statement

**ZhtpUnifiedServer violates single-axis responsibility.** It is simultaneously:
- Lifecycle manager
- Discovery policy engine
- Protocol preference engine
- Sync policy engine
- Bootstrap client
- Transport host

This entangles policies that will block:
- Alternative runtimes (mobile, embedded, light node)
- Testability
- Protocol evolution
- Partial-node roles

## Solution: NodeRuntime + ZhtpUnifiedServer Split

### Architecture Overview

```
                        NodeRuntime (Policy Authority)
                        ↓
                on_peer_discovered() ────────→ Vec<NodeAction>
                on_peer_state_changed() ─────→ Vec<NodeAction>
                on_timer() ─────────────────→ Vec<NodeAction>
                ↑
           NodeRuntimeOrchestrator (Periodic driver)
           Collects actions from runtime
                ↓
                ActionQueue
                ↓
        ZhtpUnifiedServer (Execution Host)

        Executes NodeActions:
        - Connect(peer, protocol)
        - StartSync(peer, protocol)
        - DropPeer(peer)
        etc.
```

### Critical Invariants (MUST ENFORCE)

#### NR-1: Policy Ownership Invariant
**All "should we?" decisions live in NodeRuntime.**
**All "can we?" operations live in ZhtpUnifiedServer.**

| Question | Owner | Location |
|----------|-------|----------|
| Should we discover peers now? | NodeRuntime | `on_timer()` |
| Should we sync with this peer? | NodeRuntime | `should_sync_with()` |
| Should we prefer QUIC over BLE? | NodeRuntime | `get_preferred_protocols()` |
| Can we open a QUIC session? | Server | Execute action |
| Can we send bytes to peer X? | Server | Execute action |

**Violation Detection**: If server ever says "should", boundary is broken.

#### NR-2: Server Purity Invariant
**ZhtpUnifiedServer MUST NOT contain:**
- Protocol preference logic
- Sync thresholds
- Discovery strategy
- Bootstrap heuristics
- Retry/backoff policy
- Peer promotion/demotion decisions

**Server MUST only expose:**
- Capabilities
- Hooks for runtime events
- Execution primitives

#### NR-3: Deterministic Runtime Invariant
**Given the same inputs, NodeRuntime decisions MUST be deterministic.**

Why matters:
- Reproducible tests
- Simulation
- Formal verification
- Offline reasoning

This naturally pushes toward:
- Functional core (pure decision logic)
- Explicit inputs (network state, peer state, config)
- Explicit outputs (actions to execute)

#### NR-4: No Hidden Background Behavior Invariant
**NodeRuntime MUST be ONLY component allowed to initiate background activity:**
- Discovery loops
- Sync retries
- Periodic heartbeats
- Bootstrap escalation

**Server may execute background tasks, but never start them on its own.**
Avoids "haunted" behavior during refactors.

#### NR-5: Role Awareness Invariant
**NodeRuntime defines the node's role.**
**Server must be role-agnostic.**

Examples of roles:
- FullValidator (stores complete blockchain)
- Observer (validates but not in consensus)
- LightNode (headers + ZK proofs only)
- MobileNode (minimal storage, BLE-optimized)
- BootstrapNode (helps new nodes join)
- ArchivalNode (stores all history)

Without this invariant, adding roles later requires invasive server changes.

#### NR-6: Replaceability Invariant
**Must be possible to replace NodeRuntime without modifying ZhtpUnifiedServer.**

Long-term escape hatch for:
- Multiple runtimes (desktop, mobile, embedded)
- Test runtimes
- Simulation runtimes
- Governance-driven runtimes

**If replacing runtime requires touching server internals, the split failed.**

## Current Progress

### Completed ✓

1. **NodeRuntime Trait** (`zhtp/src/runtime/node_runtime.rs`)
   - `on_peer_discovered(peer: PeerInfo) -> Vec<NodeAction>`
   - `on_peer_state_changed(change: PeerStateChange) -> Vec<NodeAction>`
   - `on_timer(tick: Tick) -> Vec<NodeAction>`
   - `get_preferred_protocols(peer: &PeerInfo) -> Vec<NetworkProtocol>`
   - `should_sync_with(peer: &PeerInfo) -> bool`

2. **NodeAction Enum**
   - `Connect { peer, protocol, address }`
   - `StartSync { peer, protocol, full_sync }`
   - `DiscoverVia(protocol)`
   - `DropPeer(peer)`
   - `AdvertiseCapabilities { peer, role }`
   - And more...

3. **NodeRuntimeOrchestrator** (`zhtp/src/runtime/node_runtime_orchestrator.rs`)
   - Drives periodic runtime decisions via timer ticks
   - Collects NodeActions into queue
   - Notifies runtime of peer state changes
   - Maintains action queue for server consumption

4. **DefaultNodeRuntime**
   - Basic implementation with sensible defaults
   - Protocol preference based on discovery method
   - Simple sync eligibility checking

### Next Phase: Extract Existing Policy Logic

#### Step 1: Discovery Policy (Lines 690-1008 in unified_server.rs)

**What to extract:**
- UDP Multicast discovery initialization
- BLE discovery initialization
- Bluetooth Classic discovery
- WiFi Direct + mDNS initialization
- LoRaWAN handler initialization

**From unified_server.rs lines 707-731:**
```rust
let peer_discovered_callback = Arc::new(move |peer_addr: String, peer_pubkey: lib_crypto::PublicKey| {
    // Decides: Register with discovery coordinator?
    // Decision: YES (always)
    // Move to: NodeRuntime.on_peer_discovered()
});
```

**From unified_server.rs lines 853-893:**
```rust
let prefer_tcp_quic = {
    // SMART PROTOCOL SELECTION
    // Decides: Should we prefer TCP/QUIC over BLE?
    // Current: YES if peer has TCP/QUIC address
    // Move to: NodeRuntime.get_preferred_protocols()
};
```

#### Step 2: Sync Policy (Lines 819-956)

**What to extract:**
- Sync type selection (edge vs full)
- Peer sync eligibility checking
- Blockchain request composition
- Sync coordinator interaction

**Key decision at lines 895-906:**
```rust
let should_sync = sync_coordinator_for_ble.register_peer_protocol(...);
if !should_sync {
    // Decides: Should we sync with this peer now?
    // Current: Check sync coordinator
    // Move to: NodeRuntime.should_sync_with()
    continue;
}
```

#### Step 3: Bootstrap Policy (Lines 1188-1229)

**What to extract:**
- Bootstrap peer selection
- Port adjustment logic (9333 → 9334)
- Connection retry decisions

**Current code:**
```rust
pub async fn connect_to_bootstrap_peers(&self, bootstrap_peers: Vec<String>) -> Result<()> {
    // Decides: Which bootstrap peers to connect to?
    // Current: All of them
    // Move to: NodeRuntime.on_timer(Tick::ThirtySecond)
    // Returns: Vec<NodeAction::BootstrapFrom(peers)>
}
```

#### Step 4: Role Detection (Lines 844-850)

**What to extract:**
- Edge node vs full node detection
- Role-based sync type selection

**Current code:**
```rust
let is_edge_node = *is_edge_node_for_ble.read().await;
let sync_type = if is_edge_node {
    SyncType::EdgeNode
} else {
    SyncType::FullBlockchain
};
```

**Move to:** `DefaultNodeRuntime::get_role()` and `get_sync_type()`

## Implementation Plan

### Phase 1: Enhanced DefaultNodeRuntime (Current Sprint)

Move existing heuristics from unified_server.rs to DefaultNodeRuntime:

```rust
impl NodeRuntime for DefaultNodeRuntime {
    async fn on_peer_discovered(&self, peer: PeerInfo) -> Vec<NodeAction> {
        // 1. Check if we should sync with this peer
        if !self.should_sync_with(&peer) {
            return vec![];
        }

        // 2. Choose best protocol
        let protocols = self.get_preferred_protocols(&peer);

        // 3. Return connect actions
        vec![NodeAction::Connect {
            peer: peer.public_key,
            protocol: protocols[0].clone(),
            address: peer.addresses.first().cloned(),
        }]
    }

    async fn on_timer(&self, tick: Tick) -> Vec<NodeAction> {
        match tick {
            Tick::ThirtySecond => {
                // Start discovery or retries
                // Bootstrap from known peers
                // Check peer health
                todo!()
            }
            _ => vec![],
        }
    }
}
```

### Phase 2: Refactor ZhtpUnifiedServer

Changes required:

1. **Add field:**
   ```rust
   pub struct ZhtpUnifiedServer {
       runtime: Arc<dyn NodeRuntime>,
       runtime_orchestrator: Arc<NodeRuntimeOrchestrator>,
       action_queue: Arc<ActionQueue>,
       // ... existing fields
   }
   ```

2. **Remove policy logic:**
   - Delete all `tokio::spawn()` calls for background decisions
   - Remove protocol preference logic
   - Remove sync eligibility checks
   - Remove bootstrap connection logic

3. **Add action execution loop:**
   ```rust
   async fn execute_actions(&mut self) {
       while let Some(action) = self.action_queue.dequeue().await {
           match action {
               NodeAction::Connect { peer, protocol, address } => {
                   self.connect_to_peer(&peer, protocol, address).await?;
               }
               NodeAction::StartSync { peer, protocol, full_sync } => {
                   self.start_sync(&peer, protocol, full_sync).await?;
               }
               // ... handle other actions
           }
       }
   }
   ```

4. **Update start() method:**
   - Start NodeRuntimeOrchestrator
   - Subscribe to peer state changes
   - Start action execution loop
   - Remove inline policy decisions

### Phase 3: Discovery Coordinator Integration

Update DiscoveryCoordinator to work with NodeRuntime:

```rust
impl DiscoveryCoordinator {
    /// Notify runtime of discovered peer
    pub async fn notify_runtime(&self, peer: PeerInfo) {
        let actions = self.runtime.on_peer_discovered(peer).await;
        self.action_queue.enqueue_all(actions);
    }

    /// Track peer state changes and notify runtime
    pub async fn on_peer_state_changed(&self, ...) {
        let actions = self.runtime.on_peer_state_changed(change).await;
        self.action_queue.enqueue_all(actions);
    }
}
```

### Phase 4: Testing & Validation

Create test runtimes to verify replaceability (NR-6):

```rust
struct TestNodeRuntime {
    always_sync: bool,
    preferred_protocol: NetworkProtocol,
}

impl NodeRuntime for TestNodeRuntime {
    async fn on_peer_discovered(&self, peer: PeerInfo) -> Vec<NodeAction> {
        if self.always_sync {
            vec![NodeAction::Connect {
                peer: peer.public_key,
                protocol: self.preferred_protocol.clone(),
                address: peer.addresses.first().cloned(),
            }]
        } else {
            vec![]
        }
    }
    // ...
}

struct SimulationNodeRuntime {
    // Simulates network conditions, peer behavior, etc.
}
```

## Files to Modify

1. **New Files:**
   - ✓ `zhtp/src/runtime/node_runtime.rs` - NodeRuntime trait
   - ✓ `zhtp/src/runtime/node_runtime_orchestrator.rs` - Orchestrator

2. **Modify:**
   - `zhtp/src/runtime/mod.rs` - Already updated with exports
   - `zhtp/src/unified_server.rs` - Extract policy, add runtime field
   - `zhtp/src/discovery_coordinator.rs` - Integrate with runtime
   - Tests to validate refactoring

## Success Criteria

- [ ] All policy decisions moved to NodeRuntime
- [ ] ZhtpUnifiedServer contains no policy logic
- [ ] No `tokio::spawn()` in server for decision-making
- [ ] DefaultNodeRuntime reproduces current behavior
- [ ] Test runtime can be swapped in without server changes
- [ ] All existing tests pass
- [ ] New tests verify invariant compliance

## References

- **Original Issue:** ZhtpUnifiedServer is still doing too much
- **Agent Instructions:** Endorsed opinionated fix with 6 critical invariants
- **Key Files:** `zhtp/src/unified_server.rs` (1358 lines), `zhtp/src/runtime/node_runtime.rs`
