# BFT Consensus — Architecture Analysis

**Repository:** `The-Sovereign-Network`
**Audit target:** `lib-consensus` and the consensus surface area across the workspace
**Date:** 2026-04-25
**Companion to:** `bft-consensus-forensic-analysis.md` (FSM-level audit)

This report answers three questions:

1. **What is *scattered* — consensus logic that lives outside `lib-consensus` but should be inside it (or inside a shared infrastructure layer)?**
2. **What is *leaked in* — code inside `lib-consensus` that does not belong there?**
3. **What is the *target shape* of a consensus library that operates as a true module?**

All findings are backed by `file:line` references against the on-disk code.

---

## Executive Summary

`lib-consensus` is **not a consensus library**. It is a 22-subdirectory mega-crate (`lib-consensus/src/{byzantine,chain_evaluation,dao,difficulty,engines,evidence,fault_model,finality_model,invariants,mempool,mining,network,observer,proofs,rewards,slashing,testing,types,validators}`) at **~30,000 LOC** that bundles:

- a Tendermint-like BFT engine (~5,400 LOC, the part actually doing BFT),
- a full DAO governance engine (~2,043 LOC),
- an ML-style behavioral observer (~3,810 LOC),
- a transaction mempool (~379 LOC),
- a PoW mining coordinator (~182 LOC),
- a slashing policy engine (~733 LOC),
- a reward calculator (~241 LOC),
- a PoStorage / PoUW / PoStake proof system (~957 LOC),
- a validator-discovery + signed-protocol middleware (~3,606 LOC),
- a wire codec + heartbeat protocol (~1,715 LOC).

Meanwhile, **the consensus event loop is partially re-implemented outside lib-consensus** in:

- `lib-blockchain/src/integration/consensus_integration.rs` — a parallel `BlockchainConsensusCoordinator` (2,124 LOC) with its own `consensus_event_loop`, vote-casting, proposal-creating, block-production, DAO and reward loops.
- `zhtp/src/runtime/components/consensus.rs` — 2,819 LOC of "adapter" that includes a 467-line catch-up sync orchestrator with fork-detection logic.
- `lib-network/src/messaging/message_handler.rs` — converts between **two different `ValidatorMessage` types** that lib-consensus exposes (`types::ValidatorMessage` with 3 variants vs `validators::ValidatorMessage` with 5 variants).

The `[features]` block in `lib-consensus/Cargo.toml:42-50` declares `dao`, `byzantine`, `rewards`, `ubi` as optional, but `default = ["full"]` enables all of them and the gates only apply to `pub use` re-exports (`lib.rs:62-69`) — they do not gate compilation. The features are **theatrical**.

The proposed target shape is a **three-crate split**:

- `lib-consensus-core` (~6 K LOC): pure BFT FSM, validator set, vote pool, invariants, slashing math.
- `lib-consensus-net` (~3 K LOC): wire codec, heartbeat, validator-protocol middleware, discovery — depends on `lib-network`.
- `lib-consensus-runtime` (~1 K LOC): the orchestration glue currently in `zhtp/runtime/components/consensus.rs` and `lib-blockchain/integration/consensus_integration.rs`, collapsed into one place.

DAO, rewards, mempool, mining, observer, difficulty move to their existing or new dedicated crates.

---

## 1. What's Scattered (consensus logic outside `lib-consensus`)

External consumers of `lib_consensus`: **34 files** across `lib-blockchain`, `lib-network`, `lib-protocols`, `zhtp`. Most of these are legitimate uses of `Validator`, `IdentityId`, etc. — but several reach **deep into private subdirs** to re-implement consensus orchestration.

### 1.1 Parallel consensus orchestration in `lib-blockchain`

**File:** `lib-blockchain/src/integration/consensus_integration.rs` (2,124 LOC)

`BlockchainConsensusCoordinator` (`consensus_integration.rs:155`) runs an entirely separate consensus event loop alongside `lib_consensus::ConsensusEngine::run_consensus_loop`. Its methods:

| Method | Line | What it does |
|---|---|---|
| `consensus_event_loop` | 453 | Receives `ConsensusEvent`s and dispatches |
| `handle_consensus_event` | 471 | Match on `ConsensusEvent` variants |
| `handle_start_round` | 517 | Begin a round at `height` |
| `handle_new_block` | 547 | Wire a new block in |
| `handle_proposal_received` | 599 | Process incoming proposal |
| `handle_vote_received` | 642 | Process incoming vote |
| `handle_round_completed` | 661 | Round finalization |
| `block_production_loop` | 862 | Block-production task |
| `attempt_block_production` | 883 | Decide to produce |
| `create_consensus_proposal` | 923 | **Construct a `ConsensusProposal`** |
| `cast_consensus_vote` | 1222 | **Cast a vote** |
| `consensus_proposal_to_block` | 1258 | Convert proposal → block |
| `extract_transactions_from_proposal` | 1297 | Extract txs |
| `dao_governance_loop` | 993 | DAO loop (separate from lib-consensus's own DAO loop) |
| `reward_distribution_loop` | 1018 | Reward loop (separate from lib-consensus's own reward loop) |

This is **a second consensus driver**. The `ConsensusEngine` source already has a single-driver invariant (`engines/consensus_engine/state_machine.rs:371-385`: "This method must NOT be used alongside `run_consensus_loop()`"). Whether `BlockchainConsensusCoordinator` triggers that error depends on injection order — but its existence is the architectural problem: consensus decisions must have one home.

**Should move to:** A single `lib-consensus-runtime` adapter crate (see §3). Block production primitives (`create_consensus_proposal`, `consensus_proposal_to_block`) belong inside `lib-consensus-core` as `Proposer::build()`. Vote casting (`cast_consensus_vote`) is already inside the engine — the duplicate must be deleted.

### 1.2 Catch-up sync + fork detection in `zhtp/runtime`

**File:** `zhtp/src/runtime/components/consensus.rs` (2,819 LOC)

Beyond the legitimate adapter implementations (`ConsensusMeshBroadcaster`, `QuicValidatorTransport`, `BlockchainValidatorAdapter`), this file contains **consensus-layer policy logic**:

| Function | Line | Concern |
|---|---|---|
| `run_catch_up_sync_task` | 467 | 152-line orchestrator with FAST_COOLDOWN/NORMAL_COOLDOWN/RETRY_COOLDOWN tuning, divergence-counter state, peer prioritization |
| `prioritize_catchup_peers` | 659 | Validator-aware peer ranking |
| `catchup_sync_from_peer` | 700 | Block download + `apply_block` |
| `HashMismatchError` | 624-631 | Typed fork-detection signal |
| `WRONG_CHAIN_WIPE_THRESHOLD` | 479 | **Consensus-safety constant**: 3 consecutive ahead-peer rejections → halt |
| `convert_to_network_message` | 241 | Wire-format conversion between two `ValidatorMessage` types |

The `WRONG_CHAIN_WIPE_THRESHOLD = 3` constant is a consensus-safety parameter (deciding when to halt the node on chain divergence). It lives in `zhtp/runtime`, far from the BFT safety constants in `lib-consensus/src/engines/consensus_engine/mod.rs:213-296` (`MAX_CHURN_NUMERATOR`, `BFT_MIN_VALIDATORS`, `LEADER_ROTATION_RULE`). A reviewer auditing safety has to know to look in two places.

The fork-on-divergence logic at `zhtp/src/runtime/components/consensus.rs:582-601` HALTS consensus when ≥3 consecutive sync rounds reject our chain. This is a **safety-critical decision** — it should be visible from the consensus crate, not buried in a runtime adapter.

**Should move to:** Catch-up sync coordination becomes a method on a new `ConsensusRuntime` type in `lib-consensus-runtime`. Fork-divergence policy and the `WRONG_CHAIN_WIPE_THRESHOLD` constant move into `lib-consensus-core` alongside the other safety constants. The `zhtp/runtime` file shrinks to ~300 LOC of pure adapter code.

### 1.3 Two `ValidatorMessage` types + conversion shims

**Files:**
- `lib-consensus/src/types/mod.rs:338` — `pub enum ValidatorMessage { Propose, Vote, Heartbeat }` (3 variants, used by `ConsensusEngine`).
- `lib-consensus/src/validators/validator_protocol.rs` — `pub enum ValidatorMessage { Propose, Vote, Commit, RoundChange, Heartbeat }` (5 variants, used by `ValidatorProtocol` middleware).

Two enums with the same name, in the same crate, with overlapping but non-identical semantics. Conversion happens in:

- `zhtp/src/runtime/components/consensus.rs:241-320` — `convert_to_network_message()`.
- `lib-network/src/messaging/message_handler.rs:2169-2200` — `convert_*_message()` (the inverse).

The conversion at `consensus.rs:293-301` substitutes `lib_crypto::generate_nonce()` into the message ID specifically because the dedup cache otherwise silently dropped re-broadcasts of the same vote — a bug caused **by the existence of the second type**:

```rust
// Use a unique per-broadcast ID so the dedup cache never silently
// drops re-broadcasts of the same vote (vote.id is deterministic
// per height+round+voter, which caused 3600s suppression).
```

There is also a wall-clock timestamp injected at `consensus.rs:308-311`:

```rust
// Use real wall-clock timestamp for network freshness checks.
// The consensus engine uses a deterministic value internally, but the
// validator-protocol layer rejects messages with stale/future timestamps.
timestamp: std::time::SystemTime::now()...
```

The consensus engine spent considerable effort to make timestamps deterministic (`state_machine.rs:425, 769, 1810, 1428`), and then the conversion shim re-introduces wall-clock time at the wire-format boundary. This is **a leak of two different notions of "time" caused by two different `ValidatorMessage` types**.

**Should consolidate to:** One `ValidatorMessage` enum in `lib-consensus-core/types`. The 5-variant `validators::ValidatorMessage` adds `Commit` (redundant with `Vote { vote_type: Commit }` already used in the engine) and `RoundChange` (which the engine doesn't use). Delete both `Commit` and `RoundChange` variants; the engine handles round changes via `on_round_timeout()`.

### 1.4 Duplicate `MessageBroadcaster` traits

**Files:**
- `lib-consensus/src/types/mod.rs:376` — `pub trait MessageBroadcaster { broadcast_to_validators(message: ValidatorMessage, validator_ids: &[IdentityId]) }`.
- `lib-network/src/message_broadcaster.rs:97` — `pub trait MessageBroadcaster { broadcast_to_validators(message: ValidatorMessage, target_validators: &[PublicKey]) -> Result<BroadcastResult>, send_to_validator(...), reachable_validator_count(...), is_validator_reachable(...) }`.

Same trait name. Different signature (the lib-network version uses `PublicKey` instead of `IdentityId` and returns `BroadcastResult` instead of `Result<()>`). Different responsibilities (lib-network includes reachability queries, lib-consensus does not — per Invariant CE-ENG-5 the engine never queries network state).

The `lib-network/src/message_broadcaster.rs:49` line `pub use lib_consensus::validators::ValidatorMessage;` re-exports the wire-format `ValidatorMessage` from lib-consensus. So the lib-network broadcaster broadcasts the wire-format enum, while the lib-consensus broadcaster broadcasts the engine-internal enum, and the conversion happens in the runtime.

**Should consolidate to:** One `MessageBroadcaster` trait in `lib-consensus-core::ports` (as a *port* in the hexagonal-architecture sense). The reachability queries move to a separate `lib-network` concern (the engine doesn't need them, per CE-ENG-5).

### 1.5 Validator discovery deep-imported by the network layer

**File:** `lib-network/src/validator_discovery_transport.rs:33-34`

```rust
use lib_consensus::validators::validator_discovery::{
    ValidatorDiscoveryProtocol, ValidatorEndpoint, ValidatorStatus,
};
```

Validator discovery is a P2P concern, not a consensus concern. It is `lib-consensus/src/validators/validator_discovery.rs` (783 LOC) but consumed by `lib-network`. Either:

- The discovery code lives in lib-network and lib-consensus consumes it (correct dependency direction), or
- Discovery is a separate `lib-validator-discovery` crate.

Today the dependency is **upside-down**: lib-network imports from lib-consensus's `validators::validator_discovery::*` deep path.

**Should move to:** `lib-network/src/validator_discovery.rs` or a new `lib-validator-discovery` crate. The deep-path imports are evidence of API leakage from lib-consensus.

### 1.6 Mempool used by `zhtp` for transaction ingress

`lib-consensus/src/mempool/` (379 LOC) defines a transaction mempool — but `lib-mempool` ALREADY EXISTS as a workspace member (`Cargo.toml:18`). Two mempools.

The `zhtp` runtime and block-production paths use `lib_consensus::Mempool` (re-exported from `lib-consensus/src/lib.rs:42`) as well as the workspace `lib-mempool` crate. This duplication splits the mempool API and creates two sources of truth for "what transactions are pending".

**Should consolidate to:** Single mempool in `lib-mempool`. Delete `lib-consensus/src/mempool/`.

### 1.7 DAO types deep-imported by `lib-blockchain`

**File:** `lib-blockchain/src/blockchain/dao.rs:772-815` (and `consensus_integration_tests.rs:611`)

```rust
let execution_params: lib_consensus::dao::dao_types::DaoExecutionParams = ...;
match lib_consensus::dao::dao_types::DaoExecutionAction::GovernanceParameterUpdate(...)
match lib_consensus::dao::dao_types::GovernanceParameterValue::BlockchainTargetTimespan(...)
```

These are deep imports into `lib-consensus`'s `dao::dao_types::*`. The DAO module is a feature-gated submodule of consensus that lib-blockchain reaches into. This is the strongest signal that DAO does not belong in `lib-consensus`.

**Should move to:** `lib-governance` (already exists at workspace root, `Cargo.toml:21`).

---

## 2. What's Leaked In (non-consensus code inside `lib-consensus`)

`lib-consensus/src/lib.rs:11-29` declares 19 public modules. Most of them have no business being in a consensus crate. Inventory:

| Subdir | LOC | Belongs in consensus? | Why / Where it should go |
|---|---|---|---|
| `engines/consensus_engine/` | 8,338 | **YES** | The actual BFT FSM. Stays. |
| `validators/validator_manager.rs` | 532 | **YES** | Validator set management. Stays. |
| `validators/validator.rs` | 722 | **YES (most)** | The `Validator` struct + key handling. Stays. |
| `network/liveness_monitor.rs` | 709 | **YES** | Stall detection is consensus-internal. Stays. |
| `byzantine/` | 968 | **YES** | Equivocation detection, fault evidence. Stays. |
| `evidence.rs` | 438 | **YES** | Slashing evidence record. Stays. |
| `invariants.rs` | 506 | **YES** | NoFork / MonotonicHeight / QuorumRequired / FinalityIrreversible. Stays. |
| `fault_model.rs` | 94 | **YES** | `safety_quorum()` math. Stays. |
| `finality_model.rs` | 97 | **YES** | Abstract finality types. Stays. |
| `slashing/` | 733 | **PARTIAL** | The *math* (`calculate_slash_amount`, `JAIL_DURATION_BLOCKS`, etc., `lib.rs:49-55`) stays; the *policy* belongs in `lib-economy` or a new `lib-slashing`. |
| `validators/validator_protocol.rs` | 1,556 | **NO** | Wire-protocol middleware with signature verification. Belongs in `lib-network` or a new `lib-consensus-net` crate. Pulls in 5-variant `ValidatorMessage` (see §1.3). |
| `validators/validator_discovery.rs` | 783 | **NO** | P2P discovery. Already deep-imported by `lib-network` (§1.5). Move to `lib-network` or new `lib-validator-discovery`. |
| `validators/genesis.rs` | 284 | **NO** | Genesis-block loader. Belongs in `lib-blockchain` or new `lib-genesis`. |
| `network/codec.rs` | 866 | **NO** | Wire codec. Belongs in `lib-network` or `lib-types`. |
| `network/heartbeat.rs` | 849 | **NO** | Heartbeat protocol — explicitly documented as "advisory telemetry, not consensus messages" (`heartbeat.rs:13-15`). Belongs in `lib-network`. |
| `dao/` | 2,043 | **NO** | DAO governance engine. Already a separate `lib-governance` workspace member (`Cargo.toml:21`); consolidate there. |
| `observer/` | 3,810 | **NO** | ML/anomaly detection, "surprisal engine", "trajectory builder", "transition model". Per its own header (`observer/mod.rs:1-3`): "deterministic, passive observer layer for consensus behavior analysis". This is observability tooling — belongs in a new `lib-consensus-observer` crate or under `tools/`. |
| `mempool/` | 379 | **NO** | Transaction mempool. `lib-mempool` already exists (`Cargo.toml:18`). Delete and consolidate. |
| `mining/` | 182 | **NO** | `should_mine_block()` PoW mining decision. BFT consensus has no mining. Belongs in `lib-blockchain` or `zhtp/runtime`. |
| `proofs/` | 957 | **NO** | PoStorage / PoUW / PoStake proofs. Already a separate `lib-proofs` workspace member (`Cargo.toml:30`); consolidate there. |
| `rewards/` | 241 | **NO** | Reward calculator. `lib-economy` already exists (`Cargo.toml:20`); consolidate there. |
| `chain_evaluation.rs` | (size n/a) | **NO** | `ChainEvaluator`, `ChainDecision`, `ChainMergeResult` — longest-chain-style evaluation. BFT has no chain evaluation (single-finality). Belongs in `lib-blockchain` or, if used at all, in a new `lib-chain-fork-policy`. |
| `difficulty.rs` | (size n/a) | **NO** | `DifficultyManager`, `DifficultyConfig`. PoW difficulty adjustment. Used by `lib-blockchain/src/lib.rs:166` (re-exported). Belongs in `lib-blockchain` directly. |
| `testing/` | (small) | **NO** | `NoOpBroadcaster` — test fixture. Belongs in `lib-consensus-core/test-utils` feature, not in main module path. |

### 2.1 Feature flags that don't actually gate compilation

`lib-consensus/Cargo.toml:42-50`:

```toml
[features]
default = ["full"]
full = ["dao", "byzantine", "rewards", "ubi"]
dao = []
byzantine = []
rewards = []
ubi = []
testing = []
dev-insecure = []
```

These features are **empty** — they declare no `optional` dependencies and no `cfg(feature = ...)` gates on `pub mod ...` declarations. The only `#[cfg(feature = ...)]` references in the entire `lib-consensus/src/` tree are at `lib.rs:62, 65, 68`:

```rust
#[cfg(feature = "dao")]      pub use dao::*;
#[cfg(feature = "byzantine")] pub use byzantine::*;
#[cfg(feature = "rewards")]  pub use rewards::*;
```

These gate **only the `pub use` re-exports**. The modules themselves are unconditionally compiled (`lib.rs:12-29`: `pub mod dao;`, `pub mod byzantine;`, `pub mod rewards;` — no `cfg` gates). With `default = ["full"]` everything is on by default; turning a feature off only removes the convenience re-export, not the code. This gives the appearance of modularity without the substance.

### 2.2 Cargo dependency table is misleadingly clean

`lib-consensus/Cargo.toml:24-28` declares only:

```toml
lib-types     = { path = "../lib-types" }
lib-crypto    = { path = "../lib-crypto" }
lib-identity  = { path = "../lib-identity" }
lib-storage   = { path = "../lib-storage" }
lib-proofs    = { path = "../lib-proofs" }
```

No dependency on `lib-blockchain`, `lib-network`, `lib-mempool`, `lib-fees`, `lib-tokens`, `lib-economy`, `lib-governance`, `lib-dht`, `lib-dns`. This was confirmed by `grep -rn "use lib_blockchain|lib_mempool|lib_fees|..." lib-consensus/src/` returning no results.

The cleanliness is **achieved by reimplementing the missing pieces** (mempool, DAO, rewards, mining, proofs) inside `lib-consensus` itself rather than depending on the corresponding crates. The dependency graph looks orthogonal but the code is duplicated. The proper modularity solution is to **add** dependencies on `lib-mempool`, `lib-economy`, `lib-governance`, `lib-proofs` and delete the in-tree re-implementations.

---

## 3. Target Module Shape

The goal: a `lib-consensus-core` crate that another project (or another blockchain) could depend on **without** pulling in this network's DAO, this network's economy, this network's wire protocol, or this network's observer.

### 3.1 Three-crate split

```
lib-consensus-core/      ~6,000 LOC   pure BFT FSM, no IO
├── src/
│   ├── lib.rs
│   ├── engine/          ── ConsensusEngine, RoundTimer, TimerToken
│   ├── fsm/             ── ValidatorFSM (new — see §3.3), transition()
│   ├── types/           ── ConsensusStep, VoteType, ConsensusVote, ConsensusProposal
│   ├── validator_set/   ── ValidatorManager, snapshots, churn rules
│   ├── vote_pool/       ── VotePoolKey, equivocation detection
│   ├── byzantine/       ── EvidenceStore, fault classification
│   ├── invariants/      ── NoFork, MonotonicHeight, QuorumRequired
│   ├── slashing/        ── pure slash math (no policy)
│   └── ports/           ── trait MessageBroadcaster, BlockCommitCallback,
│                            ConsensusBlockchainProvider, CatchUpSyncTrigger
└── Cargo.toml           depends on: lib-types, lib-crypto, lib-identity

lib-consensus-net/       ~3,000 LOC   wire format + transport adapters
├── src/
│   ├── lib.rs
│   ├── codec/           ── BincodeConsensusCodec (was lib-consensus/src/network/codec.rs)
│   ├── heartbeat/       ── HeartbeatTracker (was lib-consensus/src/network/heartbeat.rs)
│   ├── validator_protocol/  ── signed-envelope middleware
│   │                            (was lib-consensus/src/validators/validator_protocol.rs)
│   └── discovery/       ── ValidatorDiscoveryProtocol
│                            (was lib-consensus/src/validators/validator_discovery.rs)
└── Cargo.toml           depends on: lib-consensus-core, lib-network, lib-crypto

lib-consensus-runtime/   ~1,000 LOC   orchestration glue
├── src/
│   ├── lib.rs
│   ├── runtime.rs       ── ConsensusRuntime, owns ConsensusEngine + adapters
│   ├── catch_up_sync.rs ── moved from zhtp/runtime/components/consensus.rs:445-619
│   ├── fork_policy.rs   ── WRONG_CHAIN_WIPE_THRESHOLD + halt logic
│   └── adapters/        ── ConsensusMeshBroadcaster, QuicValidatorTransport,
│                            BlockchainValidatorAdapter, CatchUpSyncChannel
└── Cargo.toml           depends on: lib-consensus-core, lib-consensus-net,
                                     lib-blockchain, lib-network
```

### 3.2 Things that exit `lib-consensus` entirely

| Removed module | Goes to | Notes |
|---|---|---|
| `dao/` (2,043 LOC) | `lib-governance` | Already exists. Move types and engine. |
| `observer/` (3,810 LOC) | new `lib-consensus-observer` or `tools/consensus-observer/` | Optional dependency that observer-runtime nodes pull in. |
| `mempool/` (379 LOC) | `lib-mempool` | Already exists. Delete duplicate. |
| `mining/` (182 LOC) | `lib-blockchain` | `should_mine_block` is a blockchain-level decision. |
| `proofs/` (957 LOC) | `lib-proofs` | Already exists. Move PoStorage / PoUW / PoStake. |
| `rewards/` (241 LOC) | `lib-economy` | Already exists. Move `RewardCalculator`. |
| `difficulty.rs` | `lib-blockchain` | PoW difficulty has no place in BFT. |
| `chain_evaluation.rs` | `lib-blockchain` | Longest-chain rule is blockchain-level. |
| `validators/genesis.rs` (284 LOC) | `lib-blockchain` or new `lib-genesis` | Genesis loading is bootstrap concern. |

This drops `lib-consensus` from ~30 K LOC of in-tree code to ~6 K LOC of actual consensus.

### 3.3 The `ValidatorFSM` that doesn't exist today

The companion forensic report (`bft-consensus-forensic-analysis.md`, §5–§6) flagged that there is no central `ValidatorFSM` type and no total `transition()` function. The target shape introduces both:

```rust
// lib-consensus-core/src/fsm/mod.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmState {
    Idle,         // pre-genesis or paused
    Proposing,
    Prevoting,
    Precommitting,
    Committed,
    Rejected(RejectionReason),
    Hung,         // watchdog declared the FSM stuck
    HaltedForUpgrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    InsufficientPrevotes,
    InsufficientPrecommits,
    Timeout,
    InvalidBlock,
}

pub struct ValidatorFsm {
    state: FsmState,
    height: u64,
    round: u32,
    entered_at: std::time::Instant,   // CRITICAL — missing today
    action_tx: tokio::sync::mpsc::UnboundedSender<Action>,
}

impl ValidatorFsm {
    pub fn transition(&mut self, event: Event) -> FsmState { /* total match */ }
    pub fn enter(&mut self, new_state: FsmState) {
        self.state = new_state;
        self.entered_at = std::time::Instant::now();   // CRITICAL — missing today
    }
    pub fn send(&self, action: Action) {              // non-blocking, never .await
        let _ = self.action_tx.send(action);
    }
    pub fn state_timed_out(&self, budget: Duration) -> bool {
        self.entered_at.elapsed() >= budget
    }
}

pub enum Event {
    SelectedAsProposer,
    ReceivedProposal(ConsensusProposal),
    PrevoteThresholdReached(Hash),
    PrecommitThresholdReached(Hash),
    CommitQuorumReached(Hash),
    VoteFailed(RejectionReason),
    Timeout,
    WatchdogFired,
    UpgradeSignal { halt_at_height: u64 },
}

pub enum Action {
    BroadcastBlock(ConsensusProposal),
    SendPrevote(ConsensusVote),
    SendPrecommit(ConsensusVote),
    CommitBlock(ConsensusProposal, BftQuorumProof),
    AdvanceRound,
    ResetWatchdog,
    HaltForUpgrade,
    LogHung { reason: String },
}
```

The current scattered handlers (`on_proposal`, `on_prevote`, `on_precommit`, `on_commit_vote`, `on_round_timeout` in `state_machine.rs`) collapse into one `transition(state, event) -> next_state` match. Side effects become `Action` enum values dispatched through `action_tx` to a separate task — eliminating the inline-await problem flagged in the forensic report §9.

### 3.4 The `ConsensusRuntime` that consolidates orchestration

```rust
// lib-consensus-runtime/src/runtime.rs

pub struct ConsensusRuntime {
    engine: ConsensusEngine,                      // from lib-consensus-core
    broadcaster: Arc<dyn MessageBroadcaster>,      // from lib-consensus-core::ports
    block_committer: Arc<dyn BlockCommitCallback>, // from lib-consensus-core::ports
    catch_up_sync: CatchUpSyncTask,                // moved from zhtp runtime
    fork_policy: ForkDivergencePolicy,             // moved from zhtp runtime
    watchdog: WatchdogTask,                        // NEW — from forensic report §7
}

impl ConsensusRuntime {
    pub async fn run(self) -> Result<()> {
        // tokio::select! over engine, action receiver, watchdog, catch_up_sync.
        // The engine never .awaits side effects — it sends Actions on a channel.
        // The runtime executes Actions in spawned tasks.
    }
}
```

This replaces:
- `zhtp/src/runtime/components/consensus.rs:445-619` (catch-up sync logic)
- `lib-blockchain/src/integration/consensus_integration.rs` entirely (the parallel `BlockchainConsensusCoordinator`)

Net reduction in scattered consensus code: **~4,500 LOC consolidated into ~1,000 LOC of runtime**.

### 3.5 Cargo.toml shape

```toml
# lib-consensus-core/Cargo.toml — pure FSM, no IO, no domain leak
[dependencies]
lib-types     = { path = "../lib-types" }
lib-crypto    = { path = "../lib-crypto" }
lib-identity  = { path = "../lib-identity" }
serde         = { version = "1.0", features = ["derive"] }
thiserror     = "1.0"
tracing       = "0.1"
async-trait   = "0.1"   # for the port traits

# NO dependency on lib-storage, lib-proofs, tokio's `full` feature, chrono, dashmap, etc.
# tokio appears only as a "rt" feature dependency for tests.

[features]
default = []
test-utils = ["dep:tokio"]
```

```toml
# lib-consensus-net/Cargo.toml
[dependencies]
lib-consensus-core = { path = "../lib-consensus-core" }
lib-network        = { path = "../lib-network" }
lib-crypto         = { path = "../lib-crypto" }
tokio              = { version = "1.0", features = ["sync", "rt", "macros"] }
```

```toml
# lib-consensus-runtime/Cargo.toml
[dependencies]
lib-consensus-core = { path = "../lib-consensus-core" }
lib-consensus-net  = { path = "../lib-consensus-net" }
lib-blockchain     = { path = "../lib-blockchain" }
lib-network        = { path = "../lib-network" }
tokio              = { version = "1.0", features = ["full"] }
```

The "no IO" constraint in `lib-consensus-core` is the load-bearing rule. It guarantees that a different network, a different storage, a different blockchain implementation can plug in by implementing the `ports` traits.

### 3.6 Acceptance criteria for "consensus operates as a module"

A crate is a **module** if all of the following hold:

1. **Pluggable transport.** Replacing the QUIC mesh with a TCP-based or in-process channel transport requires implementing one trait (`MessageBroadcaster`) and **changing zero lines of `lib-consensus-core`**. Today: false — `MessageBroadcaster` is duplicated, and the wire-format conversion in `zhtp/runtime/consensus.rs:241` is required.

2. **Pluggable storage.** Swapping sled for RocksDB or in-memory storage requires implementing one trait (`BlockCommitCallback`) and changing zero lines of consensus. Today: true (the trait exists at `lib-consensus/src/types/mod.rs:519`), but the inline-await of the callback (`state_machine.rs:1186`) means a new storage layer must match sled's latency profile to avoid hangs.

3. **No domain leak.** Removing the entire `lib-governance` (DAO) crate from the workspace must compile `lib-consensus-core` clean. Today: false — DAO types live inside lib-consensus.

4. **No two consensus drivers.** There is exactly one struct that owns the consensus state machine and exactly one task that drives it. Today: false — `ConsensusEngine::run_consensus_loop` and `BlockchainConsensusCoordinator::consensus_event_loop` co-exist.

5. **No two `ValidatorMessage` types.** The wire format and the engine-internal format are the same. Today: false — `lib_consensus::types::ValidatorMessage` (3 variants) vs `lib_consensus::validators::ValidatorMessage` (5 variants).

6. **No re-exports of internal modules.** External consumers import from `lib_consensus::{ConsensusEngine, ConsensusEvent, Validator, ValidatorMessage}` only — never `lib_consensus::dao::dao_types::*` or `lib_consensus::validators::validator_discovery::*`. Today: false — `lib-blockchain/src/blockchain/dao.rs:772` and `lib-network/src/validator_discovery_transport.rs:33` reach into private subdirs.

7. **Total transition function.** A static analysis can prove `transition(state, event)` is total over the product of state × event. Today: false — `on_round_timeout(NewRound)` is `_ => {}` at `state_machine.rs:1831` and `handle_consensus_event` has a catch-all `_ => Ok(vec![])` at `state_machine.rs:330`.

---

## 4. Migration Order (lowest-risk first)

1. **Delete `lib-consensus/src/mempool/`**. Replace all in-crate uses with `lib_mempool`. Risk: low — `lib-mempool` already exists.
2. **Delete `lib-consensus/src/mining/`**. Move `should_mine_block()` to `lib-blockchain`. Risk: low — only one external caller (`zhtp/src/runtime/services/mining_service.rs:18`).
3. **Move `lib-consensus/src/rewards/` → `lib-economy/src/rewards/`**. Risk: low — `RewardCalculator` is used inside the engine (`mod.rs:475`); switch to a callback (`RewardCallback` trait).
4. **Move `lib-consensus/src/proofs/` → `lib-proofs/src/`**. Risk: medium — `lib-proofs` already exists but proofs are coupled to validator info.
5. **Unify `ValidatorMessage`**. Pick the 3-variant `types::ValidatorMessage`; delete the 5-variant `validators::ValidatorMessage`; delete the conversion shims in `zhtp/src/runtime/components/consensus.rs:241` and `lib-network/src/messaging/message_handler.rs:2169`. Risk: medium — touches the wire format. Wire-protocol version must be bumped (`CONSENSUS_PROTOCOL_VERSION` at `lib-consensus/src/engines/consensus_engine/mod.rs:247`).
6. **Move `lib-consensus/src/dao/` → `lib-governance/`**. Replace deep imports in `lib-blockchain/src/blockchain/dao.rs` with the new path. Risk: medium — large surface area, ~30 callers across the workspace.
7. **Move `lib-consensus/src/observer/` → new `lib-consensus-observer/`**. Risk: low (observer is observability-only, no consensus dependency on it from the engine path).
8. **Move `lib-consensus/src/validators/{validator_protocol,validator_discovery,genesis}.rs` → `lib-consensus-net/` (new) + `lib-blockchain/`**. Risk: high — `validator_protocol.rs` is 1,556 LOC and is the network-side wire-protocol middleware. Belongs in a new `lib-consensus-net` crate.
9. **Move `lib-consensus/src/network/{codec,heartbeat}.rs` → `lib-consensus-net/`**. Risk: medium.
10. **Introduce `ValidatorFsm` and `ConsensusRuntime`** (§3.3, §3.4). Risk: high — fundamentally restructures the engine. But the forensic report's top-3 dangerous findings (storage-await blocks loop, height desync on sync error, no watchdog) can only be properly fixed inside this restructure.
11. **Consolidate `BlockchainConsensusCoordinator` into `ConsensusRuntime`**. Delete `lib-blockchain/src/integration/consensus_integration.rs`. Move catch-up sync from `zhtp/src/runtime/components/consensus.rs` into `lib-consensus-runtime/src/catch_up_sync.rs`. Risk: high.

Steps 1–7 are mechanical and can land independently. Steps 8–11 are the architectural rewrite and should be planned as a single epic — they are the only way to satisfy acceptance criteria 1, 4, 5, and 7 in §3.6.

---

## 5. Tally

| Section | Item | Status |
|---|---|---|
| §1 Scattered | Parallel coordinator in `lib-blockchain/src/integration/consensus_integration.rs` (2,124 LOC) | **CONFIRMED** |
| §1 Scattered | Catch-up sync + fork policy in `zhtp/src/runtime/components/consensus.rs:445-619` | **CONFIRMED** |
| §1 Scattered | Two `ValidatorMessage` types | **CONFIRMED** |
| §1 Scattered | Two `MessageBroadcaster` traits | **CONFIRMED** |
| §1 Scattered | `lib-network` deep-imports `validator_discovery` | **CONFIRMED** |
| §1 Scattered | Mempool duplication (`lib-consensus/mempool` vs `lib-mempool` workspace member) | **CONFIRMED** |
| §1 Scattered | DAO deep-imports from `lib-blockchain` | **CONFIRMED** |
| §2 Leaked in | `dao/` (2,043 LOC) | **REMOVE** |
| §2 Leaked in | `observer/` (3,810 LOC) | **REMOVE** |
| §2 Leaked in | `mempool/` (379 LOC) | **REMOVE** (delete, lib-mempool exists) |
| §2 Leaked in | `mining/` (182 LOC) | **REMOVE** |
| §2 Leaked in | `proofs/` (957 LOC) | **REMOVE** (move to lib-proofs) |
| §2 Leaked in | `rewards/` (241 LOC) | **REMOVE** (move to lib-economy) |
| §2 Leaked in | `validators/{validator_protocol,validator_discovery,genesis}.rs` (~2,623 LOC) | **REMOVE** (move to net + blockchain) |
| §2 Leaked in | `network/{codec,heartbeat}.rs` (~1,715 LOC) | **REMOVE** (move to net) |
| §2 Leaked in | `chain_evaluation.rs`, `difficulty.rs` | **REMOVE** (PoW concepts) |
| §2 Leaked in | Theatrical features (`dao`, `byzantine`, `rewards`, `ubi`) | **DELETE** (replaced by real crate split) |
| §3 Target | Three-crate split: core / net / runtime | **PROPOSED** |
| §3 Target | `ValidatorFsm` + total `transition()` | **PROPOSED** |
| §3 Target | `Action` channel replacing inline-await | **PROPOSED** |

**Headline numbers:**
- `lib-consensus` today: ~30,000 LOC across 19 modules.
- `lib-consensus-core` after extraction: ~6,000 LOC across 8 modules.
- Net deletion (mempool, mining, duplicate ValidatorMessage, theatrical features, parallel coordinator, conversion shims): **~5,000 LOC**.
- Net relocation (dao, observer, proofs, rewards, validator_protocol, validator_discovery, codec, heartbeat, chain_evaluation, difficulty): **~14,000 LOC** moves to its rightful home.

---

## 6. Follow-up Audit — Adapter Architecture Violations

The §11 brief of the companion forensic report flagged that two impls (`MessageBroadcaster`, `BlockCommitCallback`) needed an audit. The latency-class findings (unbounded waits) are documented in `bft-consensus-forensic-analysis.md §12`. This section captures the *architectural* violations the same audit surfaced — the things wrong with how the adapters are *shaped*, not how slow they are.

### 6.1 Concurrency Architecture — BFT commit shares the global blockchain write lock

**Files:** `zhtp/src/runtime/components/consensus.rs:1083, 1304`, `lib-blockchain/src/blockchain.rs:843, 868, 882`.

`ConsensusBlockCommitter::commit_finalized_block` and `commit_finalized_block_with_proof` both call `blockchain_arc.write().await` to acquire the **global** `RwLock<Blockchain>`. The same lock is acquired by:

| Caller | Path | Purpose |
|---|---|---|
| Catch-up sync | `lib-blockchain/src/blockchain.rs:882` `apply_block_trusted_for_sync` | Apply downloaded blocks |
| Network observer | `lib-blockchain/src/blockchain.rs:868` `add_block_from_network` | Sync-only path |
| Local block-add | `lib-blockchain/src/blockchain.rs:843` `add_block` | Same path BFT uses |
| Proposer (read) | `consensus.rs:1192-1195` (comment) `get_pending_transactions` | Holds `read()`, blocking writers |
| ZK proof generation | `consensus.rs:1252-1267` | `try_write` (advisory) |

The fact that BFT commit competes with catch-up sync, observer-path commits, and block-production reads on the same lock is an architecture violation. BFT finality is the most safety-critical write in the system; it should not be queued behind a 200-block catch-up batch or a proposer's pending-tx fetch.

**The mitigation already applied** (`consensus.rs:1192-1195`) is to spawn ZK proof and DHT indexing as background tasks. That mitigation is reactive — it patches one observed deadlock. The structural fix is to give BFT commit either a dedicated writer task or a higher-priority lane on the storage layer.

**Belongs in:** the `ConsensusRuntime` design from §3.4 — BFT commit becomes an `Action` enum value sent through the action channel; the runtime executes it on a single dedicated task that owns blockchain mutation. Catch-up sync sends `Action::ApplyTrustedBlocks` on the same channel and is naturally serialized after any in-flight BFT commit.

### 6.2 Two `MessageBroadcaster` traits, both with the same broken latency contract

The duplicate-trait architecture violation was already documented in §1.4. The follow-up audit closes a question that was open: *does the duplication matter behaviorally?*

| Impl | Trait | File | Per-peer timeout? | Parallel? |
|---|---|---|---|---|
| `ConsensusMeshBroadcaster` | `lib_consensus::types::MessageBroadcaster` | `zhtp/src/runtime/components/consensus.rs:58-143` | **No** | **No** (sequential) |
| `MeshMessageBroadcaster` | `lib_network::message_broadcaster::MessageBroadcaster` | `lib-network/src/message_broadcaster.rs:206-270` | **No** | **No** (sequential) |

Both traits and both impls have the **same** anti-pattern. The duplication is not protective — it doubles the surface area for the same bug. The architecture violation here is that **the trait does not constrain the impl**. The trait method signature `async fn broadcast_to_validators(...) -> Result<...>` says nothing about latency, parallelism, or per-recipient bounds, so neither impl provides any. A consensus-layer trait that puts side effects on the engine's critical path must enforce a contract the engine can rely on.

**Target trait shape** (belongs in `lib-consensus-core/src/ports/`):

```rust
#[async_trait]
pub trait MessageBroadcaster: Send + Sync {
    /// Fire-and-forget: must return within `budget`. Implementations parallelize
    /// per-recipient sends and apply per-recipient timeouts internally.
    /// Failures (partial or total) MUST NOT block the caller.
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        validator_ids: &[IdentityId],
        budget: Duration,                 // <- new: caller-controlled latency cap
    );                                    // <- no Result: best-effort by contract

    /// Backpressure signal: how many recipients accepted the most recent broadcast.
    /// Engine MAY use this for diagnostics; correctness MUST NOT depend on it.
    fn last_delivered_count(&self) -> usize;
}
```

This trait shape makes the latency budget a first-class parameter of the call. The engine passes `propose_timeout / 4` and the implementation cannot exceed it. CE-ENG-4 ("MUST NOT depend on broadcast success") becomes enforceable rather than aspirational.

### 6.3 The 300s QUIC `max_idle_timeout` is a consensus-safety constant living in lib-network

**File:** `lib-network/src/protocols/quic_mesh.rs:1706-1708, 1760-1762`.

```rust
// Issue #907: Raised from 30s to 300s to prevent premature peer disconnection
transport_config.max_idle_timeout(Some(Duration::from_secs(300).try_into().unwrap()));
```

This constant is the **de-facto upper bound** on how long the consensus engine can stall on a single broadcast (forensic report D1, D4). It was raised 10× per Issue #907 with the (legitimate) goal of fewer false-disconnect events. The consequence — that consensus-loop responsiveness drops by the same factor under transport stress — was not visible from the consensus crate.

**Architecture violation:** A constant that materially affects BFT liveness lives in a crate (`lib-network`) that `lib-consensus` does not even depend on. Changing it is a network-layer decision with no consensus-layer review path.

**Belongs in:** A `lib-consensus-core/src/budget.rs` module that exposes `MAX_BROADCAST_BUDGET_MS` and asserts at runtime against the actual transport's idle timer (via a new port trait `TransportInfo::idle_timeout()`). If the transport's idle timer exceeds the consensus broadcast budget, the runtime fails to start — turning a silent latency cliff into a startup error.

### 6.4 `BlockCommitCallback` doesn't belong as a callback at all

**Files:** `lib-consensus/src/types/mod.rs:519-568` (trait), `zhtp/src/runtime/components/consensus.rs:1052-1340` (impl), `lib-consensus/src/engines/consensus_engine/state_machine.rs:1180-1212` (call site).

The trait shape is callback-style: the engine calls `await callback.commit_finalized_block_with_proof(...)` inline (`state_machine.rs:1187`). This is what makes the storage-blocks-consensus problem possible at all — finding D2 cannot exist if commit is a one-way send instead of an awaited call.

A BFT engine's relationship to storage is fundamentally **one-way**: when 2f+1 commits arrive, the engine emits a "this block is final" signal and **does not need to know whether persistence succeeded** to make the next safety decision. (It needs to know **eventually** for crash-recovery purposes, but that is a runtime concern, not a per-step concern.)

**Architecture violation:** the trait imposes a request/response shape on a fire-and-forget event. The mismatch is exactly what creates the inline-await footgun.

**Target shape** (belongs in `lib-consensus-core/src/ports/`):

```rust
pub trait BlockFinalizationSink: Send + Sync {
    /// Engine emits this when 2f+1 commits arrive. Synchronous, non-blocking.
    /// Implementation owns the write task and signals failure through a separate channel.
    fn finalized(&self, proposal: ConsensusProposal, proof: BftQuorumProof);

    /// Async query: did the most recent N finalizations succeed?
    /// Engine polls this between rounds (out of the hot path) for halt-on-fork.
    async fn recent_failure(&self) -> Option<FinalizationError>;
}
```

The runtime's implementation owns the actual sled write in a dedicated task, with an internal channel buffering finalized blocks. The engine never awaits storage. The "halt on commit failure" semantic (`state_machine.rs:1197-1211`) moves out of the inline path: the runtime's writer task signals failure on its dedicated channel, the engine polls between rounds, and a failure in writer-task state translates to `FsmState::HaltedForUpgrade` or a new `FsmState::HaltedForStorageError` (per the `ValidatorFsm` design in §3.3).

### 6.5 Updated Acceptance Criteria

Adding to §3.6 ("Acceptance criteria for *consensus operates as a module*"):

8. **Latency contract on ports.** Every port trait that the engine awaits inline (today: `MessageBroadcaster`, `BlockCommitCallback`) takes a `Duration` budget as a parameter, OR is restructured as fire-and-forget with a separate failure channel. The engine's awaited call cannot exceed the smaller of (a) the budget passed in, (b) a constant declared in `lib-consensus-core::budget`. Today: false — both ports await unboundedly.

9. **Concurrency isolation for finalization.** BFT commit does not contend with catch-up sync, network-observer block paths, or proposer reads on the same lock. There is a single writer task that serializes all storage mutations and BFT commits hold a non-blocking input to it. Today: false — the global `RwLock<Blockchain>` is shared across all writers.

10. **No consensus-affecting constants in `lib-network`.** A `grep -rn "max_idle_timeout\|consensus" lib-network/src/` returns zero matches that affect consensus correctness. Today: false — `quic_mesh.rs:1706-1708, 1760-1762` is a consensus safety parameter in disguise.

### 6.6 Migration impact

The migrations from §4 are unchanged in number but two of them gain teeth:

- **Step 5 (unify `ValidatorMessage`)** now also unifies the two `MessageBroadcaster` traits and changes the unified trait's signature to take a `Duration` budget. Risk upgrades from medium to high — every caller of `broadcast_to_validators` workspace-wide updates.
- **Step 10 (`ValidatorFsm` + `ConsensusRuntime`)** is the only migration that fixes findings D1, D2, D3 from the forensic report's §12 *and* architecture violations 6.1, 6.4 from this section. It is not optional — it is the entire point of the architectural rewrite.
