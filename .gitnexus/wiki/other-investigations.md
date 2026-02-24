# Other — investigations

# BFT Networking Integration Investigation Module Documentation

## Overview

The **BFT Networking Integration Investigation** module is part of the consensus engine for a Byzantine Fault Tolerant (BFT) system. This module is responsible for broadcasting messages to validators during various consensus phases. However, the current implementation is stubbed, meaning that while the necessary components exist, they are not wired correctly in the production runtime. This documentation outlines the purpose, functionality, and key components of the module, as well as the necessary steps to resolve the stubbed implementation.

## Purpose

The primary purpose of this module is to facilitate communication between nodes in a BFT consensus system. It ensures that messages such as proposals, PreVotes, PreCommits, and Commit votes are broadcasted to all validators in the network. This communication is crucial for achieving consensus across multiple nodes, enabling the system to function correctly in a distributed environment.

## Key Components

### 1. Consensus Engine

The `ConsensusEngine` is the core component that manages the consensus process. It orchestrates the various steps of the consensus algorithm and is responsible for calling the `broadcast_to_validators()` method to disseminate messages to validators.

#### Key Functions

- **run_propose_step()**: Initiates the proposal phase and broadcasts the proposal message.
- **run_prevote_step()**: Handles the PreVote phase and broadcasts PreVote messages.
- **run_precommit_step()**: Manages the PreCommit phase and broadcasts PreCommit messages.
- **run_commit_step()**: Finalizes the consensus by broadcasting Commit messages.

### 2. Message Broadcaster

The `MessageBroadcaster` trait defines the interface for broadcasting messages to validators. The actual implementation in the production environment should be `MeshMessageBroadcaster`, which is designed to route messages through a mesh network of peers.

#### Implementations

- **MeshMessageBroadcaster**: A fully implemented broadcaster that routes messages to validators using a mesh network. It utilizes the `MeshMessageRouter` to find the appropriate peers and send messages.

```rust
pub struct MeshMessageBroadcaster {
    local_peer_id: UnifiedPeerId,
    peer_registry: SharedPeerRegistry,
    mesh_router: Arc<MeshMessageRouter>,
}
```

- **NoOpBroadcaster**: A stub implementation used during development that ignores all broadcast calls. This is the current implementation in the production runtime, leading to the failure of message broadcasting.

### 3. Runtime Wiring

The runtime wiring is where the `ConsensusEngine` is initialized with the appropriate broadcaster. Currently, it is incorrectly set to use `NoOpBroadcaster`, which prevents any messages from being sent.

```rust
// Current (BROKEN):
let broadcaster = Arc::new(NoOpBroadcaster);
```

### 4. Dependencies

To replace the `NoOpBroadcaster` with `MeshMessageBroadcaster`, the following dependencies must be provided:

- **UnifiedPeerId**: Represents the local node's identity.
- **SharedPeerRegistry**: A registry of peers in the network.
- **Arc<MeshMessageRouter>**: The router responsible for directing messages to the correct peers.

## Execution Flow

The execution flow of the BFT Networking Integration module is primarily driven by the `ConsensusEngine`. The following sequence outlines how messages should be broadcasted during the consensus process:

1. **Proposal Phase**: The engine calls `run_propose_step()`, which broadcasts the proposal to validators.
2. **PreVote Phase**: The engine calls `run_prevote_step()`, broadcasting PreVote messages.
3. **PreCommit Phase**: The engine calls `run_precommit_step()`, broadcasting PreCommit messages.
4. **Commit Phase**: The engine calls `run_commit_step()`, broadcasting Commit messages.

### Mermaid Diagram

```mermaid
graph TD;
    A[Consensus Engine] -->|Calls| B[run_propose_step()]
    A -->|Calls| C[run_prevote_step()]
    A -->|Calls| D[run_precommit_step()]
    A -->|Calls| E[run_commit_step()]
    B -->|Broadcasts| F[Proposal]
    C -->|Broadcasts| G[PreVote]
    D -->|Broadcasts| H[PreCommit]
    E -->|Broadcasts| I[Commit]
```

## Impact of Current Implementation

The use of `NoOpBroadcaster` has significant implications for the functionality of the BFT consensus system:

- **No Proposals Broadcasted**: Validators do not receive proposals, preventing consensus from being reached.
- **No Voting Messages**: PreVotes, PreCommits, and Commit messages are not sent, leading to a failure in multi-node consensus.
- **Single-Node Operation**: The system effectively operates as a single-node BFT, which is not the intended design.

## Root Cause Analysis

The root cause of the stubbed implementation is that the `ConsensusComponent` was designed with dependency injection for the broadcaster, but the actual wiring in the production environment was never completed. The `NoOpBroadcaster` was intended as a temporary placeholder during development.

## Required Fix

To resolve the issue, the `NoOpBroadcaster` must be replaced with `MeshMessageBroadcaster` in the runtime. The following code snippet illustrates the necessary change:

```rust
// Current (BROKEN):
let broadcaster = Arc::new(NoOpBroadcaster);

// Fixed:
let broadcaster = Arc::new(MeshMessageBroadcaster::new(
    local_peer_id,
    peer_registry,
    mesh_router,
));
```

## Conclusion

The BFT Networking Integration Investigation module is critical for enabling communication in a BFT consensus system. The current implementation is stubbed, preventing proper message broadcasting. By replacing the `NoOpBroadcaster` with `MeshMessageBroadcaster`, the system can achieve multi-node consensus and function as intended.

## Files Examined

| File | Purpose |
|------|---------|
| `lib-consensus/src/engines/consensus_engine/state_machine.rs` | Contains broadcast calls for various consensus steps. |
| `lib-consensus/src/engines/consensus_engine/mod.rs` | Defines the consensus engine structure. |
| `lib-consensus/src/engines/consensus_engine/network.rs` | Manages message handling loops. |
| `lib-network/src/message_broadcaster.rs` | Implements the `MeshMessageBroadcaster`. |
| `lib-consensus/src/testing/mod.rs` | Defines the `NoOpBroadcaster` for testing. |
| `zhtp/src/runtime/components/consensus.rs` | Contains the runtime wiring for the consensus component. |

This documentation serves as a guide for developers looking to understand and contribute to the BFT Networking Integration module, ensuring that the necessary changes are made to enable full functionality.