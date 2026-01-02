//! NodeRuntimeOrchestrator - Drives NodeRuntime decisions
//!
//! This component:
//! 1. Periodically calls NodeRuntime.on_timer() to get decisions
//! 2. Collects NodeActions from runtime
//! 3. Passes actions to executor queue for server to process
//! 4. Maintains peer state and notifies runtime of changes
//!
//! This is the bridge between policy (runtime) and execution (server).

use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, Duration};
use tracing::{info, debug, error};

use super::node_runtime::{NodeRuntime, NodeAction, Tick, PeerStateChange, PeerState};

/// Queue of pending actions for the server to execute
/// SECURITY: Bounded queue with deduplication to prevent DoS
pub struct ActionQueue {
    tx: mpsc::Sender<NodeAction>,
    rx: RwLock<mpsc::Receiver<NodeAction>>,
    dedup_set: Arc<RwLock<HashSet<String>>>,
    max_queue_size: usize,
}

impl ActionQueue {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1000); // SECURITY: Max 1000 pending actions
        Self {
            tx,
            rx: RwLock::new(rx),
            dedup_set: Arc::new(RwLock::new(HashSet::new())),
            max_queue_size: 1000,
        }
    }

    /// Enqueue an action for server execution (with deduplication and backpressure)
    pub async fn enqueue(&self, action: NodeAction) {
        // SECURITY: Deduplication - prevent duplicate actions from being queued
        let action_id = format!("{:?}", action);
        let mut dedup = self.dedup_set.write().await;

        if dedup.contains(&action_id) {
            debug!("🚫 Dropping duplicate action");
            return;
        }

        dedup.insert(action_id.clone());
        drop(dedup); // Release lock before sending

        // SECURITY: Bounded send provides backpressure - will fail if queue full
        match self.tx.send(action.clone()).await {
            Ok(()) => {
                debug!("✓ Action enqueued");
            }
            Err(e) => {
                error!("⚠️ Action queue full or closed - dropping action");
                // Remove from dedup set since we couldn't queue it
                self.dedup_set.write().await.remove(&action_id);
            }
        }
    }

    /// Get next action from queue (blocking)
    pub async fn dequeue(&self) -> Option<NodeAction> {
        if let Some(action) = self.rx.write().await.recv().await {
            // Remove from dedup set once dequeued
            let action_id = format!("{:?}", action);
            self.dedup_set.write().await.remove(&action_id);
            Some(action)
        } else {
            None
        }
    }
}

/// Orchestrates NodeRuntime decisions and periodic actions
pub struct NodeRuntimeOrchestrator {
    runtime: Arc<dyn NodeRuntime>,
    action_queue: Arc<ActionQueue>,
    peer_states: Arc<RwLock<std::collections::HashMap<Vec<u8>, PeerState>>>,
    is_running: Arc<RwLock<bool>>,
}

impl NodeRuntimeOrchestrator {
    pub fn new(runtime: Arc<dyn NodeRuntime>) -> Self {
        Self {
            runtime,
            action_queue: Arc::new(ActionQueue::new()),
            peer_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Get reference to action queue for server consumption
    pub fn action_queue(&self) -> Arc<ActionQueue> {
        self.action_queue.clone()
    }

    /// Start periodic runtime execution
    pub async fn start(&self) -> tokio::task::JoinHandle<()> {
        let runtime = self.runtime.clone();
        let queue = self.action_queue.clone();
        let is_running = self.is_running.clone();

        *is_running.write().await = true;

        tokio::spawn(async move {
            // Run periodic decision loops at different intervals
            let mut five_sec_interval = interval(Duration::from_secs(5));
            let mut thirty_sec_interval = interval(Duration::from_secs(30));
            let mut one_min_interval = interval(Duration::from_secs(60));
            let mut five_min_interval = interval(Duration::from_secs(300));

            while *is_running.read().await {
                tokio::select! {
                    _ = five_sec_interval.tick() => {
                        debug!("🔔 5-second tick - calling NodeRuntime");
                        let actions = runtime.on_timer(Tick::FiveSecond).await;
                        Self::enqueue_actions(&queue, actions).await;
                    }

                    _ = thirty_sec_interval.tick() => {
                        debug!("🔔 30-second tick - calling NodeRuntime");
                        let actions = runtime.on_timer(Tick::ThirtySecond).await;
                        Self::enqueue_actions(&queue, actions).await;
                    }

                    _ = one_min_interval.tick() => {
                        debug!("🔔 1-minute tick - calling NodeRuntime");
                        let actions = runtime.on_timer(Tick::OneMinute).await;
                        Self::enqueue_actions(&queue, actions).await;
                    }

                    _ = five_min_interval.tick() => {
                        debug!("🔔 5-minute tick - calling NodeRuntime");
                        let actions = runtime.on_timer(Tick::FiveMinute).await;
                        Self::enqueue_actions(&queue, actions).await;
                    }
                }
            }

            info!("NodeRuntimeOrchestrator stopped");
        })
    }

    /// Stop periodic execution
    pub async fn stop(&self) {
        *self.is_running.write().await = false;
    }

    /// Notify runtime of peer state change (NR-7: Policy Input Completeness)
    /// Caller must provide authoritative peer_info from discovery/registry
    pub async fn on_peer_state_changed(
        &self,
        peer: lib_crypto::PublicKey,
        peer_info: super::PeerInfo,
        old_state: PeerState,
        new_state: PeerState,
        reason: Option<String>,
    ) {
        // Update internal state tracking
        {
            let mut states = self.peer_states.write().await;
            states.insert(peer.key_id.to_vec(), new_state.clone());
        }

        // Notify runtime with complete peer metadata
        let change = PeerStateChange {
            peer,
            peer_info,
            old_state,
            new_state,
            reason,
        };

        let actions = self.runtime.on_peer_state_changed(change).await;
        Self::enqueue_actions(&self.action_queue, actions).await;
    }

    /// Helper to enqueue multiple actions
    async fn enqueue_actions(queue: &Arc<ActionQueue>, actions: Vec<NodeAction>) {
        for action in actions {
            queue.enqueue(action).await;
        }
    }
}
