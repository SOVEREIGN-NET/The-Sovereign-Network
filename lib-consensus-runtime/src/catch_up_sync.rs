//! Catch-up sync orchestrator (CONS-506).
//!
//! When a node falls behind the BFT-active height, this loop downloads
//! missing blocks from connected peers and applies them locally. The
//! orchestrator is **transport-agnostic** — it talks to the network
//! through [`CatchUpTransport`] and reads local height through
//! [`BlockchainHeightProvider`]. zhtp implements both traits over its
//! QUIC mesh + sled-backed blockchain; tests use in-memory fakes.
//!
//! ## Why the trait split
//!
//! The pre-CONS-506 code lived in
//! `zhtp/src/runtime/components/consensus.rs` and reached into
//! `crate::server::mesh::core::MeshRouter`,
//! `crate::runtime::mesh_router_provider::get_global_mesh_router`,
//! and `lib_network::client::ZhtpClient` directly. Lifting it into
//! `lib-consensus-runtime` without those concrete types means
//! abstracting two seams:
//!
//! 1. **Network transport** ([`CatchUpTransport`]) — listing connected
//!    peers and downloading blocks from a chosen peer. zhtp's QUIC
//!    mesh implementation also handles validator-aware peer
//!    prioritization on its side and returns peers already ordered
//!    by preference.
//! 2. **Local height** ([`BlockchainHeightProvider`]) — reading the
//!    current chain height. Trivial trait but lets the orchestrator
//!    avoid pulling `lib-blockchain` into `lib-consensus-runtime`'s
//!    deps.
//!
//! The fork-detection logic, cooldown adaptation, and
//! `WRONG_CHAIN_HALT_THRESHOLD` enforcement (CONS-310 / AD-011) live
//! here in the orchestrator — they're cross-cutting protocol policy,
//! not transport-specific.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lib_consensus_core::budget::WRONG_CHAIN_HALT_THRESHOLD;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;
use tracing::{debug, error, info, warn};

/// One peer reachable for catch-up sync. The `node_id` is opaque
/// bytes (typically the peer's QUIC node ID); the `addr` is a
/// human-readable string used in tracing + downloads. Returned by
/// [`CatchUpTransport::connected_peers`] in the order the impl wants
/// the orchestrator to try them — zhtp prioritizes validator peers
/// internally before returning.
#[derive(Debug, Clone)]
pub struct CatchUpPeer {
    pub node_id: Vec<u8>,
    pub addr: String,
}

/// Errors returned by [`CatchUpTransport::sync_from_peer`].
///
/// Specifically distinguishes `HashMismatch` (the peer is ahead of us
/// AND rejects our chain tip → fork signal) from generic transport
/// failures, so the orchestrator can count consecutive fork signals
/// against `WRONG_CHAIN_HALT_THRESHOLD` without parsing log strings.
#[derive(Debug, Error)]
pub enum CatchUpError {
    /// The peer rejected the request because our previous-block hash
    /// at `our_height + 1` differs from theirs. This is the
    /// fork-detection signal: only emitted when the peer is genuinely
    /// ahead of us.
    #[error("hash mismatch from peer at height {our_height_plus_one}: {detail}")]
    HashMismatch {
        our_height_plus_one: u64,
        detail: String,
    },
    /// Network failure, peer offline, deserialization error, etc. —
    /// any non-fork-signal sync failure.
    #[error("transport error: {0}")]
    Transport(#[from] anyhow::Error),
}

/// Network seam for catch-up sync. Implementations expose connected
/// peers (already prioritized by impl-side preference) and a
/// download-and-apply call that returns the number of blocks applied.
#[async_trait]
pub trait CatchUpTransport: Send + Sync {
    /// All currently-connected peers, in the order the orchestrator
    /// should try them. Returning empty is allowed and tells the
    /// orchestrator to back off and retry.
    async fn connected_peers(&self) -> Vec<CatchUpPeer>;

    /// Download blocks after `our_height` from `peer_addr` and apply
    /// them locally. Returns the number of blocks applied.
    ///
    /// `Ok(0)` means "peer is at the same height or behind us — try
    /// the next peer". `Ok(n > 0)` means "successfully applied n
    /// blocks, stop iterating peers this round".
    /// `Err(CatchUpError::HashMismatch { .. })` is the fork signal.
    async fn sync_from_peer(
        &self,
        peer_addr: &str,
        our_height: u64,
        target_height: u64,
    ) -> Result<usize, CatchUpError>;
}

/// State seam for catch-up sync — reads the local chain height
/// without dragging `lib-blockchain` into this crate's deps.
#[async_trait]
pub trait BlockchainHeightProvider: Send + Sync {
    /// Current local blockchain height. Returns `None` if the
    /// blockchain is not yet populated (bootstrap window).
    async fn current_height(&self) -> Option<u64>;
}

// --- orchestrator ---

/// Cooldown after a productive sync round (>= 200 blocks applied). We
/// stay aggressive while there's clearly more to fetch.
const FAST_COOLDOWN: Duration = Duration::from_secs(3);
/// Cooldown after a normal sync round (1..200 blocks applied).
const NORMAL_COOLDOWN: Duration = Duration::from_secs(10);
/// Cooldown after an unproductive round (no blocks applied or no
/// peers reachable). Avoid spamming when the network is quiet.
const RETRY_COOLDOWN: Duration = Duration::from_secs(5);

/// Drain catch-up triggers from `rx` and download missing blocks via
/// `transport`. Halts the loop (without exiting the process) when
/// `WRONG_CHAIN_HALT_THRESHOLD` consecutive rounds detect a fork.
///
/// `sled_path` is included only for the operator-facing halt message;
/// the orchestrator never wipes or touches storage directly (per the
/// Apr 2 2026 incident postmortem — sled preservation is mandatory).
pub async fn run_catch_up_sync_task(
    mut rx: Receiver<u64>,
    transport: Arc<dyn CatchUpTransport>,
    height_provider: Arc<dyn BlockchainHeightProvider>,
    sled_path: std::path::PathBuf,
) {
    let mut next_allowed_at = tokio::time::Instant::now();
    // Counts consecutive sync rounds in which ≥1 ahead peer returned a
    // hash mismatch and zero blocks were successfully applied. Resets
    // on any success.
    let mut consecutive_wrong_chain_rounds: u32 = 0;

    while let Some(first_target) = rx.recv().await {
        // Drain any duplicate triggers buffered while we were processing,
        // keeping the LARGEST target hint. This matters when divergence
        // fires many times in quick succession against a moving network —
        // we want to chase the most-recent (highest) observed height, not
        // the first one queued. Triggers passing 0 mean "no specific
        // target" (stall heuristic) and don't lift the running max.
        let mut target_hint = first_target;
        while let Ok(next) = rx.try_recv() {
            if next > target_hint {
                target_hint = next;
            }
        }

        // Adaptive rate-limit.
        let now = tokio::time::Instant::now();
        if now < next_allowed_at {
            debug!(
                "Catch-up sync cooldown ({:.1}s remaining), skipping",
                (next_allowed_at - now).as_secs_f32()
            );
            continue;
        }

        // Read current local blockchain height (may have advanced since trigger).
        let from_height = match height_provider.current_height().await {
            Some(h) => h,
            None => {
                warn!("Catch-up sync: blockchain not yet populated");
                continue;
            }
        };

        info!(
            "🔄 Catch-up sync: local blockchain height={}, downloading newer blocks",
            from_height
        );

        let peers = transport.connected_peers().await;
        if peers.is_empty() {
            warn!("Catch-up sync: no connected peers available");
            next_allowed_at = tokio::time::Instant::now() + RETRY_COOLDOWN;
            continue;
        }

        let peer_count = peers.len();
        let mut synced_blocks = 0usize;
        // Peers that were strictly ahead of us but returned a
        // hash-mismatch error. Counted via the typed CatchUpError
        // variant so the orchestrator stays robust to log-message
        // wording changes.
        let mut ahead_peers_rejecting: u32 = 0;
        for peer in &peers {
            match transport
                .sync_from_peer(&peer.addr, from_height, target_hint)
                .await
            {
                Ok(0) => {
                    debug!(
                        "Catch-up sync: peer {} at same height ({})",
                        peer.addr, from_height
                    );
                }
                Ok(n) => {
                    info!(
                        "✅ Catch-up sync: applied {} block(s) from {} (local height now ~{})",
                        n,
                        peer.addr,
                        from_height + n as u64
                    );
                    synced_blocks = n;
                    break;
                }
                Err(CatchUpError::HashMismatch { .. }) => {
                    warn!(
                        "Catch-up sync from {} hit hash mismatch (fork signal)",
                        peer.addr
                    );
                    ahead_peers_rejecting += 1;
                }
                Err(CatchUpError::Transport(e)) => {
                    warn!("Catch-up sync from {} failed: {}", peer.addr, e);
                }
            }
        }

        if synced_blocks > 0 {
            // Successful sync — reset the divergence counter.
            consecutive_wrong_chain_rounds = 0;
        } else if ahead_peers_rejecting > 0 && from_height > 0 {
            // At least one ahead peer rejected our chain this round.
            consecutive_wrong_chain_rounds += 1;
            warn!(
                "⚠️  Wrong-chain signal: {}/{} ahead peer(s) reject height {} \
                ({}/{} consecutive round(s))",
                ahead_peers_rejecting,
                peer_count,
                from_height + 1,
                consecutive_wrong_chain_rounds,
                WRONG_CHAIN_HALT_THRESHOLD,
            );

            if consecutive_wrong_chain_rounds >= WRONG_CHAIN_HALT_THRESHOLD {
                // Unrecoverable fork: our local chain state diverged
                // from every ahead peer we can reach. HALT consensus
                // and alert the operator. DO NOT wipe sled — data
                // destruction caused total chain loss in the Apr 2
                // 2026 incident. The operator must manually
                // investigate and decide whether to resync from a
                // peer or restore from backup.
                error!(
                    "CHAIN FORK DETECTED at height {}: {} consecutive round(s) of hash \
                     mismatch from {} ahead peer(s). Consensus HALTED. \
                     Sled preserved at {:?} for operator investigation. \
                     To recover: stop the node, rsync sled from an authoritative peer, restart.",
                    from_height + 1,
                    consecutive_wrong_chain_rounds,
                    ahead_peers_rejecting,
                    sled_path,
                );
                // Halt the sync loop — do not wipe, do not exit.
                // The node stays running (API accessible) but stops
                // syncing.
                break;
            }
        } else {
            // No hash mismatches this round — reset.
            consecutive_wrong_chain_rounds = 0;
        }

        next_allowed_at = tokio::time::Instant::now()
            + if synced_blocks >= 200 {
                FAST_COOLDOWN
            } else if synced_blocks > 0 {
                NORMAL_COOLDOWN
            } else {
                RETRY_COOLDOWN
            };
    }

    info!("Catch-up sync task exited");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::mpsc;

    /// Counting fake transport: returns a fixed peer list and lets
    /// each test inject sync-from-peer behavior.
    struct FakeTransport {
        peers: Vec<CatchUpPeer>,
        sync_calls: Arc<AtomicU32>,
        result: Arc<dyn Fn(u32) -> Result<usize, CatchUpError> + Send + Sync>,
    }

    #[async_trait]
    impl CatchUpTransport for FakeTransport {
        async fn connected_peers(&self) -> Vec<CatchUpPeer> {
            self.peers.clone()
        }
        async fn sync_from_peer(
            &self,
            _peer_addr: &str,
            _our_height: u64,
            _target_height: u64,
        ) -> Result<usize, CatchUpError> {
            let n = self.sync_calls.fetch_add(1, Ordering::SeqCst);
            (self.result)(n)
        }
    }

    /// Fake height provider returning a constant.
    struct FixedHeight(u64);

    #[async_trait]
    impl BlockchainHeightProvider for FixedHeight {
        async fn current_height(&self) -> Option<u64> {
            Some(self.0)
        }
    }

    #[tokio::test]
    async fn orchestrator_exits_when_trigger_channel_closes() {
        // Closing the trigger channel must drain the loop cleanly so
        // the runtime's shutdown path doesn't dangle a task.
        let transport = Arc::new(FakeTransport {
            peers: vec![],
            sync_calls: Arc::new(AtomicU32::new(0)),
            result: Arc::new(|_| Ok(0)),
        });
        let (tx, rx) = mpsc::channel::<u64>(4);
        let h = tokio::spawn(run_catch_up_sync_task(
            rx,
            transport,
            Arc::new(FixedHeight(100)),
            std::path::PathBuf::from("/tmp/test-sled"),
        ));
        drop(tx);
        let res = tokio::time::timeout(Duration::from_secs(2), h).await;
        assert!(res.is_ok(), "orchestrator did not exit on trigger close");
    }

    #[tokio::test(start_paused = true)]
    async fn orchestrator_halts_after_wrong_chain_threshold() {
        // 3 consecutive rounds of HashMismatch from an ahead peer →
        // orchestrator halts (loop exits but the task stays alive,
        // letting the runtime's other tasks continue).
        let transport = Arc::new(FakeTransport {
            peers: vec![CatchUpPeer {
                node_id: b"ahead-peer".to_vec(),
                addr: "ahead.example:9999".to_string(),
            }],
            sync_calls: Arc::new(AtomicU32::new(0)),
            result: Arc::new(|_| {
                Err(CatchUpError::HashMismatch {
                    our_height_plus_one: 101,
                    detail: "stale tip".into(),
                })
            }),
        });
        let (tx, rx) = mpsc::channel::<u64>(8);
        let h = tokio::spawn(run_catch_up_sync_task(
            rx,
            transport.clone(),
            Arc::new(FixedHeight(100)),
            std::path::PathBuf::from("/tmp/test-sled"),
        ));

        // Send 3 triggers spaced past the cooldown.
        for _ in 0..WRONG_CHAIN_HALT_THRESHOLD {
            tx.send(100).await.unwrap();
            // Advance past RETRY_COOLDOWN so the orchestrator processes
            // each trigger.
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        drop(tx);

        // Orchestrator should have halted within a bounded virtual time.
        let res = tokio::time::timeout(Duration::from_secs(60), h).await;
        assert!(
            res.is_ok(),
            "orchestrator should halt after WRONG_CHAIN_HALT_THRESHOLD wrong-chain rounds"
        );
        let calls = transport.sync_calls.load(Ordering::SeqCst);
        assert!(
            calls >= WRONG_CHAIN_HALT_THRESHOLD,
            "expected at least {} sync attempts before halt, got {}",
            WRONG_CHAIN_HALT_THRESHOLD,
            calls
        );
    }
}
