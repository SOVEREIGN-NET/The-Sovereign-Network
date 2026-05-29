//! State-divergence detector runtime task (state-unification #2635, Phase 1).
//!
//! Periodically samples the `Blockchain` god-object's in-memory state against
//! the sled-backed `BlockchainStore` (the documented source of truth) and
//! reports any disagreement. This is the observability layer that proves the
//! two stores agree *before* the read-migration phases (#2636–#2639) flip
//! callers to sled-first and Phase 4 (#2641) deletes the legacy in-memory
//! writers entirely.
//!
//! The detection logic itself is pure and crate-agnostic — it lives in
//! `lib_blockchain::divergence_detector`. This module only owns the runtime
//! concerns: env-gating, the tokio interval loop, and the shared blockchain
//! handle.
//!
//! Activation (all off by default — this task is a no-op unless explicitly
//! enabled):
//! - `ZHTP_DIVERGENCE_DETECT=1`        — spawn the detector
//! - `ZHTP_DIVERGENCE_PANIC=1`         — panic on mismatch (testnet/CI enforcement)
//! - `ZHTP_DIVERGENCE_INTERVAL_SECS=N` — sampling cadence (default 30)
//! - `ZHTP_DIVERGENCE_SAMPLE_SIZE=N`   — keys sampled per field per cycle (default 100)

use std::sync::Arc;

use lib_blockchain::divergence_detector::{self, DivergenceConfig, DivergenceMetrics};
use lib_blockchain::Blockchain;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Spawn the divergence detector if `ZHTP_DIVERGENCE_DETECT` is set.
///
/// No-op (and no task spawned) when the flag is absent, so production nodes
/// pay nothing unless an operator opts in. Mirrors the fire-and-forget spawn
/// style of `validator_ip::spawn_periodic_ip_update`.
pub fn spawn_divergence_detector(blockchain: Arc<RwLock<Blockchain>>) {
    let cfg = DivergenceConfig::from_env();
    if !cfg.enabled {
        return;
    }

    info!(
        interval_secs = cfg.interval_secs,
        sample_size = cfg.sample_size,
        panic_on_mismatch = cfg.panic_on_mismatch,
        "State-divergence detector enabled (#2635)"
    );

    tokio::spawn(async move {
        let metrics = DivergenceMetrics::new();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(cfg.interval_secs));
        // First tick fires immediately; skip it so we don't sample before the
        // store has had a chance to take its first block.
        ticker.tick().await;

        loop {
            ticker.tick().await;

            // CR #2658: snapshot the in-memory sample while holding the read
            // lock (cheap — bounded clones, NO sled I/O), then RELEASE the lock
            // before doing the slow sled comparison. Holding the read lock
            // across sled I/O would block every consensus `blockchain.write()`
            // for the duration of the scan and could stall a BFT round.
            let snapshot = {
                let bc = blockchain.read().await;
                divergence_detector::snapshot_in_memory(&bc, cfg.sample_size)
            }; // <-- read lock dropped here

            let mismatches = match snapshot {
                Some(snap) => {
                    // All sled I/O happens here, lock-free.
                    let divergences = divergence_detector::compare_to_sled(&snap);
                    divergence_detector::report(
                        &divergences,
                        snap.sampled_count(),
                        &cfg,
                        &metrics,
                    )
                }
                // No store attached yet — nothing to compare.
                None => 0,
            };

            if mismatches == 0 {
                debug!("Divergence detector: clean cycle");
            } else {
                // report() already logged each mismatch at error! and bumped
                // metrics (and panicked if configured). Emit the rolling export
                // so the counts are observable without a Prometheus endpoint.
                info!(
                    mismatches,
                    metrics = %metrics.export_prometheus(),
                    "Divergence detector: mismatches this cycle"
                );
            }
        }
    });
}
