//! Proof-of-Useful-Work (PoUW) Backend Implementation
//!
//! This module implements the node-side functionality for the PoUW protocol:
//! - Challenge token generation (Phase 1)
//! - Receipt validation (Phase 2)
//! - Reward calculation (Phase 3)
//! - Security hardening and monitoring (Phase 4)
//! - Stress testing and production readiness (Phase 5)
//!
//! Reference: docs/dapps_auth/pouw-protocol-spec.md

pub mod challenge;
pub mod disputes;
pub mod health;
pub mod load_test;
pub mod metrics;
pub mod rate_limiter;
pub mod rewards;
pub mod session_log;
pub mod types;
pub mod validation;

pub use challenge::ChallengeGenerator;
pub use disputes::{Dispute, DisputeError, DisputeService, DisputeStatus, DisputeType};
pub use health::{HealthCheck, HealthCheckResponse, HealthStatus, PouwHealthChecker};
pub use load_test::{run_load_test, LoadTestConfig, LoadTestResults, SyntheticReceiptGenerator};
pub use metrics::{PouwMetrics, PouwMetricsSnapshot, RejectionType};
pub use rate_limiter::{PouwRateLimiter, RateLimitConfig, RateLimitReason, RateLimitResult};
pub use rewards::{
    BudgetState, EpochClientStats, IntermediarySplit, PayoutStatus, Reward, RewardCalculator,
    RewardTransaction,
};
pub use session_log::{new_shared_session_log, SessionLog, SessionLogEntry, SharedSessionLog};
pub use types::*;
pub use validation::{
    spawn_mesh_routing_listener, ReceiptValidationResult, ReceiptValidator, RejectionReason,
    SubmitResponse,
};

/// Spawn the POUW reward payout background task.
///
/// Runs every interval_secs seconds (one full epoch by default = 3600s).
/// Processes all Pending rewards: mints SOV on-chain via blockchain, persists,
/// and marks rewards Paid or Failed.
pub fn spawn_pouw_payout_task(
    calculator: std::sync::Arc<crate::pouw::rewards::RewardCalculator>,
    blockchain: std::sync::Arc<tokio::sync::RwLock<lib_blockchain::Blockchain>>,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        // Skip the immediate first tick -- let the node fully start before processing
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.tick().await;
        tracing::info!(interval_secs = interval_secs, "POUW payout task started");

        // Recover rewards left in `Processing` by an earlier run that
        // crashed / restarted between `mark_processing` and
        // `mark_paid` / `mark_failed`. Without this, every such reward
        // is permanently skipped by the `mark_processing` guard below
        // and the SOV the user is owed is never minted. Safe to do
        // unconditionally at task startup: this task is the only
        // producer of `Processing` state, and at this point no payout
        // is in flight.
        let stale_processing = calculator.reset_processing_rewards().await;
        if stale_processing > 0 {
            tracing::warn!(
                count = stale_processing,
                "Reset stale POUW rewards from Processing to Pending on startup \
                 (likely from a prior crash mid-mint)"
            );
        }

        loop {
            interval.tick().await;

            // Reset any previously-failed rewards so they get retried this cycle
            let reset_count = calculator.reset_failed_rewards().await;
            if reset_count > 0 {
                tracing::info!(
                    count = reset_count,
                    "Reset failed POUW rewards to Pending for retry"
                );
            }

            let pending = calculator.get_pending_rewards().await;
            if pending.is_empty() {
                tracing::debug!("POUW payout: no pending rewards this cycle");
                continue;
            }

            tracing::info!(count = pending.len(), "Processing POUW reward payouts");

            for reward in pending {
                let reward_id = reward.reward_id.clone();

                // Attempt to lock reward as processing (prevents concurrent double-pay)
                if !calculator.mark_processing(&reward_id).await {
                    tracing::debug!("Reward already processing or no longer pending, skipping");
                    continue;
                }

                // Compute total already reserved for intermediaries
                let intermediary_total: u128 = reward.intermediary_splits.iter().map(|s| s.amount).sum();
                let primary_amount = reward.final_amount.saturating_sub(intermediary_total);

                // Pay primary recipient
                let primary_result = mint_single_reward(&blockchain, &reward.client_did, primary_amount).await;

                match primary_result {
                    Ok(tx_hash) => {
                        // Pay intermediary nodes for routing receipts
                        let mut intermediary_results = Vec::new();
                        for split in &reward.intermediary_splits {
                            match mint_single_reward(&blockchain, &split.did, split.amount).await {
                                Ok(split_tx) => {
                                    tracing::info!(
                                        did = %split.did,
                                        amount = split.amount,
                                        tx_hash = %split_tx,
                                        "Intermediary routing reward paid"
                                    );
                                    intermediary_results.push((split.did.clone(), true));
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        did = %split.did,
                                        amount = split.amount,
                                        error = %e,
                                        "Intermediary routing reward failed"
                                    );
                                    intermediary_results.push((split.did.clone(), false));
                                }
                            }
                        }

                        let all_intermediaries_paid = intermediary_results.iter().all(|(_, ok)| *ok);

                        if all_intermediaries_paid {
                            calculator
                                .mark_paid(&reward_id, Some(tx_hash.as_bytes().to_vec()))
                                .await;
                            tracing::info!(
                                did = %reward.client_did,
                                amount = primary_amount,
                                epoch = reward.epoch,
                                tx_hash = %tx_hash,
                                intermediary_total,
                                "POUW reward paid -- TokenMint tx queued"
                            );
                        } else {
                            // Some intermediaries failed — mark Failed so they retry next cycle.
                            // NOTE: This may double-pay the primary on retry. True idempotency
                            // requires per-split tx tracking (see TODO in RewardCalculator).
                            calculator.mark_failed(&reward_id).await;
                            tracing::warn!(
                                did = %reward.client_did,
                                amount = primary_amount,
                                epoch = reward.epoch,
                                intermediaries_paid = intermediary_results.iter().filter(|(_, ok)| *ok).count(),
                                intermediaries_failed = intermediary_results.iter().filter(|(_, ok)| !ok).count(),
                                "POUW reward partially paid -- marking failed for retry"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            did = %reward.client_did,
                            amount = primary_amount,
                            epoch = reward.epoch,
                            error = %e,
                            "POUW payout failed -- will retry next epoch"
                        );
                        calculator.mark_failed(&reward_id).await;
                    }
                }
            }

            tracing::info!("POUW payout cycle complete");
        }
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte key_id from a `did:zhtp:<hex>` string.
fn derive_key_id_from_did(did: &str) -> anyhow::Result<[u8; 32]> {
    let hex_part = did
        .strip_prefix("did:zhtp:")
        .ok_or_else(|| anyhow::anyhow!("DID missing did:zhtp: prefix"))?;
    let bytes = hex::decode(hex_part)
        .map_err(|e| anyhow::anyhow!("Invalid DID hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "DID key_id must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Mint SOV for a single recipient and log the result.
async fn mint_single_reward(
    blockchain: &std::sync::Arc<tokio::sync::RwLock<lib_blockchain::Blockchain>>,
    did: &str,
    amount: u128,
) -> anyhow::Result<lib_blockchain::Hash> {
    let key_id = derive_key_id_from_did(did)?;
    let mut bc = blockchain.write().await;
    bc.mint_sov_for_pouw(key_id, amount)
}
