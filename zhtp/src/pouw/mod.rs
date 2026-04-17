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
    BudgetState, EpochClientStats, PayoutStatus, Reward, RewardCalculator, RewardTransaction,
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

                // Derive recipient key_id from DID
                // Expected format: did:zhtp:<hex-encoded-32-byte-key-id>
                let key_id_result: anyhow::Result<[u8; 32]> = (|| {
                    let hex_part = reward
                        .client_did
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
                })();

                let key_id = match key_id_result {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!(
                            did = %reward.client_did,
                            error = %e,
                            "Cannot derive key_id from DID -- marking reward failed"
                        );
                        calculator.mark_failed(&reward_id).await;
                        continue;
                    }
                };

                // Create a TokenMint system transaction on the blockchain
                let mint_result = {
                    let mut bc = blockchain.write().await;
                    bc.mint_sov_for_pouw(key_id, reward.final_amount)
                };

                match mint_result {
                    Ok(tx_hash) => {
                        calculator
                            .mark_paid(&reward_id, Some(tx_hash.as_bytes().to_vec()))
                            .await;
                        tracing::info!(
                            did = %reward.client_did,
                            amount = reward.final_amount,
                            epoch = reward.epoch,
                            tx_hash = %tx_hash,
                            "POUW reward paid -- TokenMint tx queued"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            did = %reward.client_did,
                            amount = reward.final_amount,
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
