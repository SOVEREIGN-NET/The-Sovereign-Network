//! Oracle Runtime Component
//!
//! Wires together:
//! - Incoming oracle attestation gossip (network → blockchain oracle state)
//! - Outgoing oracle attestation production (price fetch → sign → gossip)
//!
//! The oracle tracks SOV/USD price.  Attestations are produced once per oracle epoch
//! (default 600 s / ~60 blocks at 10 s block time).  A supermajority (⌊2N/3⌋+1) of
//! committee members must attest the same price for the epoch to finalize.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use lib_blockchain::{
    onramp::OraclePricingMode,
    oracle::{OraclePriceAttestation, ORACLE_PRICE_SCALE},
    Blockchain,
};
use lib_crypto::keypair::generation::KeyPair;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::runtime::services::{OracleFetchedPrice, OracleProducerConfig, OracleProducerService};

/// Oracle attestation consumer/producer runtime.
pub struct OracleComponent;

impl OracleComponent {
    /// Wire and spawn the oracle pipeline.
    ///
    /// - Creates an unbounded channel for incoming attestation gossip bytes.
    /// - Injects the sender end into the global mesh message handler so that
    ///   received `OracleAttestation` gossip messages are forwarded here.
    /// - Spawns a **consumer task** that deserializes and processes attestations.
    /// - Spawns a **producer task** that periodically fetches prices, builds a
    ///   signed attestation, gossips it, and processes it locally.
    ///
    /// `mock_sov_usd_price`: Mode A SRV override (atomic units, ORACLE_PRICE_SCALE 1e8).
    ///   Pass `None` to default to $1.00 SRV. Mode B activates automatically from on-ramp
    ///   VWAP once MIN_TRADES=5 and MIN_VOLUME=1,000 USDC thresholds are met.
    pub async fn start(
        blockchain: Arc<RwLock<Blockchain>>,
        validator_keypair: KeyPair,
        mock_sov_usd_price: Option<u64>,
    ) -> Result<()> {
        // Channel: gossip bytes → consumer task.
        // Bounded to 256 entries so a flooding peer cannot cause unbounded memory growth.
        // Wire the sender immediately so no incoming attestations are dropped while we wait
        // for the validator_registry to be fully seeded with bootstrap validators.
        let (oracle_tx, oracle_rx) = mpsc::channel::<Vec<u8>>(256);

        // Wire the sender into the QUIC message handler.
        if let Ok(mesh_router) =
            crate::runtime::mesh_router_provider::get_global_mesh_router().await
        {
            if let Some(quic_protocol) = mesh_router.quic_protocol.read().await.as_ref() {
                if let Some(handler) = quic_protocol.message_handler.as_ref() {
                    handler
                        .write()
                        .await
                        .set_oracle_attestation_sender(oracle_tx);
                    info!("🔗 Oracle attestation sender wired to mesh message handler");
                } else {
                    warn!("Oracle: QUIC message handler not available — attestations won't be received from peers");
                }
            } else {
                warn!("Oracle: QUIC protocol not available — attestations won't be received from peers");
            }
        } else {
            warn!("Oracle: mesh router not available — attestations won't be received from peers");
        }

        // Consumer task: waits for the validator_registry to have >= 2 active validators with
        // consensus keys before initialising the committee, then drains any queued attestations.
        // This eliminates the startup race where bootstrap validators haven't been seeded yet.
        {
            let bc = blockchain.clone();
            tokio::spawn(async move {
                // Poll until validator_registry has at least 2 validators with consensus keys
                // (i.e. bootstrap seeding has completed). Timeout after 60 s.
                let mut ready = false;
                for _ in 0..60 {
                    let count = {
                        let b = bc.read().await;
                        b.validator_registry
                            .values()
                            .filter(|v| v.status == "active" && !v.consensus_key.is_empty())
                            .count()
                    };
                    if count >= 2 {
                        ready = true;
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                if !ready {
                    warn!("Oracle consumer: validator_registry still has <2 active validators after 60 s — starting anyway");
                }
                // Note: Committee membership is set through governance path only.
                // The consumer reads from oracle_state.committee.members() which is populated
                // via schedule_committee_update() → apply_pending_updates() at epoch boundaries.
                Self::run_consumer(oracle_rx, bc).await;
            });
        }

        // Producer task: fetch prices, build attestation, gossip + process locally.
        {
            let bc = blockchain.clone();
            tokio::spawn(async move {
                Self::run_producer(bc, validator_keypair, mock_sov_usd_price).await;
            });
        }

        info!(
            "🔮 Oracle runtime started (mock_price={:?})",
            mock_sov_usd_price
        );
        Ok(())
    }

    // ── Consumer task ───────────────────────────────────────────────────────

    async fn run_consumer(mut rx: mpsc::Receiver<Vec<u8>>, blockchain: Arc<RwLock<Blockchain>>) {
        info!("🔮 Oracle attestation consumer started");
        while let Some(payload) = rx.recv().await {
            debug!(
                "🔮 Oracle: received attestation payload ({} bytes) via gossip",
                payload.len()
            );
            let attestation: OraclePriceAttestation = match bincode::deserialize(&payload) {
                Ok(a) => a,
                Err(e) => {
                    warn!(
                        "Oracle: failed to deserialize attestation ({} bytes): {}",
                        payload.len(),
                        e
                    );
                    continue;
                }
            };

            // ORACLE-R3: Check protocol version - in strict spec mode, attestations must go through
            // transactions only, not direct gossip processing
            {
                let bc = blockchain.read().await;
                if bc.oracle_state.is_strict_spec_active() {
                    // In strict spec mode, reject direct gossip attestations
                    // Validators must submit attestations via transactions
                    debug!(
                        "🔮 Oracle: rejecting gossip attestation in strict spec mode (epoch={}). \
                         Validators must use transaction-based attestations.",
                        attestation.epoch_id
                    );
                    continue;
                }
            }

            // Use block timestamp for epoch derivation (Oracle Spec v1 §4.1)
            // Wall clock MUST NOT be used to determine epoch_id.
            let mut bc = blockchain.write().await;
            let block_timestamp = bc.last_committed_timestamp();
            let current_epoch = bc.oracle_state.epoch_id(block_timestamp);

            // Guard: reject attestations from future epochs (more than 1 epoch ahead)
            if attestation.epoch_id > current_epoch + 1 {
                warn!(
                    "Oracle: attestation epoch {} is too far ahead of current {} — dropping",
                    attestation.epoch_id, current_epoch
                );
                continue;
            }

            // Build key lookup: oracle_signing_pubkeys (from bootstrap) takes priority,
            // then validator_registry consensus keys as fallback.
            let oracle_pubkeys = bc.oracle_state.oracle_signing_pubkeys.clone();
            let key_map: Vec<([u8; 32], [u8; 2592])> = bc
                .validator_registry
                .values()
                .filter(|v| !v.consensus_key.is_empty())
                .map(|v| {
                    let kid = lib_blockchain::blake3_hash(&v.consensus_key).as_array();
                    (kid, v.consensus_key)
                })
                .collect();

            let result = bc.oracle_state.process_attestation(
                &attestation,
                current_epoch,
                |key_id: [u8; 32]| {
                    // Check bootstrapped oracle signing pubkeys first.
                    if let Some(pk) = oracle_pubkeys.get(&key_id) {
                        if !pk.is_empty() {
                            return Some(pk.clone());
                        }
                    }
                    // Fall back to validator_registry consensus keys.
                    key_map
                        .iter()
                        .find(|(kid, _)| *kid == key_id)
                        .map(|(_, pk)| pk.to_vec())
                },
            );

            use lib_blockchain::oracle::{
                OracleAttestationAdmissionError, OracleAttestationValidationError,
                OracleSlashReason,
            };

            match result {
                Ok(admission) => {
                    info!(
                        "🔮 Oracle attestation admitted (epoch={}, price={} USD): {:?}",
                        attestation.epoch_id,
                        format_price_8dec(attestation.sov_usd_price),
                        admission
                    );
                    // Relay admitted attestations to all peers so nodes that aren't
                    // directly connected to every validator still reach quorum.
                    // Skip relay for our own attestations (already gossiped at production time)
                    // and for duplicates/finalized (no new information to share).
                    use lib_blockchain::oracle::OracleAttestationAdmission;
                    match &admission {
                        OracleAttestationAdmission::Accepted
                        | OracleAttestationAdmission::Finalized(_) => {
                            let att_clone = attestation.clone();
                            tokio::spawn(async move {
                                Self::gossip_attestation(&att_clone).await;
                            });
                        }
                        _ => {} // Don't relay duplicates or ignored attestations
                    }
                }
                Err(OracleAttestationAdmissionError::ConflictingSigner { .. }) => {
                    // ORACLE-4: Slash for double-signing (two different prices for same epoch)
                    warn!(
                        "🔮 Oracle: ConflictingSigner detected — slashing validator {} for double-sign",
                        hex::encode(&attestation.validator_pubkey[..8])
                    );
                    bc.slash_oracle_validator(
                        attestation.validator_pubkey,
                        OracleSlashReason::ConflictingAttestation,
                        attestation.epoch_id,
                    );
                }
                Err(OracleAttestationAdmissionError::Validation(validation_err)) => {
                    // Validation failures include non-malicious states (missing key material during startup,
                    // signature codec mismatch, or non-committee signer). Do not slash by default here.
                    //
                    // Note: Wrong-epoch attestations are normally handled as
                    // `IgnoredOutsideCurrentEpoch` by `precheck_attestation`, so they do not arrive here.
                    // We still keep explicit handling for defensive completeness.
                    match slash_reason_for_validation_error(&validation_err) {
                        Some(OracleSlashReason::WrongEpoch) => {
                            let (expected, got) = match validation_err {
                                OracleAttestationValidationError::WrongEpoch { expected, got } => {
                                    (expected, got)
                                }
                                _ => (0, 0),
                            };
                            warn!(
                                "🔮 Oracle: wrong-epoch attestation (expected={}, got={}) from {} — slashing",
                                expected,
                                got,
                                hex::encode(&attestation.validator_pubkey[..8])
                            );
                            bc.slash_oracle_validator(
                                attestation.validator_pubkey,
                                OracleSlashReason::WrongEpoch,
                                attestation.epoch_id,
                            );
                        }
                        Some(OracleSlashReason::DeviationBand) => {
                            let (attested, median, max_dev, actual_dev) = match &validation_err {
                                OracleAttestationValidationError::DeviationBand {
                                    attested_price,
                                    median_price,
                                    max_deviation_bps,
                                    actual_deviation_bps,
                                } => (
                                    *attested_price,
                                    *median_price,
                                    *max_deviation_bps,
                                    *actual_deviation_bps,
                                ),
                                _ => (0, 0, 0, 0),
                            };
                            warn!(
                                "🔮 Oracle: deviation-band violation (attested={}, median={}, max_dev={}bps, actual_dev={}bps) from {} — slashing",
                                attested,
                                median,
                                max_dev,
                                actual_dev,
                                hex::encode(&attestation.validator_pubkey[..8])
                            );
                            bc.slash_oracle_validator(
                                attestation.validator_pubkey,
                                OracleSlashReason::DeviationBand,
                                attestation.epoch_id,
                            );
                        }
                        Some(other_reason) => {
                            warn!(
                                "🔮 Oracle attestation validation mapped to unsupported slash reason {:?}; rejecting without slashing (validator={})",
                                other_reason,
                                hex::encode(&attestation.validator_pubkey[..8]),
                            );
                        }
                        None => {
                            warn!(
                                "🔮 Oracle attestation validation rejected without slashing: {:?} (validator={})",
                                validation_err,
                                hex::encode(&attestation.validator_pubkey[..8]),
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "🔮 Oracle attestation rejected (epoch={}): {:?}",
                        attestation.epoch_id, e
                    );
                }
            }
        }
        info!("Oracle attestation consumer exited (channel closed)");
    }

    // ── Producer task ───────────────────────────────────────────────────────

    async fn run_producer(
        blockchain: Arc<RwLock<Blockchain>>,
        keypair: KeyPair,
        mock_sov_usd_price: Option<u64>,
    ) {
        let mut producer = OracleProducerService::new(OracleProducerConfig::default());
        // Wait a bit at startup so that the blockchain and consensus are fully ready.
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        info!("🔮 Oracle attestation producer started");

        loop {
            // ORACLE-R8: Single snapshot of all on-chain state needed for this epoch.
            // Taking one lock avoids inconsistencies if a block commits between reads
            // (e.g. config/committee updated by one epoch while current_epoch is from another).
            let (
                on_chain_config,
                epoch_duration_secs,
                committee_members,
                current_epoch,
                is_strict_spec,
            ) = {
                let bc = blockchain.read().await;
                let config = bc.oracle_state.config.clone();
                let epoch_duration = config.epoch_duration_secs.max(60);
                let members = bc.oracle_state.committee.members().to_vec();
                let ts = bc.last_committed_timestamp();
                let epoch = bc.oracle_state.epoch_id(ts);
                let strict_spec = bc.oracle_state.is_strict_spec_active();
                (config, epoch_duration, members, epoch, strict_spec)
            };
            producer.update_config(&on_chain_config);

            if committee_members.is_empty() {
                debug!("Oracle producer: committee empty, skipping epoch");
                tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
                continue;
            }

            // Pricing Model v1.0: derive SOV/USD and CBE/USD from on-chain data only.
            //
            // Mode A (Genesis Reference): insufficient on-ramp data.
            //   SOV/USD = SRV (mock_sov_usd_price, $1 at genesis)
            //   CBE/USD = SRV * bonding_curve_price / ORACLE_PRICE_SCALE
            //
            // Mode B (Live Derived): on-ramp VWAP meets MIN_TRADES(5) and MIN_VOLUME(1000 USDC).
            //   CBE/USD = onramp_state.cbe_usd_vwap(current_block)
            //   SOV/USD = CBE/USD * ORACLE_PRICE_SCALE / cbe_sov_curve
            //
            // Transitions A→B and B→A are automatic based on window thresholds.
            // No external feeds. No SOV/USDC pairs. SOV/USD is always derived.
            let now_ts = unix_now();
            let (prices, cbe_usd_price) = {
                let bc = blockchain.read().await;
                let current_block = bc.get_height();
                let cbe_sov_curve = bc.get_cbe_curve_price_atomic();
                let mode = bc.onramp_state.oracle_mode(current_block);
                let cbe_usd_vwap = bc.onramp_state.cbe_usd_vwap(current_block);

                match (mode, cbe_usd_vwap, cbe_sov_curve) {
                    (OraclePricingMode::LiveDerived, Some(cbe_usd), Some(cbe_sov))
                        if cbe_sov > 0 =>
                    {
                        // Mode B: SOV/USD = CBE/USD_vwap * ORACLE_PRICE_SCALE / CBE/SOV_curve
                        // cbe_usd is in ORACLE_PRICE_SCALE (1e8) units.
                        // cbe_sov is in ORACLE_PRICE_SCALE (1e8) units (SOV per CBE).
                        if let Some(derived_sov_usd) = cbe_usd
                            .checked_mul(ORACLE_PRICE_SCALE as u128)
                            .and_then(|v| v.checked_div(cbe_sov as u128))
                        {
                            info!(
                                "🔮 Oracle Mode B: cbe_usd_vwap={}, cbe_sov_curve={}, \
                                 sov_usd={} USD",
                                cbe_usd,
                                cbe_sov,
                                format_price_8dec(derived_sov_usd)
                            );
                            let prices = vec![
                                OracleFetchedPrice {
                                    source_id: "onramp_vwap_a".into(),
                                    sov_usd_price: derived_sov_usd,
                                    timestamp: now_ts,
                                },
                                OracleFetchedPrice {
                                    source_id: "onramp_vwap_b".into(),
                                    sov_usd_price: derived_sov_usd,
                                    timestamp: now_ts,
                                },
                                OracleFetchedPrice {
                                    source_id: "onramp_vwap_c".into(),
                                    sov_usd_price: derived_sov_usd,
                                    timestamp: now_ts,
                                },
                            ];
                            (prices, Some(cbe_usd))
                        } else {
                            warn!(
                                "Oracle Mode B: overflow or divide-by-zero deriving SOV/USD \
                                 from cbe_usd_vwap={} cbe_sov_curve={}",
                                cbe_usd, cbe_sov
                            );
                            (Vec::new(), None)
                        }
                    }
                    _ => {
                        // Mode A: use SRV. CBE/USD derived from curve * SRV.
                        let sov_usd = mock_sov_usd_price
                            .map(|p| p as u128)
                            .unwrap_or(ORACLE_PRICE_SCALE as u128);
                        let cbe_usd = cbe_sov_curve.map(|cbe_sov| {
                            (cbe_sov as u128 * sov_usd) / ORACLE_PRICE_SCALE as u128
                        });
                        let prices = vec![
                            OracleFetchedPrice {
                                source_id: "srv_a".into(),
                                sov_usd_price: sov_usd,
                                timestamp: now_ts,
                            },
                            OracleFetchedPrice {
                                source_id: "srv_b".into(),
                                sov_usd_price: sov_usd,
                                timestamp: now_ts,
                            },
                            OracleFetchedPrice {
                                source_id: "srv_c".into(),
                                sov_usd_price: sov_usd,
                                timestamp: now_ts,
                            },
                        ];
                        (prices, cbe_usd)
                    }
                }
            };

            if prices.is_empty() {
                warn!(
                    "Oracle producer: no price sources available, skipping epoch {}",
                    current_epoch
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
                continue;
            }

            // Re-check epoch after price derivation.
            let epoch_after_fetch = {
                let bc = blockchain.read().await;
                bc.oracle_state.epoch_id(bc.last_committed_timestamp())
            };
            if epoch_after_fetch != current_epoch {
                warn!(
                    "Oracle producer: epoch changed during price fetch ({} → {}) — skipping",
                    current_epoch, epoch_after_fetch
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
                continue;
            }

            // Build and sign the attestation.
            // Note: attestation timestamp uses wall clock (when attestation was created),
            // while epoch_id uses block timestamp (per Oracle Spec v1 §4.1).
            let attestation_timestamp = unix_now();
            match producer.build_attestation(
                current_epoch,
                attestation_timestamp,
                &committee_members,
                &keypair,
                prices,
                cbe_usd_price,
            ) {
                Ok(Some(attestation)) => {
                    info!(
                        "🔮 Oracle produced attestation (epoch={}, price={} USD)",
                        current_epoch,
                        format_price_8dec(attestation.sov_usd_price)
                    );

                    if is_strict_spec {
                        // ORACLE-R3: In strict spec mode, create and submit a transaction
                        // instead of processing directly. The transaction will be included
                        // in a block and processed through the canonical path.
                        debug!(
                            "🔮 Oracle: strict spec mode - submitting attestation as transaction"
                        );
                        Self::submit_attestation_transaction(&attestation, &blockchain).await;
                    } else {
                        // Legacy mode: Gossip and process directly
                        Self::gossip_attestation(&attestation).await;

                        // Process locally (our own vote counts).
                        let mut bc = blockchain.write().await;
                        let epoch2 = bc.oracle_state.epoch_id(bc.last_committed_timestamp());
                        let oracle_pubkeys2 = bc.oracle_state.oracle_signing_pubkeys.clone();
                        let key_map: Vec<([u8; 32], [u8; 2592])> = bc
                            .validator_registry
                            .values()
                            .filter(|v| !v.consensus_key.is_empty())
                            .map(|v| {
                                let kid = lib_blockchain::blake3_hash(&v.consensus_key).as_array();
                                (kid, v.consensus_key)
                            })
                            .collect();

                        match bc.oracle_state.process_attestation(
                            &attestation,
                            epoch2,
                            |key_id: [u8; 32]| {
                                if let Some(pk) = oracle_pubkeys2.get(&key_id) {
                                    if !pk.is_empty() {
                                        return Some(pk.clone());
                                    }
                                }
                                key_map
                                    .iter()
                                    .find(|(kid, _)| *kid == key_id)
                                    .map(|(_, pk)| pk.to_vec())
                            },
                        ) {
                            Ok(r) => info!("🔮 Oracle: self-attestation local result: {:?}", r),
                            Err(e) => warn!("🔮 Oracle: self-attestation local rejected: {:?}", e),
                        }
                    }
                }
                Ok(None) => {
                    debug!(
                        "Oracle producer: abstaining epoch {} (not enough valid sources)",
                        current_epoch
                    );
                }
                Err(e) => {
                    warn!(
                        "Oracle producer: build_attestation failed (epoch={}): {:?}",
                        current_epoch, e
                    );
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
        }
    }

    // ── Gossip ──────────────────────────────────────────────────────────────

    async fn gossip_attestation(attestation: &OraclePriceAttestation) {
        let payload = match bincode::serialize(attestation) {
            Ok(b) => b,
            Err(e) => {
                warn!("Oracle gossip: serialize failed: {}", e);
                return;
            }
        };
        let msg = ZhtpMeshMessage::OracleAttestation { payload };
        let bytes = match bincode::serialize(&msg) {
            Ok(b) => b,
            Err(e) => {
                warn!("Oracle gossip: mesh message serialize failed: {}", e);
                return;
            }
        };

        if let Ok(mesh_router) =
            crate::runtime::mesh_router_provider::get_global_mesh_router().await
        {
            if let Some(qp) = mesh_router.quic_protocol.read().await.as_ref() {
                match qp.broadcast_message(&bytes).await {
                    Ok(count) => info!("🔮 Oracle attestation gossiped to {} peer(s)", count),
                    Err(e) => warn!("Oracle gossip broadcast failed: {}", e),
                }
            }
        }
    }

    /// Submit an attestation as a transaction in strict spec mode.
    ///
    /// ORACLE-R3: In strict spec mode, attestations go through the canonical
    /// transaction/block path. The transaction is added to the local mempool
    /// and will be included in a future block by the proposer.
    async fn submit_attestation_transaction(
        attestation: &OraclePriceAttestation,
        blockchain: &Arc<RwLock<Blockchain>>,
    ) {
        use lib_blockchain::transaction::core::{Transaction, TransactionPayload, TX_VERSION_V8};
        use lib_blockchain::transaction::oracle_governance::OracleAttestationData;
        use lib_blockchain::types::transaction_type::TransactionType;

        let attestation_data = OracleAttestationData {
            epoch_id: attestation.epoch_id,
            sov_usd_price: attestation.sov_usd_price,
            cbe_usd_price: attestation.cbe_usd_price,
            timestamp: attestation.timestamp,
            validator_pubkey: attestation.validator_pubkey,
            signature: attestation.signature.clone(),
        };

        // Derive chain_id from runtime configuration via the ZHTP_CHAIN_ID environment
        // variable, falling back to the legacy dev-chain id (0x03) if not set or invalid.
        let chain_id: u8 = std::env::var("ZHTP_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or_else(|| {
                debug!("ZHTP_CHAIN_ID not set or invalid; using fallback chain_id=0x03");
                0x03
            });

        let tx = Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::OracleAttestation,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature: lib_crypto::Signature::default(),
            memo: Vec::new(),
            payload: TransactionPayload::OracleAttestation(attestation_data),
        };

        let mut bc = blockchain.write().await;
        match bc.add_pending_transaction(tx) {
            Ok(()) => {
                info!(
                    "Oracle attestation submitted to mempool (epoch={})",
                    attestation.epoch_id
                );
            }
            Err(e) => {
                warn!(
                    "Oracle attestation mempool submission failed (epoch={}): {}",
                    attestation.epoch_id, e
                );
            }
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_price_8dec(value: u128) -> String {
    let whole = value / ORACLE_PRICE_SCALE as u128;
    let frac = value % ORACLE_PRICE_SCALE as u128;
    format!("{whole}.{frac:08}")
}

fn slash_reason_for_validation_error(
    err: &lib_blockchain::oracle::OracleAttestationValidationError,
) -> Option<lib_blockchain::oracle::OracleSlashReason> {
    match err {
        lib_blockchain::oracle::OracleAttestationValidationError::WrongEpoch { .. } => {
            Some(lib_blockchain::oracle::OracleSlashReason::WrongEpoch)
        }
        lib_blockchain::oracle::OracleAttestationValidationError::DeviationBand { .. } => {
            Some(lib_blockchain::oracle::OracleSlashReason::DeviationBand)
        }
        lib_blockchain::oracle::OracleAttestationValidationError::InvalidSignature
        | lib_blockchain::oracle::OracleAttestationValidationError::MissingSignerPublicKey(_)
        | lib_blockchain::oracle::OracleAttestationValidationError::NonCommitteeSigner(_)
        | lib_blockchain::oracle::OracleAttestationValidationError::DuplicateSigner(_)
        | lib_blockchain::oracle::OracleAttestationValidationError::EncodeError(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::{
        oracle::{OracleAttestationValidationError, OraclePriceAttestation, OracleSlashReason},
        transaction::core::TransactionPayload,
        types::transaction_type::TransactionType,
        Blockchain, ValidatorInfo,
    };
    use lib_crypto::keypair::generation::KeyPair;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Build a minimal ValidatorInfo for tests — fills only the fields that
    /// `validate_oracle_attestation_transaction` inspects.
    fn make_validator_info(identity: &str, consensus_key: [u8; 2592]) -> ValidatorInfo {
        let oracle_key_id = lib_crypto::hash_blake3(&consensus_key);
        ValidatorInfo {
            identity_id: identity.to_string(),
            stake: 10_000,
            storage_provided: 0,
            networking_key: Vec::new(),
            rewards_key: Vec::new(),
            network_address: "127.0.0.1:0".to_string(),
            commission_rate: 0,
            status: "active".to_string(),
            registered_at: 0,
            last_activity: 0,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: "test".to_string(),
            governance_proposal_id: None,
            oracle_key_id: Some(oracle_key_id),
            consensus_key,
        }
    }

    /// Set up a blockchain with a single oracle committee member, return the keypair
    /// and the `validator_pubkey` (= blake3 of the raw Dilithium public key).
    ///
    /// `Blockchain::default()` starts with an empty validator registry, a single
    /// genesis block (height 0), and oracle config defaults (epoch_duration_secs = 600).
    /// These are sufficient for the oracle attestation mempool submission path.
    fn setup_blockchain_with_oracle_validator() -> (Blockchain, KeyPair, [u8; 32]) {
        let kp = KeyPair::generate().expect("keypair generation must succeed");
        // consensus_key = raw Dilithium pk bytes; validator_pubkey = blake3 of those bytes
        let dilithium_pk = kp.public_key.dilithium_pk.clone();
        let validator_pubkey = lib_crypto::hash_blake3(&dilithium_pk);

        let mut blockchain = Blockchain::default();

        // Register the validator in the registry so the stateful validator can look it up
        let validator_info = make_validator_info("test-validator", dilithium_pk);
        blockchain
            .validator_registry
            .insert("test-validator".to_string(), validator_info);

        // Initialize oracle committee with only this validator's pubkey hash
        blockchain
            .init_oracle_committee(vec![validator_pubkey])
            .expect("oracle committee init must succeed");

        (blockchain, kp, validator_pubkey)
    }

    /// Build a signed OraclePriceAttestation for epoch 0 using the given keypair.
    fn build_signed_attestation(
        kp: &KeyPair,
        validator_pubkey: [u8; 32],
        epoch_id: u64,
        timestamp: u64,
    ) -> OraclePriceAttestation {
        let mut attestation = OraclePriceAttestation {
            epoch_id,
            sov_usd_price: 100_000_000, // $1.00 at 8 decimal precision
            cbe_usd_price: None,
            timestamp,
            validator_pubkey,
            signature: Vec::new(),
        };
        let digest = attestation
            .signing_digest()
            .expect("signing digest must build");
        let sig = kp.sign(&digest).expect("signing must succeed");
        attestation.signature = sig.signature;
        attestation
    }

    /// Verify that `submit_attestation_transaction` enqueues a single
    /// `TransactionType::OracleAttestation` transaction whose payload fields
    /// match the source attestation.
    #[tokio::test]
    async fn submit_attestation_enqueues_oracle_attestation_tx() {
        let (blockchain, kp, validator_pubkey) = setup_blockchain_with_oracle_validator();

        // Use a timestamp in the middle of epoch 0 so epoch_id(timestamp) == 0
        let epoch_duration = blockchain.oracle_state.config().epoch_duration_secs;
        let timestamp = epoch_duration / 2;
        let epoch_id = blockchain.oracle_state.epoch_id(timestamp);
        assert_eq!(epoch_id, 0, "timestamp should fall in epoch 0");

        let attestation = build_signed_attestation(&kp, validator_pubkey, epoch_id, timestamp);

        let blockchain_arc = Arc::new(RwLock::new(blockchain));

        OracleComponent::submit_attestation_transaction(&attestation, &blockchain_arc).await;

        // The transaction must have been enqueued
        let bc = blockchain_arc.read().await;
        let pending = bc.get_pending_transactions();
        assert_eq!(pending.len(), 1, "exactly one pending transaction expected");

        let tx = &pending[0];
        assert_eq!(
            tx.transaction_type,
            TransactionType::OracleAttestation,
            "transaction type must be OracleAttestation"
        );

        // Verify payload fields match the source attestation
        match &tx.payload {
            TransactionPayload::OracleAttestation(data) => {
                assert_eq!(data.epoch_id, attestation.epoch_id);
                assert_eq!(data.sov_usd_price, attestation.sov_usd_price);
                assert_eq!(data.cbe_usd_price, attestation.cbe_usd_price);
                assert_eq!(data.timestamp, attestation.timestamp);
                assert_eq!(data.validator_pubkey, attestation.validator_pubkey);
                assert_eq!(data.signature, attestation.signature);
            }
            other => panic!("unexpected payload variant: {:?}", other),
        }
    }

    /// Verify that the fallback chain_id (0x03) is used when ZHTP_CHAIN_ID is absent.
    ///
    /// Saves and restores the previous value of ZHTP_CHAIN_ID to avoid polluting
    /// the environment for concurrently-running tests.
    #[tokio::test]
    async fn submit_attestation_defaults_chain_id_when_env_unset() {
        // Save previous value so we can restore it after the test
        let previous = std::env::var("ZHTP_CHAIN_ID").ok();
        std::env::remove_var("ZHTP_CHAIN_ID");

        let (blockchain, kp, validator_pubkey) = setup_blockchain_with_oracle_validator();
        let epoch_duration = blockchain.oracle_state.config().epoch_duration_secs;
        let timestamp = epoch_duration / 2;
        let epoch_id = blockchain.oracle_state.epoch_id(timestamp);
        let attestation = build_signed_attestation(&kp, validator_pubkey, epoch_id, timestamp);

        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        OracleComponent::submit_attestation_transaction(&attestation, &blockchain_arc).await;

        let bc = blockchain_arc.read().await;
        let pending = bc.get_pending_transactions();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].chain_id, 0x03,
            "chain_id must fall back to 0x03 when ZHTP_CHAIN_ID is not set"
        );

        // Restore the previous env var value (if any) to avoid polluting other tests
        match previous {
            Some(val) => std::env::set_var("ZHTP_CHAIN_ID", val),
            None => std::env::remove_var("ZHTP_CHAIN_ID"),
        }
    }

    #[test]
    fn slashes_on_wrong_epoch_and_deviation_band() {
        let wrong_epoch = OracleAttestationValidationError::WrongEpoch {
            expected: 10,
            got: 11,
        };
        assert_eq!(
            slash_reason_for_validation_error(&wrong_epoch),
            Some(OracleSlashReason::WrongEpoch)
        );

        let deviation_band = OracleAttestationValidationError::DeviationBand {
            attested_price: 100_000_000,
            median_price: 50_000_000,
            max_deviation_bps: 500,
            actual_deviation_bps: 10_000,
        };
        assert_eq!(
            slash_reason_for_validation_error(&deviation_band),
            Some(OracleSlashReason::DeviationBand)
        );

        let non_committee = OracleAttestationValidationError::NonCommitteeSigner([1u8; 32]);
        assert_eq!(slash_reason_for_validation_error(&non_committee), None);

        let invalid_sig = OracleAttestationValidationError::InvalidSignature;
        assert_eq!(slash_reason_for_validation_error(&invalid_sig), None);

        let missing_pk = OracleAttestationValidationError::MissingSignerPublicKey([2u8; 32]);
        assert_eq!(slash_reason_for_validation_error(&missing_pk), None);
    }
}
