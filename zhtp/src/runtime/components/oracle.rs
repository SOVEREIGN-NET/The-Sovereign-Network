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
    /// `mock_sov_usd_price`: testnet override (atomic units, ORACLE_PRICE_SCALE 1e8).
    ///   Pass `None` to use real exchange price feeds.
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
        if let Ok(mesh_router) = crate::runtime::mesh_router_provider::get_global_mesh_router().await {
            if let Some(quic_protocol) = mesh_router.quic_protocol.read().await.as_ref() {
                if let Some(handler) = quic_protocol.message_handler.as_ref() {
                    handler.write().await.set_oracle_attestation_sender(oracle_tx);
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

        info!("🔮 Oracle runtime started (mock_price={:?})", mock_sov_usd_price);
        Ok(())
    }

    // ── Consumer task ───────────────────────────────────────────────────────

    async fn run_consumer(
        mut rx: mpsc::Receiver<Vec<u8>>,
        blockchain: Arc<RwLock<Blockchain>>,
    ) {
        info!("🔮 Oracle attestation consumer started");
        while let Some(payload) = rx.recv().await {
            debug!("🔮 Oracle: received attestation payload ({} bytes) via gossip", payload.len());
            let attestation: OraclePriceAttestation = match bincode::deserialize(&payload) {
                Ok(a) => a,
                Err(e) => {
                    warn!("Oracle: failed to deserialize attestation ({} bytes): {}", payload.len(), e);
                    continue;
                }
            };

            let now = unix_now();
            let mut bc = blockchain.write().await;
            let current_epoch = bc.oracle_state.epoch_id(now);

            // Snapshot validator consensus keys for signature verification.
            let key_map: Vec<([u8; 32], Vec<u8>)> = bc
                .validator_registry
                .values()
                .filter(|v| !v.consensus_key.is_empty())
                .map(|v| {
                    let kid = lib_blockchain::blake3_hash(&v.consensus_key).as_array();
                    (kid, v.consensus_key.clone())
                })
                .collect();

            let result = bc.oracle_state.process_attestation(
                &attestation,
                current_epoch,
                |key_id: [u8; 32]| {
                    key_map
                        .iter()
                        .find(|(kid, _)| *kid == key_id)
                        .map(|(_, pk)| pk.clone())
                },
            );

            match result {
                Ok(admission) => {
                    info!(
                        "🔮 Oracle attestation admitted (epoch={}, price={:.4} USD): {:?}",
                        attestation.epoch_id,
                        attestation.sov_usd_price as f64 / ORACLE_PRICE_SCALE as f64,
                        admission
                    );
                }
                Err(e) => {
                    warn!("🔮 Oracle attestation rejected (epoch={}): {:?}", attestation.epoch_id, e);
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
        let producer = OracleProducerService::new(OracleProducerConfig::default());
        // Wait a bit at startup so that the blockchain and consensus are fully ready.
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        info!("🔮 Oracle attestation producer started");

        loop {
            let epoch_duration_secs: u64 = {
                let bc = blockchain.read().await;
                bc.oracle_state.config.epoch_duration_secs.max(60)
            };

            // Note: Committee membership is set through governance path only.
            // The committee is updated via schedule_committee_update() → apply_pending_updates()
            // at epoch boundaries in the block processing pipeline.
            // This loop reads from oracle_state.committee.members() but does NOT modify it.

            let committee_members: Vec<[u8; 32]> = {
                let bc = blockchain.read().await;
                bc.oracle_state.committee.members().to_vec()
            };

            if committee_members.is_empty() {
                debug!("Oracle producer: committee empty, skipping epoch");
                tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
                continue;
            }

            let now = unix_now();
            let current_epoch = {
                let bc = blockchain.read().await;
                bc.oracle_state.epoch_id(now)
            };

            // Fetch prices (may involve network I/O for real exchange feeds).
            let prices = Self::gather_prices(mock_sov_usd_price, now).await;
            if prices.is_empty() {
                warn!("Oracle producer: no price sources available, skipping epoch {}", current_epoch);
                tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
                continue;
            }

            // Re-check the epoch: if price fetching crossed an epoch boundary the attestation
            // would be built for a stale epoch and rejected by peers.
            let now_after_fetch = unix_now();
            let epoch_after_fetch = {
                let bc = blockchain.read().await;
                bc.oracle_state.epoch_id(now_after_fetch)
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
            match producer.build_attestation(
                current_epoch,
                now,
                &committee_members,
                &keypair,
                prices,
            ) {
                Ok(Some(attestation)) => {
                    info!(
                        "🔮 Oracle produced attestation (epoch={}, price={:.4} USD)",
                        current_epoch,
                        attestation.sov_usd_price as f64 / ORACLE_PRICE_SCALE as f64
                    );

                    // Gossip to peers.
                    Self::gossip_attestation(&attestation).await;

                    // Process locally (our own vote counts).
                    let payload = match bincode::serialize(&attestation) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Oracle: failed to serialize own attestation: {}", e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
                            continue;
                        }
                    };

                    let now2 = unix_now();
                    let mut bc = blockchain.write().await;
                    let epoch2 = bc.oracle_state.epoch_id(now2);
                    let key_map: Vec<([u8; 32], Vec<u8>)> = bc
                        .validator_registry
                        .values()
                        .filter(|v| !v.consensus_key.is_empty())
                        .map(|v| {
                            let kid = lib_blockchain::blake3_hash(&v.consensus_key).as_array();
                            (kid, v.consensus_key.clone())
                        })
                        .collect();

                    match bc.oracle_state.process_attestation(
                        &attestation,
                        epoch2,
                        |key_id: [u8; 32]| {
                            key_map.iter().find(|(kid, _)| *kid == key_id).map(|(_, pk)| pk.clone())
                        },
                    ) {
                        Ok(r) => info!("🔮 Oracle: self-attestation local result: {:?}", r),
                        Err(e) => warn!("🔮 Oracle: self-attestation local rejected: {:?}", e),
                    }
                }
                Ok(None) => {
                    debug!("Oracle producer: abstaining epoch {} (not enough valid sources)", current_epoch);
                }
                Err(e) => {
                    warn!("Oracle producer: build_attestation failed (epoch={}): {:?}", current_epoch, e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(epoch_duration_secs)).await;
        }
    }

    // ── Price fetching ──────────────────────────────────────────────────────

    /// Gather SOV/USD prices from available sources.
    ///
    /// When `mock_price` is set it is used as three identical synthetic sources so
    /// the median aggregation always passes the `min_sources_required = 3` check.
    async fn gather_prices(mock_price: Option<u64>, now: u64) -> Vec<OracleFetchedPrice> {
        if let Some(price) = mock_price {
            // Three synthetic sources (identical values, different source IDs) so the
            // producer's min_sources_required = 3 check passes.
            return vec![
                OracleFetchedPrice { source_id: "mock_a".into(), sov_usd_price: price as u128, timestamp: now },
                OracleFetchedPrice { source_id: "mock_b".into(), sov_usd_price: price as u128, timestamp: now },
                OracleFetchedPrice { source_id: "mock_c".into(), sov_usd_price: price as u128, timestamp: now },
            ];
        }

        // Real exchange feeds (SOV not yet listed — these will return errors; kept as scaffolding).
        let mut prices = Vec::new();

        if let Some(p) = fetch_coingecko_sov_usd(now).await {
            prices.push(p);
        }
        if let Some(p) = fetch_binance_sov_usdt(now).await {
            prices.push(p);
        }

        prices
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

        if let Ok(mesh_router) = crate::runtime::mesh_router_provider::get_global_mesh_router().await {
            if let Some(qp) = mesh_router.quic_protocol.read().await.as_ref() {
                match qp.broadcast_message(&bytes).await {
                    Ok(count) => info!("🔮 Oracle attestation gossiped to {} peer(s)", count),
                    Err(e) => warn!("Oracle gossip broadcast failed: {}", e),
                }
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

/// Build a shared `reqwest::Client` with a 10-second overall timeout.
fn exchange_http_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()
}

/// Fetch SOV/USD from CoinGecko (scaffolding — SOV not yet listed).
async fn fetch_coingecko_sov_usd(now: u64) -> Option<OracleFetchedPrice> {
    // CoinGecko simple price API.  Replace `sov-token` with the actual CoinGecko ID once listed.
    let url = "https://api.coingecko.com/api/v3/simple/price?ids=sov-token&vs_currencies=usd";
    let client = exchange_http_client()?;
    let resp = client.get(url).send().await.ok()?.error_for_status().ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;
    let price_f = json["sov-token"]["usd"].as_f64()?;
    let price_atomic = (price_f * ORACLE_PRICE_SCALE as f64) as u128;
    Some(OracleFetchedPrice {
        source_id: "coingecko".into(),
        sov_usd_price: price_atomic,
        timestamp: now,
    })
}

/// Fetch SOV/USDT from Binance (scaffolding — SOV not yet listed).
async fn fetch_binance_sov_usdt(now: u64) -> Option<OracleFetchedPrice> {
    let url = "https://api.binance.com/api/v3/ticker/price?symbol=SOVUSDT";
    let client = exchange_http_client()?;
    let resp = client.get(url).send().await.ok()?.error_for_status().ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;
    let price_str = json["price"].as_str()?;
    let price_f: f64 = price_str.parse().ok()?;
    let price_atomic = (price_f * ORACLE_PRICE_SCALE as f64) as u128;
    Some(OracleFetchedPrice {
        source_id: "binance".into(),
        sov_usd_price: price_atomic,
        timestamp: now,
    })
}
