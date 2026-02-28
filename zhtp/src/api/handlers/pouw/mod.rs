//! PoUW (Proof-of-Useful-Work) QUIC Handler

use std::sync::Arc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Minimum identity age in seconds before a DID is eligible for PoUW rewards.
/// Default: 86400s = 24 hours. Prevents Sybil attacks from freshly registered DIDs.
pub const MIN_IDENTITY_AGE_SECS: u64 = 86_400;
use async_trait::async_trait;
use hex;

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_identity::IdentityManager;

use crate::pouw::{
    ChallengeGenerator, ReceiptValidator, RewardCalculator,
    PouwMetrics, PouwRateLimiter, types::ReceiptBatch,
};

pub struct PouwHandler {
    challenge_generator: Arc<ChallengeGenerator>,
    receipt_validator: Arc<RwLock<ReceiptValidator>>,
    reward_calculator: Arc<RewardCalculator>,
    metrics: Arc<PouwMetrics>,
    rate_limiter: Arc<PouwRateLimiter>,
    identity_manager: Arc<RwLock<IdentityManager>>,
}

impl PouwHandler {
    const DEFAULT_PAGE_LIMIT: usize = 100;
    const MAX_PAGE_LIMIT: usize = 1000;

    pub fn new(
        challenge_generator: Arc<ChallengeGenerator>,
        receipt_validator: ReceiptValidator,
        reward_calculator: RewardCalculator,
        identity_manager: Arc<RwLock<IdentityManager>>,
    ) -> Self {
        Self {
            challenge_generator,
            receipt_validator: Arc::new(RwLock::new(receipt_validator)),
            reward_calculator: Arc::new(reward_calculator),
            metrics: Arc::new(PouwMetrics::new()),
            rate_limiter: Arc::new(PouwRateLimiter::with_defaults()),
            identity_manager,
        }
    }

    /// Create with a pre-wrapped `Arc<RwLock<ReceiptValidator>>` so it can be shared
    /// with Web4 handlers, QuicHandler, and MeshMessageRouter.
    pub fn new_with_validator_arc(
        challenge_generator: Arc<ChallengeGenerator>,
        receipt_validator: Arc<RwLock<ReceiptValidator>>,
        reward_calculator: RewardCalculator,
        identity_manager: Arc<RwLock<IdentityManager>>,
    ) -> Self {
        Self {
            challenge_generator,
            receipt_validator,
            reward_calculator: Arc::new(reward_calculator),
            metrics: Arc::new(PouwMetrics::new()),
            rate_limiter: Arc::new(PouwRateLimiter::with_defaults()),
            identity_manager,
        }
    }


    pub fn new_with_calculator_arc(
        challenge_generator: Arc<ChallengeGenerator>,
        receipt_validator: Arc<RwLock<ReceiptValidator>>,
        reward_calculator: Arc<RewardCalculator>,
        identity_manager: Arc<RwLock<IdentityManager>>,
    ) -> Self {
        Self {
            challenge_generator,
            receipt_validator,
            reward_calculator,
            metrics: Arc::new(crate::pouw::PouwMetrics::new()),
            rate_limiter: Arc::new(crate::pouw::PouwRateLimiter::with_defaults()),
            identity_manager,
        }
    }

    /// Get the shared RewardCalculator Arc (for the payout background task).
    pub fn reward_calculator_arc(&self) -> Arc<RewardCalculator> {
        Arc::clone(&self.reward_calculator)
    }

    fn parse_query_params(uri: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(query) = uri.split('?').nth(1) {
            for pair in query.split('&') {
                let mut parts = pair.split('=');
                if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                    params.insert(key.to_string(), value.to_string());
                }
            }
        }
        params
    }

    fn extract_path_param(uri: &str, prefix: &str) -> String {
        let raw = uri
            .strip_prefix(prefix)
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("");
        urlencoding::decode(raw)
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(raw))
            .to_string()
    }

    fn parse_pagination(uri: &str) -> (usize, usize) {
        let params = Self::parse_query_params(uri);
        let limit = params
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_PAGE_LIMIT)
            .min(Self::MAX_PAGE_LIMIT);
        let offset = params
            .get("offset")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        (limit, offset)
    }

    /// Extract client IP from request headers
    fn extract_client_ip(request: &ZhtpRequest) -> IpAddr {
        // Try X-Real-IP first (from reverse proxy)
        if let Some(ip_str) = request.headers.get("X-Real-IP") {
            if let Ok(ip) = ip_str.parse() {
                return ip;
            }
        }

        // Try X-Forwarded-For (may contain multiple IPs, take first)
        if let Some(forwarded) = request.headers.get("X-Forwarded-For") {
            if let Some(first_ip) = forwarded.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }

        // Default to localhost if no IP headers are present
        "127.0.0.1".parse().unwrap()
    }

    /// Extract client DID from request
    fn extract_client_did(request: &ZhtpRequest) -> String {
        // Try to get DID from requester identity first
        if let Some(ref identity) = request.requester {
            // Convert IdentityId to string representation
            return format!("did:zhtp:{}", hex::encode(identity.as_bytes()));
        }

        // Fallback to header if present
        if let Some(did) = request.headers.get("X-Client-DID") {
            return did;
        }

        // Default DID for anonymous requests
        "did:zhtp:anonymous".to_string()
    }

    /// Validate client DID against identity registry
    async fn validate_client_identity(&self, client_did: &str) -> Result<(), String> {
        // Check DID format (currently only did:zhtp:... is supported by identity registry)
        if !client_did.starts_with("did:zhtp:") {
            return Err("Invalid DID format: must start with 'did:zhtp:'".to_string());
        }

        // Check if identity exists in registry, ensuring exact DID match.
        let identity_manager = self.identity_manager.read().await;
        match identity_manager.get_identity_by_did(client_did) {
            Some(identity) => {
                if identity.did != client_did {
                    return Err(format!(
                        "Client DID mismatch: requested {}, found {}",
                        client_did, identity.did
                    ));
                }

                // Identity age check: reject DIDs registered less than MIN_IDENTITY_AGE_SECS ago.
                // Prevents Sybil attacks from freshly created identities.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let age_secs = now.saturating_sub(identity.created_at);
                if age_secs < MIN_IDENTITY_AGE_SECS {
                    warn!(
                        did = %client_did,
                        age_secs = age_secs,
                        required_secs = MIN_IDENTITY_AGE_SECS,
                        "PoUW reward rejected: identity too new"
                    );
                    return Err(format!(
                        "Identity too new for reward eligibility: {} seconds old, minimum {} seconds required",
                        age_secs, MIN_IDENTITY_AGE_SECS
                    ));
                }

                debug!("Client identity validated: {}", client_did);
                Ok(())
            }
            None => Err(format!("Client DID not found in identity registry: {}", client_did)),
        }
    }

    fn payout_status_str(status: crate::pouw::rewards::PayoutStatus) -> &'static str {
        match status {
            crate::pouw::rewards::PayoutStatus::Pending => "pending",
            crate::pouw::rewards::PayoutStatus::Processing => "processing",
            crate::pouw::rewards::PayoutStatus::Paid => "paid",
            crate::pouw::rewards::PayoutStatus::Failed => "failed",
        }
    }

    fn checked_reward_sum(
        rewards: &[crate::pouw::rewards::Reward],
        field: &str,
        scope: &str,
    ) -> u64 {
        rewards
            .iter()
            .try_fold(0u64, |acc, r| acc.checked_add(r.final_amount))
            .unwrap_or_else(|| {
                warn!("Overflow calculating {} for {}", field, scope);
                u64::MAX
            })
    }

    async fn check_reward_query_access(
        &self,
        request: &ZhtpRequest,
        target_did: &str,
        op_name: &str,
    ) -> Result<(), ZhtpResponse> {
        let client_ip = Self::extract_client_ip(request);
        let requester_did = Self::extract_client_did(request);
        let rate_check = self.rate_limiter.check_request(client_ip, &requester_did).await;
        if let crate::pouw::rate_limiter::RateLimitResult::Denied { reason, retry_after } = rate_check {
            let mut response = ZhtpResponse::error_json(
                ZhtpStatus::TooManyRequests,
                &serde_json::json!({
                    "error": "Rate limit exceeded",
                    "reason": reason.to_string(),
                    "retry_after_seconds": retry_after.as_secs(),
                }),
            )
            .map_err(|_| ZhtpResponse::error(
                ZhtpStatus::InternalServerError,
                "Failed to create error response".to_string(),
            ))?;
            response.headers = response
                .headers
                .with_custom_header("Retry-After".to_string(), retry_after.as_secs().to_string());
            return Err(response);
        }

        if requester_did == "did:zhtp:anonymous" {
            return Err(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                format!("{} requires authenticated requester DID", op_name),
            ));
        }
        if requester_did != target_did {
            return Err(ZhtpResponse::error(
                ZhtpStatus::Forbidden,
                format!("Requester DID {} cannot access {}", requester_did, target_did),
            ));
        }

        if let Err(e) = self.validate_client_identity(target_did).await {
            return Err(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                format!("Invalid client identity: {}", e),
            ));
        }

        Ok(())
    }

    async fn handle_get_challenge(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW challenge request");

        // Extract client information for rate limiting
        let client_ip = Self::extract_client_ip(request);
        let client_did = Self::extract_client_did(request);

        // Check rate limits
        let rate_check = self.rate_limiter.check_request(client_ip, &client_did).await;
        if let crate::pouw::rate_limiter::RateLimitResult::Denied { reason, retry_after } = rate_check {
            warn!(
                ip = %client_ip,
                did = %client_did,
                reason = %reason,
                "Rate limit exceeded for challenge request"
            );
            
            let error_body = serde_json::json!({
                "error": "Rate limit exceeded",
                "reason": reason.to_string(),
                "retry_after_seconds": retry_after.as_secs(),
            });

            let mut response = ZhtpResponse::error_json(ZhtpStatus::TooManyRequests, &error_body)
                .map_err(|e| anyhow::anyhow!("Failed to create error response: {}", e))?;
            
            // Add Retry-After header
            response.headers = response.headers.with_custom_header("Retry-After".to_string(), retry_after.as_secs().to_string());
            
            return Ok(response);
        }

        // Parse query parameters from the request URI to configure the challenge.
        let params = Self::parse_query_params(&request.uri);

        // Capability: default to "hash" if not provided.
        // URL-decode the value so %2C-separated lists (e.g. Android clients) are handled correctly.
        let cap_decoded: String;
        let capability = match params.get("cap") {
            Some(raw) => {
                cap_decoded = urlencoding::decode(raw)
                    .unwrap_or_else(|_| std::borrow::Cow::Borrowed(raw.as_str()))
                    .into_owned();
                Some(cap_decoded.as_str())
            }
            None => Some("hash"),
        };

        // Optional numeric limits from query parameters; invalid values are ignored.
        let max_bytes = params
            .get("max_bytes")
            .and_then(|v| v.parse::<u64>().ok());

        let max_receipts = params
            .get("max_receipts")
            .and_then(|v| v.parse::<u32>().ok());

        let challenge = self
            .challenge_generator
            .generate_challenge(capability, max_bytes, max_receipts, None)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        self.metrics.record_challenge_issued();

        let body = serde_json::json!({
            "token": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &challenge.token),
            "expires_at": challenge.expires_at,
        });

        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    async fn handle_submit_receipt(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW receipt submission");

        // Extract client information for rate limiting
        let client_ip = Self::extract_client_ip(request);
        let client_did = Self::extract_client_did(request);

        // Check rate limits
        let rate_check = self.rate_limiter.check_request(client_ip, &client_did).await;
        if let crate::pouw::rate_limiter::RateLimitResult::Denied { reason, retry_after } = rate_check {
            warn!(
                ip = %client_ip,
                did = %client_did,
                reason = %reason,
                "Rate limit exceeded for receipt submission"
            );
            
            let error_body = serde_json::json!({
                "error": "Rate limit exceeded",
                "reason": reason.to_string(),
                "retry_after_seconds": retry_after.as_secs(),
            });

            let mut response = ZhtpResponse::error_json(ZhtpStatus::TooManyRequests, &error_body)
                .map_err(|e| anyhow::anyhow!("Failed to create error response: {}", e))?;
            
            // Add Retry-After header
            response.headers = response.headers.with_custom_header("Retry-After".to_string(), retry_after.as_secs().to_string());
            
            return Ok(response);
        }

        let batch: ReceiptBatch = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Validate client DID against identity registry
        if let Err(e) = self.validate_client_identity(&batch.client_did).await {
            warn!(
                ip = %client_ip,
                did = %client_did,
                error = %e,
                "Client identity validation failed"
            );
            
            let error_body = serde_json::json!({
                "error": "Invalid client identity",
                "reason": e.to_string(),
            });

            return Ok(ZhtpResponse::error_json(ZhtpStatus::Unauthorized, &error_body)
                .map_err(|e| anyhow::anyhow!("Failed to create error response: {}", e))?);
        }

        // Check batch size limit
        let batch_size = batch.receipts.len();
        let batch_check = self.rate_limiter.check_batch_size(batch_size);
        if let crate::pouw::rate_limiter::RateLimitResult::Denied { reason, .. } = batch_check {
            warn!(
                ip = %client_ip,
                did = %client_did,
                batch_size = batch_size,
                reason = %reason,
                "Batch size limit exceeded for receipt submission"
            );
            
            let error_body = serde_json::json!({
                "error": "Batch size limit exceeded",
                "reason": reason.to_string(),
                "batch_size": batch_size,
                "max_batch_size": 100, // From default config
            });

            return Ok(ZhtpResponse::error_json(ZhtpStatus::BadRequest, &error_body)
                .map_err(|e| anyhow::anyhow!("Failed to create error response: {}", e))?);
        }

        let validator = self.receipt_validator.read().await;
        let result = validator.validate_batch(&batch)
            .await
            .map_err(|e| anyhow::anyhow!("Validation failed: {}", e))?;

        // Calculate rewards for newly accepted receipts only.
        let mut rewards = vec![];
        let mut reward_calc = serde_json::json!({ "status": "skipped", "reason": "no_accepted_receipts" });
        if !result.accepted.is_empty() {
            let validated = validator
                .get_validated_receipts_for_nonces(&result.accepted)
                .await;
            if !validated.is_empty() {
                let calculator = &*self.reward_calculator;
                let current_epoch = calculator.current_epoch();
                match calculator.calculate_epoch_rewards(&validated, current_epoch).await {
                    Ok(epoch_rewards) => {
                        for r in epoch_rewards {
                            rewards.push(serde_json::json!({
                                "reward_id": hex::encode(&r.reward_id),
                                "client_did": r.client_did,
                                "amount": r.final_amount,
                                "epoch": r.epoch,
                            }));
                        }
                        reward_calc = serde_json::json!({
                            "status": "ok",
                            "epoch": current_epoch,
                            "calculated_rewards": rewards.len(),
                        });
                    }
                    Err(e) => {
                        warn!("Failed to calculate rewards: {}", e);
                        reward_calc = serde_json::json!({
                            "status": "failed",
                            "error": e.to_string(),
                        });
                    }
                }
            } else {
                reward_calc = serde_json::json!({
                    "status": "skipped",
                    "reason": "no_validated_receipts_for_batch",
                });
            }
        }

        let body = serde_json::json!({
            "accepted": result.accepted.len(),
            "rejected": result.rejected.len(),
            "rewards": rewards,
            "reward_calculation": reward_calc,
        });

        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    async fn handle_health_check(&self) -> ZhtpResult<ZhtpResponse> {
        let calculator = &*self.reward_calculator;
        let suspicious_dids = calculator.get_suspicious_dids().await;
        let body = serde_json::json!({
            "status": "ok",
            "suspicious_dids": suspicious_dids,
            "suspicious_did_count": suspicious_dids.len(),
        });
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle GET /pouw/rewards/{client_did} - Get rewards for a specific client
    async fn handle_get_client_rewards(
        &self,
        request: &ZhtpRequest,
        client_did: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        debug!("Getting rewards for client: {}", client_did);

        if let Err(response) = self
            .check_reward_query_access(request, client_did, "reward lookup")
            .await
        {
            return Ok(response);
        }

        let (limit, offset) = Self::parse_pagination(&request.uri);
        let calculator = &*self.reward_calculator;
        let rewards = calculator.get_client_rewards(client_did).await;

        let total_earned: u64 = Self::checked_reward_sum(
            &rewards,
            "total_earned",
            &format!("client {}", client_did),
        );
        let paid_rewards: Vec<_> = rewards
            .iter()
            .filter(|r| r.payout_status == crate::pouw::rewards::PayoutStatus::Paid)
            .cloned()
            .collect();
        let total_paid: u64 = Self::checked_reward_sum(
            &paid_rewards,
            "total_paid",
            &format!("client {}", client_did),
        );

        let total_rewards = rewards.len();
        let page_rewards: Vec<_> = rewards.into_iter().skip(offset).take(limit).collect();

        let reward_list: Vec<serde_json::Value> = page_rewards.iter().map(|r| {
            serde_json::json!({
                "reward_id": hex::encode(&r.reward_id),
                "epoch": r.epoch,
                "total_bytes": r.total_bytes,
                "raw_amount": r.raw_amount,
                "final_amount": r.final_amount,
                "payout_status": Self::payout_status_str(r.payout_status),
                "paid_at": r.paid_at,
                "tx_hash": r.tx_hash.as_ref().map(|h| hex::encode(h)),
            })
        }).collect();

        let body = serde_json::json!({
            "client_did": client_did,
            "total_rewards": total_rewards,
            "total_earned": total_earned,
            "total_paid": total_paid,
            "pending": total_earned.saturating_sub(total_paid),
            "limit": limit,
            "offset": offset,
            "rewards": reward_list,
        });

        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle GET /pouw/epochs/{epoch} - Get rewards for a specific epoch
    async fn handle_get_epoch_rewards(
        &self,
        request: &ZhtpRequest,
        epoch: u64,
    ) -> ZhtpResult<ZhtpResponse> {
        debug!("Getting rewards for epoch: {}", epoch);

        let client_ip = Self::extract_client_ip(request);
        let requester_did = Self::extract_client_did(request);
        let rate_check = self.rate_limiter.check_request(client_ip, &requester_did).await;
        if let crate::pouw::rate_limiter::RateLimitResult::Denied { reason, retry_after } = rate_check {
            let mut response = ZhtpResponse::error_json(
                ZhtpStatus::TooManyRequests,
                &serde_json::json!({
                    "error": "Rate limit exceeded",
                    "reason": reason.to_string(),
                    "retry_after_seconds": retry_after.as_secs(),
                }),
            )
            .map_err(|e| anyhow::anyhow!("Failed to create error response: {}", e))?;
            response.headers = response
                .headers
                .with_custom_header("Retry-After".to_string(), retry_after.as_secs().to_string());
            return Ok(response);
        }

        let (limit, offset) = Self::parse_pagination(&request.uri);
        let calculator = &*self.reward_calculator;
        let rewards = calculator.get_epoch_rewards(epoch).await;

        let total_earned: u64 = Self::checked_reward_sum(
            &rewards,
            "total_earned",
            &format!("epoch {}", epoch),
        );
        let paid_rewards: Vec<_> = rewards
            .iter()
            .filter(|r| r.payout_status == crate::pouw::rewards::PayoutStatus::Paid)
            .cloned()
            .collect();
        let total_paid: u64 = Self::checked_reward_sum(
            &paid_rewards,
            "total_paid",
            &format!("epoch {}", epoch),
        );
        let total_rewards = rewards.len();
        let page_rewards: Vec<_> = rewards.into_iter().skip(offset).take(limit).collect();

        let reward_list: Vec<serde_json::Value> = page_rewards.iter().map(|r| {
            serde_json::json!({
                "reward_id": hex::encode(&r.reward_id),
                "client_did": r.client_did,
                "epoch": r.epoch,
                "total_bytes": r.total_bytes,
                "raw_amount": r.raw_amount,
                "final_amount": r.final_amount,
                "payout_status": Self::payout_status_str(r.payout_status),
                "paid_at": r.paid_at,
                "tx_hash": r.tx_hash.as_ref().map(|h| hex::encode(h)),
            })
        }).collect();

        let body = serde_json::json!({
            "epoch": epoch,
            "total_rewards": total_rewards,
            "total_earned": total_earned,
            "total_paid": total_paid,
            "pending": total_earned.saturating_sub(total_paid),
            "limit": limit,
            "offset": offset,
            "rewards": reward_list,
        });

        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle GET /pouw/stats — global POUW statistics
    async fn handle_get_stats(&self) -> ZhtpResult<ZhtpResponse> {
        let rewards = self.reward_calculator.get_all_rewards().await;
        let total_rewards = rewards.len() as u64;
        let total_earned: u64 = rewards.iter()
            .map(|r| r.final_amount)
            .fold(0u64, |acc, x| acc.saturating_add(x));
        let total_paid: u64 = rewards.iter()
            .filter(|r| r.payout_status == crate::pouw::rewards::PayoutStatus::Paid)
            .map(|r| r.final_amount)
            .fold(0u64, |acc, x| acc.saturating_add(x));
        let pending_count = rewards.iter()
            .filter(|r| r.payout_status == crate::pouw::rewards::PayoutStatus::Pending)
            .count() as u64;
        let current_epoch = self.reward_calculator.current_epoch();
        let body = serde_json::json!({
            "current_epoch": current_epoch,
            "total_rewards": total_rewards,
            "total_earned_atomic": total_earned,
            "total_paid_atomic": total_paid,
            "pending_rewards": pending_count,
            "epoch_duration_secs": crate::pouw::rewards::DEFAULT_EPOCH_DURATION_SECS,
            "per_node_cap_atomic": crate::pouw::rewards::POUW_PER_NODE_EPOCH_CAP,
            "epoch_pool_atomic": crate::pouw::rewards::POUW_EPOCH_POOL,
        });
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle GET /pouw/epochs — paginated list of epochs with rewards
    async fn handle_list_epochs(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let (limit, offset) = Self::parse_pagination(&request.uri);
        let epochs = self.reward_calculator.list_epochs_with_rewards().await;
        let total = epochs.len();
        let page: Vec<serde_json::Value> = epochs
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|epoch| {
                serde_json::json!({
                    "epoch": epoch,
                    "start_timestamp": self.reward_calculator.epoch_start(epoch),
                    "end_timestamp": self.reward_calculator.epoch_end(epoch),
                })
            })
            .collect();
        let body = serde_json::json!({
            "total": total,
            "limit": limit,
            "offset": offset,
            "epochs": page,
        });
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle GET /pouw/receipts/{did} — validated receipts for a DID
    async fn handle_get_receipts_for_did(
        &self,
        request: &ZhtpRequest,
        client_did: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        if let Err(response) = self
            .check_reward_query_access(request, client_did, "receipt lookup")
            .await
        {
            return Ok(response);
        }
        let (limit, offset) = Self::parse_pagination(&request.uri);
        let validator = self.receipt_validator.read().await;
        let receipts = validator.get_receipts_for_did(client_did).await;
        let total = receipts.len();
        let page: Vec<serde_json::Value> = receipts
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|r| serde_json::json!({
                "receipt_nonce": hex::encode(&r.receipt_nonce),
                "proof_type": format!("{:?}", r.proof_type),
                "bytes_verified": r.bytes_verified,
                "validated_at": r.validated_at,
                "domain": r.domain,
            }))
            .collect();
        let body = serde_json::json!({
            "client_did": client_did,
            "total": total,
            "limit": limit,
            "offset": offset,
            "receipts": page,
        });
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle GET /pouw/rewards/{did}/transactions — paid reward transactions for a DID
    async fn handle_get_reward_transactions(
        &self,
        request: &ZhtpRequest,
        client_did: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        if let Err(response) = self
            .check_reward_query_access(request, client_did, "transaction history lookup")
            .await
        {
            return Ok(response);
        }
        let (limit, offset) = Self::parse_pagination(&request.uri);
        let txns = self.reward_calculator.get_reward_transactions_for_did(client_did).await;
        let total = txns.len();
        let page: Vec<serde_json::Value> = txns
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|t| serde_json::json!({
                "reward_id": hex::encode(&t.reward_id),
                "epoch": t.epoch,
                "amount": t.amount,
                "paid_at": t.paid_at,
                "tx_hash": t.tx_hash.as_ref().map(|h| hex::encode(h)),
            }))
            .collect();
        let body = serde_json::json!({
            "client_did": client_did,
            "total": total,
            "limit": limit,
            "offset": offset,
            "transactions": page,
        });
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle GET /pouw/disputes/{did} — rejection/dispute log for a DID
    async fn handle_get_disputes_for_did(
        &self,
        request: &ZhtpRequest,
        client_did: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        if let Err(response) = self
            .check_reward_query_access(request, client_did, "dispute lookup")
            .await
        {
            return Ok(response);
        }
        let (limit, offset) = Self::parse_pagination(&request.uri);
        let validator = self.receipt_validator.read().await;
        let disputes = validator.get_disputes_for_did(client_did).await;
        let total = disputes.len();
        let page: Vec<serde_json::Value> = disputes
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|d| serde_json::json!({
                "timestamp": d.timestamp,
                "reason": d.reason.as_str(),
                "receipt_nonce": d.receipt_nonce.as_ref().map(|n| hex::encode(n)),
            }))
            .collect();
        let body = serde_json::json!({
            "client_did": client_did,
            "total": total,
            "limit": limit,
            "offset": offset,
            "disputes": page,
        });
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }
}

#[async_trait]
impl ZhtpRequestHandler for PouwHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let full_uri = request.uri.as_str();
        // Strip /api/v1 prefix so internal routing works with /pouw/... paths
        let uri_with_query = full_uri.strip_prefix("/api/v1").unwrap_or(full_uri);
        // Strip query string for routing — handlers read params via parse_query_params(&request.uri)
        let uri = uri_with_query.split('?').next().unwrap_or(uri_with_query);
        
        // Handle routes with path parameters
        // GET /pouw/rewards/{did}/transactions — must be checked BEFORE /pouw/rewards/{did}
        if uri.starts_with("/pouw/rewards/") && uri.ends_with("/transactions") && request.method.as_str() == "GET" {
            let did = uri
                .strip_prefix("/pouw/rewards/")
                .and_then(|s| s.strip_suffix("/transactions"))
                .unwrap_or("");
            let did = urlencoding::decode(did)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(did))
                .to_string();
            if did.is_empty() {
                return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, "Missing DID".to_string()));
            }
            return self.handle_get_reward_transactions(&request, &did).await;
        }

        if uri.starts_with("/pouw/rewards/") && request.method.as_str() == "GET" {
            // GET /pouw/rewards/{client_did}
            let client_did = Self::extract_path_param(uri, "/pouw/rewards/");
            if client_did.is_empty() {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Missing client DID parameter".to_string(),
                ));
            }
            return self.handle_get_client_rewards(&request, &client_did).await;
        }
        
        if uri.starts_with("/pouw/rewards/") {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::MethodNotAllowed,
                "Method not allowed for rewards endpoint".to_string(),
            ));
        }

        if uri.starts_with("/pouw/epochs/") && request.method.as_str() == "GET" {
            // GET /pouw/epochs/{epoch}
            let epoch_str = Self::extract_path_param(uri, "/pouw/epochs/");
            if epoch_str.is_empty() {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Missing epoch parameter: must be a valid number".to_string(),
                ));
            }
            match epoch_str.parse::<u64>() {
                Ok(epoch) => return self.handle_get_epoch_rewards(&request, epoch).await,
                Err(_) => {
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::BadRequest,
                        "Invalid epoch parameter: must be a valid number".to_string(),
                    ));
                }
            }
        }

        if uri.starts_with("/pouw/epochs/") {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::MethodNotAllowed,
                "Method not allowed for epochs endpoint".to_string(),
            ));
        }
        
        // GET /pouw/receipts/{did}
        if uri.starts_with("/pouw/receipts/") && request.method.as_str() == "GET" {
            let did = Self::extract_path_param(uri, "/pouw/receipts/");
            if did.is_empty() {
                return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, "Missing DID".to_string()));
            }
            return self.handle_get_receipts_for_did(&request, &did).await;
        }

        // GET /pouw/disputes/{did}
        if uri.starts_with("/pouw/disputes/") && request.method.as_str() == "GET" {
            let did = Self::extract_path_param(uri, "/pouw/disputes/");
            if did.is_empty() {
                return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, "Missing DID".to_string()));
            }
            return self.handle_get_disputes_for_did(&request, &did).await;
        }

        match (request.method.as_str(), uri) {
            ("GET", "/pouw/challenge") => self.handle_get_challenge(&request).await,
            ("POST", "/pouw/submit") => self.handle_submit_receipt(&request).await,
            ("GET", "/pouw/health") => self.handle_health_check().await,
            ("GET", "/pouw/stats") => self.handle_get_stats().await,
            ("GET", "/pouw/epochs") => self.handle_list_epochs(&request).await,
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Not found: {} {}", request.method, uri),
            ))
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/pouw") || request.uri.starts_with("/pouw")
    }

    fn priority(&self) -> u32 { 100 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pouw::types::ProofType;
    use crate::pouw::validation::ValidatedReceipt;
    use lib_identity::IdentityType;

    async fn register_known_identity(
        identity_manager: &Arc<RwLock<lib_identity::IdentityManager>>,
        did: &str,
    ) {
        let keypair = lib_crypto::generate_keypair().expect("keypair");
        let identity_id = lib_identity::did::parse_did_to_identity_id(did).expect("did parse");
        identity_manager
            .write()
            .await
            .register_external_identity(
                identity_id,
                did.to_string(),
                keypair.public_key,
                IdentityType::Human,
                "test-device".to_string(),
                Some("test-user".to_string()),
                1_700_000_000,
            )
            .expect("register external identity");
    }

    fn build_test_handler() -> PouwHandler {
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);
        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        let validator = ReceiptValidator::new(generator.clone(), Arc::new(tokio::sync::RwLock::new(lib_identity::IdentityManager::new())));
        let reward_calculator = RewardCalculator::new(1_700_000_000);
        let identity_manager = Arc::new(RwLock::new(lib_identity::IdentityManager::new()));
        PouwHandler::new(generator, validator, reward_calculator, identity_manager)
    }

    #[test]
    fn can_handle_pouw_routes() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/pouw/health".to_string(), None).unwrap();
        assert!(handler.can_handle(&req));
    }

    #[test]
    fn rejects_non_pouw_routes() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/status".to_string(), None).unwrap();
        assert!(!handler.can_handle(&req));
    }

    #[tokio::test]
    async fn health_route_returns_ok() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/pouw/health".to_string(), None).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok);
    }

    #[tokio::test]
    async fn unknown_route_returns_not_found() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/pouw/unknown".to_string(), None).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::NotFound);
    }

    #[tokio::test]
    async fn test_client_identity_validation() {
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);
        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        let validator = ReceiptValidator::new(generator.clone(), Arc::new(tokio::sync::RwLock::new(lib_identity::IdentityManager::new())));
        let reward_calculator = RewardCalculator::new(1_700_000_000);
        let identity_manager = Arc::new(RwLock::new(lib_identity::IdentityManager::new()));
        register_known_identity(
            &identity_manager,
            "did:zhtp:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await;

        let handler = PouwHandler::new(generator, validator, reward_calculator, identity_manager);
        
        // Test invalid DID format - should fail format check
        let result = handler.validate_client_identity("invalid-did").await;
        assert!(result.is_err(), "Invalid DID format should be rejected");
        assert!(result.unwrap_err().contains("Invalid DID format"), "Error should mention format");
        
        // Test valid format but non-existent DID - should fail registry check.
        let result = handler
            .validate_client_identity("did:zhtp:2222222222222222222222222222222222222222222222222222222222222222")
            .await;
        assert!(result.is_err(), "Non-existent identity should be rejected");
        assert!(result.unwrap_err().contains("not found"), "Error should mention not found");
        
        // Test known DID success path.
        let result = handler
            .validate_client_identity("did:zhtp:1111111111111111111111111111111111111111111111111111111111111111")
            .await;
        assert!(result.is_ok(), "Known identity in registry should be accepted");
    }

    #[tokio::test]
    async fn rewards_endpoint_returns_client_data() {
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);
        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        let validator = ReceiptValidator::new(generator.clone(), Arc::new(tokio::sync::RwLock::new(lib_identity::IdentityManager::new())));
        let reward_calculator = RewardCalculator::new(1_700_000_000);
        let identity_manager = Arc::new(RwLock::new(lib_identity::IdentityManager::new()));
        let client_did = "did:zhtp:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        register_known_identity(&identity_manager, client_did).await;
        let handler = PouwHandler::new(generator, validator, reward_calculator, identity_manager);

        {
            let calc = &*handler.reward_calculator;
            let validated = vec![ValidatedReceipt {
                receipt_nonce: vec![1u8; 16],
                client_did: client_did.to_string(),
                task_id: vec![2u8; 16],
                proof_type: ProofType::Hash,
                bytes_verified: 4096,
                validated_at: 1_700_003_601,
                challenge_nonce: vec![3u8; 16],
                manifest_cid: None,
                domain: None,
                route_hops: None,
                served_from_cache: None,
            }];
            let _ = calc.calculate_epoch_rewards(&validated, 1).await.unwrap();
        }

        let mut req = ZhtpRequest::get(
            format!("/pouw/rewards/{}?limit=10&offset=0", urlencoding::encode(client_did)),
            None,
        )
        .unwrap();
        req.headers = req
            .headers
            .with_custom_header("x-client-did".to_string(), client_did.to_string());
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok);

        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["client_did"], client_did);
        assert!(body["total_rewards"].as_u64().unwrap() >= 1);
        assert!(body["total_earned"].as_u64().unwrap() >= body["total_paid"].as_u64().unwrap());
        assert_eq!(
            body["pending"].as_u64().unwrap(),
            body["total_earned"].as_u64().unwrap() - body["total_paid"].as_u64().unwrap()
        );
        assert!(body["rewards"].is_array());
    }

    #[tokio::test]
    async fn epoch_endpoint_returns_epoch_data() {
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);
        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        let validator = ReceiptValidator::new(generator.clone(), Arc::new(tokio::sync::RwLock::new(lib_identity::IdentityManager::new())));
        let reward_calculator = RewardCalculator::new(1_700_000_000);
        let identity_manager = Arc::new(RwLock::new(lib_identity::IdentityManager::new()));
        let client_did = "did:zhtp:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        register_known_identity(&identity_manager, client_did).await;
        let handler = PouwHandler::new(generator, validator, reward_calculator, identity_manager);

        {
            let calc = &*handler.reward_calculator;
            let validated = vec![ValidatedReceipt {
                receipt_nonce: vec![5u8; 16],
                client_did: client_did.to_string(),
                task_id: vec![6u8; 16],
                proof_type: ProofType::Merkle,
                bytes_verified: 8192,
                validated_at: 1_700_025_201,
                challenge_nonce: vec![7u8; 16],
                manifest_cid: None,
                domain: None,
                route_hops: None,
                served_from_cache: None,
            }];
            let _ = calc.calculate_epoch_rewards(&validated, 7).await.unwrap();
        }

        let mut req = ZhtpRequest::get("/pouw/epochs/7?limit=10&offset=0".to_string(), None).unwrap();
        req.headers = req
            .headers
            .with_custom_header("x-client-did".to_string(), client_did.to_string());
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok);

        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["epoch"], 7);
        assert!(body["total_rewards"].as_u64().unwrap() >= 1);
        assert!(body["total_earned"].as_u64().unwrap() >= body["total_paid"].as_u64().unwrap());
        assert_eq!(
            body["pending"].as_u64().unwrap(),
            body["total_earned"].as_u64().unwrap() - body["total_paid"].as_u64().unwrap()
        );
        assert!(body["rewards"].is_array());
    }

    #[tokio::test]
    async fn epoch_endpoint_rejects_invalid_epoch_param() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/pouw/epochs/not-a-number".to_string(), None).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }
}
