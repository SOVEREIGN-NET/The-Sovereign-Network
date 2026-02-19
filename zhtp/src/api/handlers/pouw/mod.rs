//! PoUW (Proof-of-Useful-Work) QUIC Handler

use std::sync::Arc;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;
use tracing::{debug, warn};
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
    reward_calculator: Arc<RwLock<RewardCalculator>>,
    metrics: Arc<PouwMetrics>,
    rate_limiter: Arc<PouwRateLimiter>,
    identity_manager: Arc<RwLock<IdentityManager>>,
}

impl PouwHandler {
    pub fn new(
        challenge_generator: Arc<ChallengeGenerator>,
        receipt_validator: ReceiptValidator,
        reward_calculator: RewardCalculator,
        identity_manager: Arc<RwLock<IdentityManager>>,
    ) -> Self {
        Self {
            challenge_generator,
            receipt_validator: Arc::new(RwLock::new(receipt_validator)),
            reward_calculator: Arc::new(RwLock::new(reward_calculator)),
            metrics: Arc::new(PouwMetrics::new()),
            rate_limiter: Arc::new(PouwRateLimiter::with_defaults()),
            identity_manager,
        }
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
        // Check DID format (did:sov:... or did:zhtp:...)
        if !client_did.starts_with("did:sov:") && !client_did.starts_with("did:zhtp:") {
            return Err(format!("Invalid DID format: must start with 'did:sov:' or 'did:zhtp:'"));
        }

        // Check if identity exists in registry
        let identity_manager = self.identity_manager.read().await;
        match identity_manager.get_identity_by_did(client_did) {
            Some(_identity) => {
                debug!("Client identity validated: {}", client_did);
                Ok(())
            }
            None => {
                Err(format!("Client DID not found in identity registry: {}", client_did))
            }
        }
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
        let capability = params
            .get("cap")
            .map(|s| s.as_str())
            .or(Some("hash"));

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
                let calculator = self.reward_calculator.read().await;
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
        let body = serde_json::json!({"status": "ok"});
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }
}

#[async_trait]
impl ZhtpRequestHandler for PouwHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        match (request.method.as_str(), request.uri.as_str()) {
            ("GET", "/pouw/challenge") => self.handle_get_challenge(&request).await,
            ("POST", "/pouw/submit") => self.handle_submit_receipt(&request).await,
            ("GET", "/pouw/health") => self.handle_health_check().await,
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Not found: {} {}", request.method, request.uri),
            ))
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/pouw")
    }

    fn priority(&self) -> u32 { 100 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_handler() -> PouwHandler {
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);
        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        let validator = ReceiptValidator::new(generator.clone());
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
        let validator = ReceiptValidator::new(generator.clone());
        let reward_calculator = RewardCalculator::new(1_700_000_000);
        
        // Create identity manager without pre-loaded identities (empty registry)
        let identity_manager = Arc::new(RwLock::new(lib_identity::IdentityManager::new()));
        
        let handler = PouwHandler::new(generator, validator, reward_calculator, identity_manager);
        
        // Test invalid DID format - should fail format check
        let result = handler.validate_client_identity("invalid-did").await;
        assert!(result.is_err(), "Invalid DID format should be rejected");
        assert!(result.unwrap_err().contains("Invalid DID format"), "Error should mention format");
        
        // Test valid format but non-existent DID - should fail registry check
        let result = handler.validate_client_identity("did:sov:nonexistent").await;
        assert!(result.is_err(), "Non-existent identity should be rejected");
        assert!(result.unwrap_err().contains("not found"), "Error should mention not found");
        
        // Test did:zhtp: format - should also work
        let result = handler.validate_client_identity("did:zhtp:test").await;
        assert!(result.is_err(), "did:zhtp: format should pass format check but fail registry");
    }
}
