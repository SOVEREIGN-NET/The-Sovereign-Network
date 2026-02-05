#[cfg(test)]
mod api_integration_tests {
    
    use crate::runtime::{RuntimeOrchestrator, Component, ApiComponent};
    use crate::config::NodeConfig;
    use crate::api::handlers::identity::IdentityHandler;
    use crate::api::middleware::{RateLimiter, CsrfProtection};
    use crate::session_manager::SessionManager;
    use crate::api::handlers::identity::login_handlers::AccountLockout;
    use lib_identity::{IdentityManager, RecoveryPhraseManager, economics::EconomicModel as IdentityEconomicModel};
    use lib_protocols::types::{ZhtpHeaders, ZhtpMethod, ZhtpRequest, ZHTP_VERSION, ZhtpStatus};
    use lib_protocols::zhtp::ZhtpRequestHandler;
    use lib_storage::{UnifiedStorageConfig, UnifiedStorageSystem};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use base64::Engine as _;
    
    
    
    fn create_test_config() -> NodeConfig {
        let mut config = NodeConfig::default();
        // Customize for testing
        config.node_id = [1u8; 32];
        config.data_directory = "test_data".to_string();
        config.network_config.mesh_port = 8081;
        config.storage_config.dht_port = 8080;
        config.protocols_config.api_port = 8082;
        config.network_config.bootstrap_peers = vec![]; // No bootstrap peers for tests
        config
    }
    
    #[tokio::test]
    async fn test_api_component_integration() {
        // Initialize runtime with test config
        let config = create_test_config();
        let runtime_result = RuntimeOrchestrator::new(config).await;
        assert!(runtime_result.is_ok(), "Runtime should initialize successfully");
        
        let runtime = runtime_result.unwrap();
        
        // Register all components including API
        let register_result = runtime.register_all_components().await;
        assert!(register_result.is_ok(), "Runtime should register components successfully");
        
        // Test basic runtime functionality without starting components
        // (starting components requires actual network resources and can timeout in CI)
        let status_result = runtime.get_component_status().await;
        assert!(status_result.is_ok(), "Should be able to get component status");
        
        // Test getting detailed health (components will be uninitialized but method should work)
        let health_result = runtime.get_detailed_health().await;
        assert!(health_result.is_ok(), "Should be able to get detailed health status");
        
        // This proves the API component is properly integrated into the runtime system
        println!("API component successfully integrated into runtime orchestrator");
    }
    
    #[tokio::test]
    async fn test_api_component_lifecycle() {
        // Test individual API component lifecycle
        let api_component = ApiComponent::new();
        
        // Test start
        let start_result = api_component.start().await;
        assert!(start_result.is_ok(), "API component should start successfully");
        
        // Test health check
        let health_result = api_component.health_check().await;
        assert!(health_result.is_ok(), "API component should be healthy after start");
        
        // Test stop
        let stop_result = api_component.stop().await;
        assert!(stop_result.is_ok(), "API component should stop successfully");
    }

    #[tokio::test]
    async fn test_register_identity_derives_did_and_node_id() {
        let mut storage_config = UnifiedStorageConfig::default();
        let db_path = std::env::temp_dir().join(format!("zhtp-test-dht-{}", rand::random::<u64>()));
        storage_config.storage_config.dht_persist_path = Some(db_path.clone());

        let storage = UnifiedStorageSystem::new_persistent(storage_config, db_path.clone())
            .await
            .expect("failed to create storage");

        let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
        let economic_model = Arc::new(RwLock::new(IdentityEconomicModel::new()));
        let session_manager = Arc::new(SessionManager::new());
        let rate_limiter = Arc::new(RateLimiter::new());
        let account_lockout = Arc::new(AccountLockout::new());
        let csrf_protection = Arc::new(CsrfProtection::new());
        let recovery_phrase_manager = Arc::new(RwLock::new(RecoveryPhraseManager::new()));
        let storage_system = Arc::new(RwLock::new(storage));

        let handler = IdentityHandler::new(
            identity_manager,
            economic_model,
            session_manager,
            rate_limiter,
            account_lockout,
            csrf_protection,
            recovery_phrase_manager,
            storage_system,
        );

        let device_id = "device-test-123";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let keypair = lib_crypto::KeyPair::generate().expect("keypair generation failed");
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&keypair.public_key.dilithium_pk);

        let signed_message = format!("ZHTP_REGISTER:{}", timestamp);
        let signature = lib_crypto::sign_message(&keypair, signed_message.as_bytes())
            .expect("sign failed");
        let registration_proof_b64 = base64::engine::general_purpose::STANDARD.encode(&signature.signature);

        let body = serde_json::to_vec(&serde_json::json!({
            "public_key": public_key_b64,
            "device_id": device_id,
            "identity_type": "human",
            "registration_proof": registration_proof_b64,
            "timestamp": timestamp
        })).expect("serialize request");

        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/register".to_string(),
            version: ZHTP_VERSION.to_string(),
            headers: ZhtpHeaders::new(),
            body,
            timestamp,
            requester: None,
            auth_proof: None,
        };

        let response = handler.handle_request(request).await.expect("handler failed");
        assert_eq!(response.status, ZhtpStatus::Ok);

        let json: serde_json::Value = serde_json::from_slice(&response.body).expect("invalid json");
        let did = json.get("did").and_then(|v| v.as_str()).expect("missing did");
        let node_id = json.get("node_id").and_then(|v| v.as_str()).expect("missing node_id");
        let identity_id = json.get("identity_id").and_then(|v| v.as_str()).expect("missing identity_id");

        let expected_key_id = lib_crypto::hash_blake3(&keypair.public_key.dilithium_pk);
        let expected_did = format!("did:zhtp:{}", hex::encode(expected_key_id));
        let expected_node_id = hex::encode(lib_crypto::hash_blake3(format!("{}{}", expected_did, device_id).as_bytes()));
        let expected_identity_id = hex::encode(expected_key_id);

        assert_eq!(did, expected_did);
        assert_eq!(node_id, expected_node_id);
        assert_eq!(identity_id, expected_identity_id);

        let _ = std::fs::remove_dir_all(db_path);
    }
}
