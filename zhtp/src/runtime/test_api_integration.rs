#[cfg(test)]
mod api_integration_tests {

    use crate::api::handlers::identity::login_handlers::AccountLockout;
    use crate::api::handlers::identity::IdentityHandler;
    use crate::api::middleware::{CsrfProtection, RateLimiter};
    use crate::config::NodeConfig;
    use crate::runtime::{ApiComponent, Component, RuntimeOrchestrator};
    use crate::session_manager::SessionManager;
    use base64::Engine as _;
    use lib_identity::{
        economics::EconomicModel as IdentityEconomicModel, IdentityManager, RecoveryPhraseManager,
    };
    use lib_protocols::types::{ZhtpHeaders, ZhtpMethod, ZhtpRequest, ZhtpStatus, ZHTP_VERSION};
    use lib_protocols::zhtp::ZhtpRequestHandler;
    use lib_storage::{PersistentStorageSystem, UnifiedStorageConfig, UnifiedStorageSystem};
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::RwLock;

    /// Serialise tests that mutate the process-global blockchain provider so
    /// parallel `cargo test` workers cannot race on `set_global_blockchain`.
    fn global_blockchain_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn create_test_config() -> NodeConfig {
        let mut config = NodeConfig::default();
        // Customize for testing
        config.node_id = [1u8; 32];
        config.data_directory = "test_data".to_string();
        config.network_config.mesh_port = 8081;
        config.storage_config.dht_port = 8080;
        config.protocols_config.api_port = 8082;
        config.network_config.bootstrap_peers = vec![]; // No bootstrap peers for tests
        // RuntimeOrchestrator::new requires node_type to be set (normally done by
        // the start_* path); derive it from the config fields here.
        config.derive_node_type();
        config
    }

    #[tokio::test]
    async fn test_api_component_integration() {
        // Initialize runtime with test config
        let config = create_test_config();
        let runtime_result = RuntimeOrchestrator::new(config).await;
        assert!(
            runtime_result.is_ok(),
            "Runtime should initialize successfully"
        );

        let runtime = runtime_result.unwrap();

        // Register all components including API
        let register_result = runtime.register_all_components().await;
        assert!(
            register_result.is_ok(),
            "Runtime should register components successfully"
        );

        // Test basic runtime functionality without starting components
        // (starting components requires actual network resources and can timeout in CI)
        let status_result = runtime.get_component_status().await;
        assert!(
            status_result.is_ok(),
            "Should be able to get component status"
        );

        // Test getting detailed health (components will be uninitialized but method should work)
        let health_result = runtime.get_detailed_health().await;
        assert!(
            health_result.is_ok(),
            "Should be able to get detailed health status"
        );

        // This proves the API component is properly integrated into the runtime system
        println!("API component successfully integrated into runtime orchestrator");
    }

    #[tokio::test]
    async fn test_api_component_lifecycle() {
        // Test individual API component lifecycle
        let api_component = ApiComponent::new();

        // Test start
        let start_result = api_component.start().await;
        assert!(
            start_result.is_ok(),
            "API component should start successfully"
        );

        // Test health check
        let health_result = api_component.health_check().await;
        assert!(
            health_result.is_ok(),
            "API component should be healthy after start"
        );

        // Test stop
        let stop_result = api_component.stop().await;
        assert!(
            stop_result.is_ok(),
            "API component should stop successfully"
        );
    }

    #[tokio::test]
    async fn test_register_identity_derives_did_and_node_id() {
        let mut storage_config = UnifiedStorageConfig::default();
        let db_path = std::env::temp_dir().join(format!("zhtp-test-dht-{}", rand::random::<u64>()));
        storage_config.storage_config.dht_persist_path = Some(db_path.clone());

        let storage = UnifiedStorageSystem::new_persistent(storage_config, db_path.clone())
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
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(&keypair.public_key.dilithium_pk);

        let signed_message = format!("ZHTP_REGISTER:{}", timestamp);
        let signature =
            lib_crypto::sign_message(&keypair, signed_message.as_bytes()).expect("sign failed");
        let registration_proof_b64 =
            base64::engine::general_purpose::STANDARD.encode(&signature.signature);

        let body = serde_json::to_vec(&serde_json::json!({
            "public_key": public_key_b64,
            "device_id": device_id,
            "identity_type": "human",
            "registration_proof": registration_proof_b64,
            "timestamp": timestamp
        }))
        .expect("serialize request");

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

        let response = handler
            .handle_request(request)
            .await
            .expect("handler failed");
        assert_eq!(response.status, ZhtpStatus::Ok);

        let json: serde_json::Value = serde_json::from_slice(&response.body).expect("invalid json");
        let did = json
            .get("did")
            .and_then(|v| v.as_str())
            .expect("missing did");
        let node_id = json
            .get("node_id")
            .and_then(|v| v.as_str())
            .expect("missing node_id");
        let identity_id = json
            .get("identity_id")
            .and_then(|v| v.as_str())
            .expect("missing identity_id");

        let expected_key_id = lib_crypto::hash_blake3(&keypair.public_key.dilithium_pk);
        let expected_did = format!("did:zhtp:{}", hex::encode(expected_key_id));
        let expected_node_id = hex::encode(lib_crypto::hash_blake3(
            format!("{}{}", expected_did, device_id).as_bytes(),
        ));
        let expected_identity_id = hex::encode(expected_key_id);

        assert_eq!(did, expected_did);
        assert_eq!(node_id, expected_node_id);
        assert_eq!(identity_id, expected_identity_id);

        let _ = std::fs::remove_dir_all(db_path);
    }

    fn build_identity_handler(
        storage: PersistentStorageSystem,
        db_path: std::path::PathBuf,
    ) -> (IdentityHandler, std::path::PathBuf) {
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
        (handler, db_path)
    }

    fn build_register_request(
        keypair: &lib_crypto::KeyPair,
        device_id: &str,
        timestamp: u64,
        display_name: Option<&str>,
    ) -> ZhtpRequest {
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(&keypair.public_key.dilithium_pk);
        let signed_message = format!("ZHTP_REGISTER:{}", timestamp);
        let signature =
            lib_crypto::sign_message(keypair, signed_message.as_bytes()).expect("sign failed");
        let registration_proof_b64 =
            base64::engine::general_purpose::STANDARD.encode(&signature.signature);

        let mut body = serde_json::json!({
            "public_key": public_key_b64,
            "device_id": device_id,
            "identity_type": "human",
            "registration_proof": registration_proof_b64,
            "timestamp": timestamp
        });
        if let Some(name) = display_name {
            body["display_name"] = serde_json::Value::String(name.to_string());
        }

        ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/register".to_string(),
            version: ZHTP_VERSION.to_string(),
            headers: ZhtpHeaders::new(),
            body: serde_json::to_vec(&body).expect("serialize request"),
            timestamp,
            requester: None,
            auth_proof: None,
        }
    }

    #[tokio::test]
    async fn test_register_identity_rejects_future_timestamp() {
        let mut storage_config = UnifiedStorageConfig::default();
        let db_path = std::env::temp_dir().join(format!("zhtp-test-future-{}", rand::random::<u64>()));
        storage_config.storage_config.dht_persist_path = Some(db_path.clone());
        let storage = UnifiedStorageSystem::new_persistent(storage_config, db_path.clone())
            .expect("failed to create storage");
        let (handler, db_path) = build_identity_handler(storage, db_path);

        let keypair = lib_crypto::KeyPair::generate().expect("keypair generation failed");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let request = build_register_request(&keypair, "device-future", now + 120, None);

        let response = handler
            .handle_request(request)
            .await
            .expect("handler failed");
        assert_eq!(response.status, ZhtpStatus::BadRequest);

        let _ = std::fs::remove_dir_all(db_path);
    }

    #[tokio::test]
    async fn test_register_identity_rejects_invalid_display_name() {
        let mut storage_config = UnifiedStorageConfig::default();
        let db_path = std::env::temp_dir().join(format!("zhtp-test-name-{}", rand::random::<u64>()));
        storage_config.storage_config.dht_persist_path = Some(db_path.clone());
        let storage = UnifiedStorageSystem::new_persistent(storage_config, db_path.clone())
            .expect("failed to create storage");
        let (handler, db_path) = build_identity_handler(storage, db_path);

        let keypair = lib_crypto::KeyPair::generate().expect("keypair generation failed");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let request = build_register_request(&keypair, "device-bad-name", now, Some("bad name!"));

        let response = handler
            .handle_request(request)
            .await
            .expect("handler failed");
        assert_eq!(response.status, ZhtpStatus::BadRequest);

        let _ = std::fs::remove_dir_all(db_path);
    }

    #[tokio::test]
    async fn test_register_identity_empty_display_name_uses_user_prefix_fallback() {
        let _guard = global_blockchain_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut storage_config = UnifiedStorageConfig::default();
        let db_path = std::env::temp_dir().join(format!(
            "zhtp-test-empty-name-{}",
            rand::random::<u64>()
        ));
        storage_config.storage_config.dht_persist_path = Some(db_path.clone());
        let storage = UnifiedStorageSystem::new_persistent(storage_config, db_path.clone())
            .expect("failed to create storage");
        let (handler, db_path) = build_identity_handler(storage, db_path);

        crate::runtime::blockchain_provider::initialize_global_blockchain_provider();
        let bc = lib_blockchain::Blockchain::new().expect("new blockchain");
        crate::runtime::blockchain_provider::set_global_blockchain(Arc::new(RwLock::new(bc)))
            .await
            .expect("set global blockchain");

        let keypair = lib_crypto::KeyPair::generate().expect("keypair generation failed");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Whitespace-only display_name must fall back to user_{key_id_prefix}.
        let request = build_register_request(&keypair, "device-empty-name", now, Some("   "));

        let response = handler
            .handle_request(request)
            .await
            .expect("handler failed");
        assert_eq!(response.status, ZhtpStatus::Ok);

        let json: serde_json::Value = serde_json::from_slice(&response.body).expect("invalid json");
        assert_eq!(json.get("status").and_then(|v| v.as_str()), Some("queued"));
        assert!(
            json.get("blockchain_tx").and_then(|v| v.as_str()).is_some(),
            "success response must include blockchain_tx hash"
        );

        let expected_prefix = format!(
            "user_{}",
            &hex::encode(lib_crypto::hash_blake3(&keypair.public_key.dilithium_pk))[..8]
        );
        // Pending projection / shadow uses the fallback name; surface via chain shadow.
        let did = json
            .get("did")
            .and_then(|v| v.as_str())
            .expect("missing did");
        let bc = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .expect("blockchain");
        let bc = bc.read().await;
        let name = bc
            .identity_display_name(did)
            .expect("shadow identity after successful register");
        assert_eq!(name, expected_prefix);

        let _ = std::fs::remove_dir_all(db_path);
    }

    #[tokio::test]
    async fn test_register_identity_rejects_on_chain_duplicate() {
        let _guard = global_blockchain_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut storage_config = UnifiedStorageConfig::default();
        let db_path =
            std::env::temp_dir().join(format!("zhtp-test-dup-{}", rand::random::<u64>()));
        storage_config.storage_config.dht_persist_path = Some(db_path.clone());
        let storage = UnifiedStorageSystem::new_persistent(storage_config, db_path.clone())
            .expect("failed to create storage");
        let (handler, db_path) = build_identity_handler(storage, db_path);

        let keypair = lib_crypto::KeyPair::generate().expect("keypair generation failed");
        let did = format!(
            "did:zhtp:{}",
            hex::encode(lib_crypto::hash_blake3(&keypair.public_key.dilithium_pk))
        );

        crate::runtime::blockchain_provider::initialize_global_blockchain_provider();
        let mut bc = lib_blockchain::Blockchain::new().expect("new blockchain");
        bc.insert_identity_shadow(
            did.clone(),
            lib_blockchain::transaction::core::IdentityTransactionData::new(
                did,
                "existing".to_string(),
                keypair.public_key.dilithium_pk.to_vec(),
                vec![0x01],
                "human".to_string(),
                lib_blockchain::types::Hash::default(),
                0,
                0,
            ),
        );
        crate::runtime::blockchain_provider::set_global_blockchain(Arc::new(RwLock::new(bc)))
            .await
            .expect("set global blockchain");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let request = build_register_request(&keypair, "device-dup", now, None);

        let response = handler
            .handle_request(request)
            .await
            .expect("handler failed");
        assert_eq!(response.status, ZhtpStatus::Conflict);

        let _ = std::fs::remove_dir_all(db_path);
    }

    /// #2773: unauthenticated register admits at most 10 attempts / hour / IP.
    #[tokio::test]
    async fn test_register_identity_rate_limits_per_ip() {
        let mut storage_config = UnifiedStorageConfig::default();
        let db_path =
            std::env::temp_dir().join(format!("zhtp-test-rl-{}", rand::random::<u64>()));
        storage_config.storage_config.dht_persist_path = Some(db_path.clone());
        let storage = UnifiedStorageSystem::new_persistent(storage_config, db_path.clone())
            .expect("failed to create storage");
        let (handler, db_path) = build_identity_handler(storage, db_path);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 10 attempts (any status) from the same IP must be admitted into the handler.
        // 11th is rejected before crypto / parse side effects matter.
        for i in 0..10 {
            let keypair = lib_crypto::KeyPair::generate().expect("keypair");
            // Far-future timestamp → cheap BadRequest after rate-limit consume
            let mut request =
                build_register_request(&keypair, &format!("device-rl-{}", i), now + 120, None);
            request.headers.set("peer_addr", "203.0.113.50".into());
            let response = handler
                .handle_request(request)
                .await
                .expect("handler failed");
            assert_ne!(
                response.status,
                ZhtpStatus::TooManyRequests,
                "attempt {} should not be rate-limited yet",
                i + 1
            );
        }

        let keypair = lib_crypto::KeyPair::generate().expect("keypair");
        let mut request =
            build_register_request(&keypair, "device-rl-blocked", now + 120, None);
        request.headers.set("peer_addr", "203.0.113.50".into());
        let response = handler
            .handle_request(request)
            .await
            .expect("handler failed");
        assert_eq!(response.status, ZhtpStatus::TooManyRequests);

        // Different peer is unaffected
        let keypair = lib_crypto::KeyPair::generate().expect("keypair");
        let mut request =
            build_register_request(&keypair, "device-rl-other", now + 120, None);
        request.headers.set("peer_addr", "203.0.113.99".into());
        let response = handler
            .handle_request(request)
            .await
            .expect("handler failed");
        assert_ne!(response.status, ZhtpStatus::TooManyRequests);

        let _ = std::fs::remove_dir_all(db_path);
    }
}
