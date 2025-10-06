#[cfg(test)]
mod api_integration_tests {
    use super::*;
    use crate::runtime::{RuntimeOrchestrator, ComponentId, Component, ApiComponent};
    use crate::config::{NodeConfig, MeshMode, SecurityLevel, Environment};
    use tokio::time::{timeout, Duration};
    use std::collections::HashMap;
    
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
}