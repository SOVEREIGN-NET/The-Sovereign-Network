//! Integration test for Identity Handler with real lib-identity services
//! 
//! This test validates that the Identity API handler correctly integrates
//! with the actual lib-identity service implementations.

#[cfg(test)]
mod tests {
    use super::super::identity::IdentityHandler;
    use serde_json::json;
    use std::collections::HashMap;
    
    #[tokio::test]
    async fn test_create_citizen_identity_integration() {
        // Create handler with real lib-identity services
        let handler = IdentityHandler::new();
        
        // Test citizen identity creation request
        let request_body = json!({
            "identity_type": "human",
            "display_name": "Test Citizen",
            "recovery_options": ["email:test@example.com", "phone:+1234567890"],
            "initial_wallet_type": "citizen_wallet"
        });
        
        let request_bytes = serde_json::to_vec(&request_body).unwrap();
        let empty_headers = HashMap::new();
        
        // Call the real service integration
        let result = handler.handle("POST", "/api/v1/identity/create", &request_bytes, &empty_headers).await;
        
        assert!(result.is_ok(), "Identity creation should succeed: {:?}", result.err());
        
        let response = result.unwrap();
        
        // Verify response structure matches real lib-identity output
        assert_eq!(response["status"], "success");
        assert!(response["identity_id"].is_string());
        assert!(response["did"].as_str().unwrap().starts_with("did:zhtp:"));
        assert_eq!(response["display_name"], "Test Citizen");
        assert_eq!(response["identity_type"], "human");
        
        // Verify citizen benefits are included
        assert!(response["dao_registration"].is_object());
        assert!(response["ubi_registration"].is_object());
        assert!(response["web4_access"].is_object());
        assert!(response["welcome_bonus"].is_object());
        assert!(response["benefits_summary"].is_object());
        
        // Verify wallet creation
        assert!(response["primary_wallet_id"].is_string());
        assert!(response["ubi_wallet_id"].is_string());
        assert!(response["savings_wallet_id"].is_string());
        
        println!("✅ Citizen identity creation integration test passed");
        println!("📋 Response: {}", serde_json::to_string_pretty(&response).unwrap());
    }
    
    #[tokio::test]
    async fn test_basic_identity_creation_integration() {
        let handler = IdentityHandler::new();
        
        // Test non-human identity creation (should not get citizen benefits)
        let request_body = json!({
            "identity_type": "organization",
            "display_name": "Test Organization", 
            "recovery_options": ["admin:org@example.com"],
            "initial_wallet_type": "basic_wallet"
        });
        
        let request_bytes = serde_json::to_vec(&request_body).unwrap();
        let empty_headers = HashMap::new();
        
        let result = handler.handle("POST", "/api/v1/identity/create", &request_bytes, &empty_headers).await;
        
        assert!(result.is_ok(), "Basic identity creation should succeed: {:?}", result.err());
        
        let response = result.unwrap();
        
        // Verify basic identity response (no citizen benefits)
        assert_eq!(response["status"], "success");
        assert_eq!(response["message"], "Basic identity created (non-citizen)");
        assert_eq!(response["identity_type"], "organization");
        assert!(response["note"].as_str().unwrap().contains("Only human identities receive full citizen benefits"));
        
        println!("✅ Basic identity creation integration test passed");
    }
    
    #[tokio::test]
    async fn test_identity_verification_integration() {
        let handler = IdentityHandler::new();
        
        // First create an identity to verify
        let create_request = json!({
            "identity_type": "human",
            "display_name": "Test Verification User",
            "recovery_options": ["email:verify@example.com"]
        });
        
        let create_bytes = serde_json::to_vec(&create_request).unwrap();
        let empty_headers = HashMap::new();
        
        let create_result = handler.handle("POST", "/api/v1/identity/create", &create_bytes, &empty_headers).await;
        assert!(create_result.is_ok());
        
        let create_response = create_result.unwrap();
        let identity_id = create_response["identity_id"].as_str().unwrap().to_string();
        
        // Now test verification with the created identity
        let verify_request = json!({
            "identity_id": identity_id,
            "verification_level": "Standard",
            "required_credentials": ["age_verification", "reputation"],
            "privacy_level": 85
        });
        
        let verify_bytes = serde_json::to_vec(&verify_request).unwrap();
        
        let verify_result = handler.handle("POST", "/api/v1/identity/verify", &verify_bytes, &empty_headers).await;
        
        assert!(verify_result.is_ok(), "Identity verification should succeed: {:?}", verify_result.err());
        
        let verify_response = verify_result.unwrap();
        
        // Verify response structure
        assert!(verify_response["verified"].is_boolean());
        assert_eq!(verify_response["identity_id"], identity_id);
        assert_eq!(verify_response["verification_level"], "Standard");
        assert!(verify_response["requirements_met"].is_array());
        assert!(verify_response["privacy_score"].is_number());
        assert!(verify_response["verified_at"].is_number());
        assert_eq!(verify_response["verification_method"], "zero_knowledge_proof");
        
        println!("✅ Identity verification integration test passed");
        println!("🔍 Verification result: {}", serde_json::to_string_pretty(&verify_response).unwrap());
    }
}
