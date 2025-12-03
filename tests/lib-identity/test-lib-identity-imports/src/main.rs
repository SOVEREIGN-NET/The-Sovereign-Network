//! External test crate to verify lib-identity exports work correctly
//! 
//! This tests that external crates can import all required types and modules

use anyhow::Result;

// Core type imports - these should all work from root
use lib_identity::{
    AccessLevel,
    ContentMetadataSnapshot,
    ContentOwnershipRecord,
    ContentOwnershipStatistics,
    ContentTransfer,
    ContentTransferType,
    DaoGovernanceSettings,
    DaoHierarchyInfo,
    DaoWalletProperties,
    Guardian,
    GuardianConfig,
    GuardianStatus,
    IdentityId,
    IdentityManager,
    IdentityType,
    IdentityVerification,
    KeyPair,
    NodeId,
    PasswordManager,
    PasswordStrength,
    PublicTransactionEntry,
    RecoveryPhrase,
    RecoveryRequest,
    RecoveryStatus,
    SocialRecoveryManager,
    TransparencyLevel,
    VerificationLevel,
    VerificationResult,
    WalletId,
    WalletManager,
    WalletPasswordError,
    WalletPasswordManager,
    WalletPasswordValidation,
    WalletType,
    ZhtpIdentity,
};

// Module imports - verify modules are accessible
use lib_identity::types;
use lib_identity::identity;
use lib_identity::wallets;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Testing lib-identity exports with REAL functionality...\n");
    
    // Test 1: Generate real KeyPair using lib_crypto (imported as KeyPair type)
    println!("1. Testing KeyPair generation...");
    let keypair = lib_identity::crypto::generate_keypair()?;
    println!("   ✓ Generated real KeyPair with Dilithium keys");
    println!("   - Dilithium public key length: {} bytes", keypair.public_key.dilithium_pk.len());
    println!("   - Kyber public key length: {} bytes", keypair.public_key.kyber_pk.len());
    
    // Verify KeyPair type is accessible
    let _keypair_type_check: KeyPair = keypair.clone();
    println!("   ✓ KeyPair type imported and used successfully");
    
    // Test 2: Create real NodeId from DID
    println!("\n2. Testing NodeId generation from DID...");
    let did = "did:zhtp:test123";
    let device_name = "test-device";
    let node_id = NodeId::from_did_device(did, device_name)?;
    println!("   ✓ Generated NodeId: {}", node_id);
    println!("   - DID: {}", did);
    println!("   - Device: {}", device_name);
    
    // Test 3: Create IdentityManager and verify it works (use imported type)
    println!("\n3. Testing IdentityManager...");
    let manager: IdentityManager = IdentityManager::new();
    println!("   ✓ Created IdentityManager with {} identities", manager.list_identities().len());
    
    // Test via identity module
    let _manager_via_module: identity::IdentityManager = identity::IdentityManager::new();
    println!("   ✓ identity module accessible directly");
    println!("   ✓ IdentityManager type imported and used successfully");
    
    // Test 4: Create WalletManager with real identity
    println!("\n4. Testing WalletManager...");
    let identity_id = IdentityId::from_bytes(&keypair.public_key.dilithium_pk[..32]);
    let wallet_manager: WalletManager = WalletManager::new(identity_id.clone());
    let wallet_count = wallet_manager.list_wallets().len();
    println!("   ✓ Created WalletManager for identity: {}", hex::encode(&identity_id.0));
    println!("   ✓ WalletManager type imported and used (wallets: {})", wallet_count);
    
    // Create WalletId to verify import
    let wallet_id: WalletId = WalletId::from_bytes(&keypair.public_key.kyber_pk[..32]);
    println!("   ✓ WalletId type imported and used: {}", hex::encode(&wallet_id.0[..8]));
    
    // Test 5: Test RecoveryPhrase generation (use imported RecoveryPhrase type)
    println!("\n5. Testing RecoveryPhrase generation...");
    use lib_identity::recovery::{RecoveryPhraseManager, PhraseGenerationOptions, EntropySource};
    let mut phrase_manager = RecoveryPhraseManager::new();
    let options = PhraseGenerationOptions {
        entropy_source: EntropySource::SystemRandom,
        word_count: 20,
        language: "english".to_string(),
        custom_wordlist: None,
        include_checksum: true,
    };
    let recovery_phrase: RecoveryPhrase = phrase_manager.generate_recovery_phrase(&identity_id.to_string(), options).await?;
    println!("   ✓ Generated 20-word recovery phrase");
    println!("   - First 3 words: {} {} {}...", 
        recovery_phrase.words[0], 
        recovery_phrase.words[1], 
        recovery_phrase.words[2]
    );
    println!("   ✓ RecoveryPhrase type imported and used successfully");
    
    // Test 6: Test PasswordManager (imported type used)
    println!("\n6. Testing PasswordManager...");
    let password_mgr: PasswordManager = PasswordManager::new();
    let has_pwd = password_mgr.has_password(&identity_id);
    println!("   ✓ PasswordManager type imported and instantiated");
    println!("   ✓ Password management system accessible (has_password: {})", has_pwd);
    
    // Test 7: Test types from types module (use imported types)
    println!("\n7. Testing types module exports...");
    let identity_type: IdentityType = IdentityType::Human;
    let access_level: AccessLevel = AccessLevel::FullCitizen;
    println!("   ✓ IdentityType imported and used: {:?}", identity_type);
    println!("   ✓ AccessLevel imported and used: {:?}", access_level);
    
    // Also test via types module directly
    let _node_id_via_module: types::NodeId = types::NodeId::from_bytes([5u8; 32]);
    let _identity_type_via_module: types::IdentityType = types::IdentityType::Device;
    println!("   ✓ types module accessible directly");
    
    // Test 8: Test wallet types (use imported WalletType)
    println!("\n8. Testing wallet types...");
    let wallet_type_standard: WalletType = WalletType::Standard;
    let wallet_type_savings: WalletType = WalletType::Savings;
    println!("   ✓ WalletType::Standard imported and used: {:?}", wallet_type_standard);
    println!("   ✓ WalletType::Savings imported and used: {:?}", wallet_type_savings);
    
    // Test via wallets module
    let _wallet_type_via_module: wallets::WalletType = wallets::WalletType::Standard;
    println!("   ✓ wallets module accessible directly");
    
    // Test 9: Verify ZhtpIdentity type is accessible
    println!("\n9. Testing ZhtpIdentity type...");
    let _zhtp_identity_type: Option<ZhtpIdentity> = None;
    println!("   ✓ ZhtpIdentity type imported and accessible");

    // Test 10: Verify DAO/content/guardian exports are accessible
    println!("\n10. Testing DAO, content ownership, guardian, and verification exports...");
    let _dao_props: Option<DaoWalletProperties> = None;
    let _dao_governance: Option<DaoGovernanceSettings> = None;
    let _dao_hierarchy: Option<DaoHierarchyInfo> = None;
    let _transparency: TransparencyLevel = TransparencyLevel::Full;
    let _public_tx: Option<PublicTransactionEntry> = None;
    let _content_record: Option<ContentOwnershipRecord> = None;
    let _content_stats: Option<ContentOwnershipStatistics> = None;
    let _content_transfer_record: Option<ContentTransfer> = None;
    let _content_transfer_type: ContentTransferType = ContentTransferType::Sale;
    let _content_snapshot: Option<ContentMetadataSnapshot> = None;
    let _wallet_pwd_mgr: WalletPasswordManager = WalletPasswordManager::new();
    let _wallet_pwd_error: Option<WalletPasswordError> = None;
    let _wallet_pwd_validation: Option<WalletPasswordValidation> = None;
    let _password_strength: Option<PasswordStrength> = None;
    let _verification: Option<IdentityVerification> = None;
    let _verification_level: VerificationLevel = VerificationLevel::Basic;
    let _verification_result: Option<VerificationResult> = None;
    let _guardian: Option<Guardian> = None;
    let _guardian_config: Option<GuardianConfig> = None;
    let _guardian_status: GuardianStatus = GuardianStatus::Active;
    let _social_recovery_mgr: Option<SocialRecoveryManager> = None;
    let _recovery_request: Option<RecoveryRequest> = None;
    let _recovery_status: RecoveryStatus = RecoveryStatus::Pending;
    println!("   ✓ Additional exports are accessible and type-checked");
    
    println!("\n✅ ALL TESTS PASSED - Real functionality verified!");
    println!("\n📦 VERIFIED EXPORTS:");
    println!("   ✓ NodeId - imported and used (generated: {})", node_id);
    println!("   ✓ KeyPair - imported and used ({} byte Dilithium keys)", _keypair_type_check.public_key.dilithium_pk.len());
    println!("   ✓ ZhtpIdentity - imported and type-checked");
    println!("   ✓ WalletManager - imported and instantiated");
    println!("   ✓ WalletId - imported and used");
    println!("   ✓ IdentityId - imported and used");
    println!("   ✓ IdentityManager - imported and used");
    println!("   ✓ IdentityType - imported and used: {:?}", identity_type);
    println!("   ✓ AccessLevel - imported and used: {:?}", access_level);
    println!("   ✓ RecoveryPhrase - imported and used ({} words)", recovery_phrase.words.len());
    println!("   ✓ PasswordManager - imported and instantiated");
    println!("   ✓ WalletType - imported and used");
    println!("\n📁 VERIFIED MODULES:");
    println!("   ✓ lib_identity::types - accessible");
    println!("   ✓ lib_identity::identity - accessible");
    println!("   ✓ lib_identity::wallets - accessible");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_node_id_import() {
        // Direct import from root
        use lib_identity::NodeId;
        let node_id = NodeId::from_bytes([0u8; 32]);
        assert_eq!(node_id.as_bytes(), &[0u8; 32]);
    }
    
    #[test]
    fn test_node_id_from_types_module() {
        // Import from types module
        use lib_identity::types::NodeId;
        let node_id = NodeId::from_bytes([0u8; 32]);
        assert_eq!(node_id.as_bytes(), &[0u8; 32]);
    }
    
    #[test]
    fn test_keypair_import() {
        // KeyPair is re-exported from lib_crypto
        use lib_identity::KeyPair;
        let _: Option<KeyPair> = None;
    }
    
    #[test]
    fn test_zhtp_identity_import() {
        use lib_identity::ZhtpIdentity;
        let _: Option<ZhtpIdentity> = None;
    }
    
    #[test]
    fn test_wallet_manager_import() {
        use lib_identity::WalletManager;
        let _: Option<WalletManager> = None;
    }
    
    #[test]
    fn test_types_module_accessible() {
        use lib_identity::types;
        let _node_id: types::NodeId = types::NodeId::from_bytes([0u8; 32]);
        let _identity_type = types::IdentityType::Human;
        let _access_level = types::AccessLevel::FullCitizen;
    }
    
    #[test]
    fn test_identity_module_accessible() {
        use lib_identity::identity;
        let manager = identity::IdentityManager::new();
        assert_eq!(manager.list_identities().len(), 0);
    }
    
    #[test]
    fn test_wallets_module_accessible() {
        use lib_identity::wallets;
        let _wallet_type = wallets::WalletType::Standard;
    }
    
    #[test]
    fn test_all_common_types() {
        use lib_identity::{
            IdentityId, IdentityType, AccessLevel, IdentityManager,
            WalletType, WalletId, RecoveryPhrase, PasswordManager,
        };
        
        let _id: IdentityId = IdentityId::from_bytes(&[0u8; 32]);
        let _type = IdentityType::Human;
        let _access = AccessLevel::FullCitizen;
        let _manager = IdentityManager::new();
        let _wallet_type = WalletType::Standard;
        let _wallet_id: WalletId = WalletId::from_bytes(&[1u8; 32]);
        let _recovery: Option<RecoveryPhrase> = None;
        let _pwd_mgr = PasswordManager::new();
    }
    
    #[test]
    fn test_no_unused_import_warnings() {
        // This test ensures that importing and using types doesn't generate warnings
        use lib_identity::{NodeId, KeyPair, ZhtpIdentity, WalletManager};
        
        let _node = NodeId::from_bytes([0u8; 32]);
        let _keypair: Option<KeyPair> = None;
        let _identity: Option<ZhtpIdentity> = None;
        let _wallet_manager: Option<WalletManager> = None;
    }

    #[test]
    fn test_dao_and_content_exports_accessible() {
        use lib_identity::{
            ContentMetadataSnapshot,
            ContentOwnershipRecord,
            ContentOwnershipStatistics,
            ContentTransfer,
            ContentTransferType,
            DaoGovernanceSettings,
            DaoHierarchyInfo,
            DaoWalletProperties,
            PublicTransactionEntry,
            TransparencyLevel,
            WalletPasswordError,
            WalletPasswordManager,
            WalletPasswordValidation,
        };

        let _dao_props: Option<DaoWalletProperties> = None;
        let _dao_governance: Option<DaoGovernanceSettings> = None;
        let _dao_hierarchy: Option<DaoHierarchyInfo> = None;
        let _transparency = TransparencyLevel::Full;
        let _public_tx: Option<PublicTransactionEntry> = None;
        let _content_record: Option<ContentOwnershipRecord> = None;
        let _content_stats: Option<ContentOwnershipStatistics> = None;
        let _content_transfer_record: Option<ContentTransfer> = None;
        let _content_transfer_type = ContentTransferType::Sale;
        let _content_snapshot: Option<ContentMetadataSnapshot> = None;
        let _wallet_pwd_mgr = WalletPasswordManager::new();
        let _wallet_pwd_error: Option<WalletPasswordError> = None;
        let _wallet_pwd_validation: Option<WalletPasswordValidation> = None;

        // Silence unused warnings
        let _ = (
            _dao_props,
            _dao_governance,
            _dao_hierarchy,
            _transparency,
            _public_tx,
            _content_record,
            _content_stats,
            _content_transfer_record,
            _content_transfer_type,
            _content_snapshot,
            _wallet_pwd_mgr,
            _wallet_pwd_error,
            _wallet_pwd_validation,
        );
    }

    #[test]
    fn test_guardian_and_recovery_exports_accessible() {
        use lib_identity::{
            Guardian,
            GuardianConfig,
            GuardianStatus,
            RecoveryRequest,
            RecoveryStatus,
            SocialRecoveryManager,
        };

        let _guardian: Option<Guardian> = None;
        let _guardian_config: Option<GuardianConfig> = None;
        let _guardian_status = GuardianStatus::Active;
        let _social_recovery_mgr: Option<SocialRecoveryManager> = None;
        let _recovery_request: Option<RecoveryRequest> = None;
        let _recovery_status = RecoveryStatus::Pending;

        let _ = (
            _guardian,
            _guardian_config,
            _guardian_status,
            _social_recovery_mgr,
            _recovery_request,
            _recovery_status,
        );
    }

    #[test]
    fn test_verification_exports_accessible() {
        use lib_identity::{IdentityVerification, VerificationLevel, VerificationResult};

        let _verification: Option<IdentityVerification> = None;
        let _level = VerificationLevel::Basic;
        let _result: Option<VerificationResult> = None;

        let _ = (_verification, _level, _result);
    }
}
