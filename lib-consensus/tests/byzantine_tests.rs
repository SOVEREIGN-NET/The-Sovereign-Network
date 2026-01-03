//! Tests for Byzantine fault detection system

use anyhow::Result;
use lib_consensus::{
    ByzantineFault, ByzantineFaultDetector, ByzantineFaultType, FaultSeverity, ValidatorManager,
};
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper function to create test identity
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

#[test]
fn test_byzantine_fault_detector_initialization() {
    let mut detector = ByzantineFaultDetector::new();

    // Initially should have no faults detected
    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager).unwrap();
    assert_eq!(faults.len(), 0);
}

#[test]
fn test_double_sign_detection() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();

    let validator = create_test_identity("malicious_validator");
    let height = 100;
    let round = 1;
    let first_signature = vec![1, 2, 3, 4];
    let second_signature = vec![5, 6, 7, 8];

    // Record double signing event
    detector.record_double_sign(
        validator.clone(),
        height,
        round,
        first_signature.clone(),
        second_signature.clone(),
    );

    // Detect faults
    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager)?;

    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].validator, validator);
    assert_eq!(faults[0].fault_type, ByzantineFaultType::DoubleSign);
    assert_eq!(faults[0].severity, FaultSeverity::Critical);
    assert!(faults[0].evidence.contains("Double signed"));

    Ok(())
}

#[test]
fn test_liveness_violation_detection() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();

    let validator = create_test_identity("inactive_validator");
    let height = 200;
    let missed_rounds = 5;

    // Record liveness violation
    detector.record_liveness_violation(validator.clone(), height, missed_rounds);

    // Detect faults
    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager)?;

    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].validator, validator);
    assert_eq!(faults[0].fault_type, ByzantineFaultType::Liveness);
    assert_eq!(faults[0].severity, FaultSeverity::Minor);
    assert!(faults[0].evidence.contains("Missed"));

    Ok(())
}

#[test]
fn test_liveness_violation_severity_escalation() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();

    let validator = create_test_identity("very_inactive_validator");

    // Record multiple severe liveness violations
    for i in 0..12 {
        detector.record_liveness_violation(validator.clone(), 100 + i, 5);
    }

    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager)?;

    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].fault_type, ByzantineFaultType::Liveness);
    assert_eq!(faults[0].severity, FaultSeverity::Critical); // Should escalate to critical

    Ok(())
}

#[test]
fn test_invalid_proposal_detection() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();

    let validator = create_test_identity("malicious_proposer");
    let height = 300;
    let proposal_hash = [42u8; 32];
    let violation_type = "Invalid merkle root".to_string();

    // Record multiple invalid proposals to trigger detection
    for i in 0..3 {
        detector.record_invalid_proposal(
            validator.clone(),
            height + i,
            proposal_hash,
            violation_type.clone(),
        );
    }

    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager)?;

    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].validator, validator);
    assert_eq!(faults[0].fault_type, ByzantineFaultType::InvalidProposal);
    assert_eq!(faults[0].severity, FaultSeverity::Major);
    assert!(faults[0].evidence.contains("invalid proposals"));

    Ok(())
}

#[test]
fn test_multiple_fault_types() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();

    let validator1 = create_test_identity("double_signer");
    let validator2 = create_test_identity("inactive_validator");
    let validator3 = create_test_identity("invalid_proposer");

    // Record different types of faults
    detector.record_double_sign(validator1.clone(), 100, 1, vec![1, 2], vec![3, 4]);
    detector.record_liveness_violation(validator2.clone(), 200, 10);

    for i in 0..3 {
        detector.record_invalid_proposal(
            validator3.clone(),
            300 + i,
            [i as u8; 32],
            "Invalid proposal".to_string(),
        );
    }

    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager)?;

    assert_eq!(faults.len(), 3);

    // Check that all fault types are detected
    let fault_types: Vec<ByzantineFaultType> =
        faults.iter().map(|f| f.fault_type.clone()).collect();
    assert!(fault_types.contains(&ByzantineFaultType::DoubleSign));
    assert!(fault_types.contains(&ByzantineFaultType::Liveness));
    assert!(fault_types.contains(&ByzantineFaultType::InvalidProposal));

    Ok(())
}

#[test]
fn test_fault_processing_and_slashing() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);

    // Register a validator
    let validator_id = create_test_identity("malicious_validator");
    validator_manager.register_validator(
        validator_id.clone(),
        2000 * 1_000_000,
        200 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5,
    )?;

    let initial_stake = validator_manager
        .get_validator(&validator_id)
        .unwrap()
        .stake;

    // Record and detect double signing
    detector.record_double_sign(validator_id.clone(), 100, 1, vec![1, 2], vec![3, 4]);
    let faults = detector.detect_faults(&validator_manager)?;

    // Process the faults (apply slashing)
    detector.process_faults(faults, &mut validator_manager)?;

    // Verify slashing was applied
    let validator = validator_manager.get_validator(&validator_id).unwrap();
    assert!(validator.stake < initial_stake);

    Ok(())
}

#[test]
fn test_fault_record_cleanup() {
    let mut detector = ByzantineFaultDetector::new();

    let validator = create_test_identity("test_validator");

    // Record some faults
    detector.record_double_sign(validator.clone(), 100, 1, vec![1, 2], vec![3, 4]);
    detector.record_liveness_violation(validator.clone(), 200, 5);
    detector.record_invalid_proposal(validator.clone(), 300, [1u8; 32], "test".to_string());

    // Verify faults were recorded
    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults_before = detector.detect_faults(&validator_manager).unwrap();
    assert!(!faults_before.is_empty());

    // Clean up old records: use current time + max_age + 1000 to ensure cleanup
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cleanup_time = current_time + 86400 + 1000; // Current time + 24h + buffer
    detector.cleanup_old_records(cleanup_time);

    // After cleanup with far future timestamp, old faults should be cleaned
    let faults_after = detector.detect_faults(&validator_manager).unwrap();
    assert_eq!(faults_after.len(), 0, "Expected cleanup to remove old faults");
}

#[test]
fn test_no_false_positives() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();

    let validator = create_test_identity("good_validator");

    // Record minimal violations that shouldn't trigger detection
    detector.record_liveness_violation(validator.clone(), 100, 1); // Only 1 missed round
    detector.record_invalid_proposal(validator.clone(), 200, [1u8; 32], "test".to_string()); // Only 1 invalid proposal

    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager)?;

    // Should not detect faults for minor violations
    assert_eq!(faults.len(), 0);

    Ok(())
}

#[test]
fn test_fault_severity_levels() -> Result<()> {
    let mut detector = ByzantineFaultDetector::new();

    let validator1 = create_test_identity("critical_validator");
    let validator2 = create_test_identity("major_validator");
    let validator3 = create_test_identity("minor_validator");

    // Critical fault: double signing
    detector.record_double_sign(validator1.clone(), 100, 1, vec![1, 2], vec![3, 4]);

    // Major fault: multiple invalid proposals
    for i in 0..3 {
        detector.record_invalid_proposal(
            validator2.clone(),
            200 + i,
            [i as u8; 32],
            "test".to_string(),
        );
    }

    // Minor fault: few liveness violations
    detector.record_liveness_violation(validator3.clone(), 300, 5);

    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager)?;

    assert_eq!(faults.len(), 3);

    // Check severity levels
    for fault in faults {
        match fault.fault_type {
            ByzantineFaultType::DoubleSign => assert_eq!(fault.severity, FaultSeverity::Critical),
            ByzantineFaultType::InvalidProposal => assert_eq!(fault.severity, FaultSeverity::Major),
            ByzantineFaultType::Liveness => assert_eq!(fault.severity, FaultSeverity::Minor),
        }
    }

    Ok(())
}

#[test]
fn test_timestamp_accuracy() {
    let mut detector = ByzantineFaultDetector::new();

    let validator = create_test_identity("test_validator");
    let before_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    detector.record_double_sign(validator.clone(), 100, 1, vec![1, 2], vec![3, 4]);

    let after_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    let faults = detector.detect_faults(&validator_manager).unwrap();

    assert_eq!(faults.len(), 1);
    assert!(faults[0].detected_at >= before_time);
    assert!(faults[0].detected_at <= after_time);
}
