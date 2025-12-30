//! Byzantine fault detection system

use crate::types::SlashType;
use crate::validators::ValidatorManager;
use anyhow::Result;
use lib_identity::IdentityId;
use std::collections::HashMap;

/// Byzantine fault detector
#[derive(Debug, Clone)]
pub struct ByzantineFaultDetector {
    /// Detected double-signing events
    double_signs: HashMap<IdentityId, Vec<DoubleSignEvent>>,
    /// Liveness violations
    liveness_violations: HashMap<IdentityId, Vec<LivenessViolation>>,
    /// Invalid proposal attempts
    invalid_proposals: HashMap<IdentityId, Vec<InvalidProposalEvent>>,
}

/// Double signing event
#[derive(Debug, Clone)]
pub struct DoubleSignEvent {
    pub validator: IdentityId,
    pub height: u64,
    pub round: u32,
    pub first_signature: Vec<u8>,
    pub second_signature: Vec<u8>,
    pub detected_at: u64,
}

/// Liveness violation event
#[derive(Debug, Clone)]
pub struct LivenessViolation {
    pub validator: IdentityId,
    pub height: u64,
    pub expected_participation: bool,
    pub actual_participation: bool,
    pub missed_rounds: u32,
    pub detected_at: u64,
}

/// Invalid proposal event
#[derive(Debug, Clone)]
pub struct InvalidProposalEvent {
    pub validator: IdentityId,
    pub height: u64,
    pub proposal_hash: [u8; 32],
    pub violation_type: String,
    pub detected_at: u64,
}

impl ByzantineFaultDetector {
    /// Create a new Byzantine fault detector
    pub fn new() -> Self {
        Self {
            double_signs: HashMap::new(),
            liveness_violations: HashMap::new(),
            invalid_proposals: HashMap::new(),
        }
    }

    /// Detect Byzantine faults among validators
    pub fn detect_faults(
        &mut self,
        validator_manager: &ValidatorManager,
    ) -> Result<Vec<ByzantineFault>> {
        let mut detected_faults = Vec::new();

        // Check for double signing
        for (validator_id, events) in &self.double_signs {
            if !events.is_empty() {
                detected_faults.push(ByzantineFault {
                    validator: validator_id.clone(),
                    fault_type: ByzantineFaultType::DoubleSign,
                    evidence: format!("Double signed {} times", events.len()),
                    severity: FaultSeverity::Critical,
                    detected_at: events.last().unwrap().detected_at,
                });
            }
        }

        // Check for liveness violations
        for (validator_id, violations) in &self.liveness_violations {
            let recent_violations = violations.iter().filter(|v| v.missed_rounds >= 3).count();

            if recent_violations > 0 {
                detected_faults.push(ByzantineFault {
                    validator: validator_id.clone(),
                    fault_type: ByzantineFaultType::Liveness,
                    evidence: format!("Missed {} rounds in recent violations", recent_violations),
                    severity: if recent_violations >= 10 {
                        FaultSeverity::Critical
                    } else {
                        FaultSeverity::Minor
                    },
                    detected_at: violations.last().unwrap().detected_at,
                });
            }
        }

        // Check for invalid proposals
        for (validator_id, events) in &self.invalid_proposals {
            if events.len() >= 3 {
                detected_faults.push(ByzantineFault {
                    validator: validator_id.clone(),
                    fault_type: ByzantineFaultType::InvalidProposal,
                    evidence: format!("Made {} invalid proposals", events.len()),
                    severity: FaultSeverity::Major,
                    detected_at: events.last().unwrap().detected_at,
                });
            }
        }

        Ok(detected_faults)
    }

    /// Record a double signing event
    pub fn record_double_sign(
        &mut self,
        validator: IdentityId,
        height: u64,
        round: u32,
        first_signature: Vec<u8>,
        second_signature: Vec<u8>,
    ) {
        let event = DoubleSignEvent {
            validator: validator.clone(),
            height,
            round,
            first_signature,
            second_signature,
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.double_signs
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Record a liveness violation
    pub fn record_liveness_violation(
        &mut self,
        validator: IdentityId,
        height: u64,
        missed_rounds: u32,
    ) {
        let violation = LivenessViolation {
            validator: validator.clone(),
            height,
            expected_participation: true,
            actual_participation: false,
            missed_rounds,
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.liveness_violations
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(violation);
    }

    /// Record an invalid proposal
    pub fn record_invalid_proposal(
        &mut self,
        validator: IdentityId,
        height: u64,
        proposal_hash: [u8; 32],
        violation_type: String,
    ) {
        let event = InvalidProposalEvent {
            validator: validator.clone(),
            height,
            proposal_hash,
            violation_type,
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.invalid_proposals
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Process detected faults and apply penalties
    pub fn process_faults(
        &mut self,
        faults: Vec<ByzantineFault>,
        validator_manager: &mut ValidatorManager,
    ) -> Result<()> {
        for fault in faults {
            match fault.fault_type {
                ByzantineFaultType::DoubleSign => {
                    let slash_percentage = match fault.severity {
                        FaultSeverity::Critical => 10, // 10% slash for double signing
                        _ => 5,
                    };

                    if let Err(e) = validator_manager.slash_validator(
                        &fault.validator,
                        SlashType::DoubleSign,
                        slash_percentage,
                    ) {
                        tracing::warn!("Failed to slash validator for double signing: {}", e);
                    }
                }
                ByzantineFaultType::Liveness => {
                    let slash_percentage = match fault.severity {
                        FaultSeverity::Critical => 3, // 3% slash for severe liveness violations
                        _ => 1,                       // 1% slash for minor violations
                    };

                    if let Err(e) = validator_manager.slash_validator(
                        &fault.validator,
                        SlashType::Liveness,
                        slash_percentage,
                    ) {
                        tracing::warn!("Failed to slash validator for liveness violation: {}", e);
                    }
                }
                ByzantineFaultType::InvalidProposal => {
                    if let Err(e) = validator_manager.slash_validator(
                        &fault.validator,
                        SlashType::InvalidProposal,
                        2, // 2% slash for invalid proposals
                    ) {
                        tracing::warn!("Failed to slash validator for invalid proposal: {}", e);
                    }
                }
            }

            tracing::warn!(
                " Byzantine fault detected: {:?} by validator {:?} - {}",
                fault.fault_type,
                fault.validator,
                fault.evidence
            );
        }

        Ok(())
    }

    /// Clear old fault records to prevent memory bloat
    pub fn cleanup_old_records(&mut self, max_age_seconds: u64) {
        let cutoff_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(max_age_seconds);

        // Clean double signs
        self.double_signs.retain(|_, events| {
            events.retain(|event| event.detected_at > cutoff_time);
            !events.is_empty()
        });

        // Clean liveness violations
        self.liveness_violations.retain(|_, violations| {
            violations.retain(|violation| violation.detected_at > cutoff_time);
            !violations.is_empty()
        });

        // Clean invalid proposals
        self.invalid_proposals.retain(|_, events| {
            events.retain(|event| event.detected_at > cutoff_time);
            !events.is_empty()
        });
    }
}

/// Byzantine fault information
#[derive(Debug, Clone)]
pub struct ByzantineFault {
    pub validator: IdentityId,
    pub fault_type: ByzantineFaultType,
    pub evidence: String,
    pub severity: FaultSeverity,
    pub detected_at: u64,
}

/// Types of Byzantine faults
#[derive(Debug, Clone, PartialEq)]
pub enum ByzantineFaultType {
    /// Validator signed multiple blocks at the same height
    DoubleSign,
    /// Validator failed to participate in consensus
    Liveness,
    /// Validator made an invalid proposal
    InvalidProposal,
}

/// Severity levels for Byzantine faults
#[derive(Debug, Clone, PartialEq)]
pub enum FaultSeverity {
    /// Minor fault with small penalty
    Minor,
    /// Major fault with significant penalty
    Major,
    /// Critical fault requiring immediate action
    Critical,
}
