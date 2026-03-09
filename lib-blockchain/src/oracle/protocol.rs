//! Oracle Protocol Version and Activation Gate
//!
//! Implements R6: Protocol Upgrade mechanism for safe Oracle remediation rollout.
//!
//! This module provides deterministic activation boundaries for protocol behavior changes,
//! ensuring:
//! - Legacy behavior before activation point (height/epoch)
//! - Strict-spec behavior after activation point
//! - Deterministic, replay-safe activation decisions
//! - Governance-controlled activation scheduling
//!
//! # Activation Gate Semantics
//!
//! The activation gate uses block height as the canonical trigger because:
//! - Block height is deterministic across all nodes
//! - Block height survives restarts and replays identically
//! - Governance can schedule activation at a future block height
//! - Easy to coordinate across the network

use serde::{Deserialize, Serialize};
use tracing::info;

/// Minimum number of blocks between scheduling and activation of a protocol upgrade.
///
/// This lead time is consensus-critical and must remain consistent across all call sites
/// that validate or schedule protocol upgrades.
pub const MIN_PROTOCOL_ACTIVATION_LEAD_BLOCKS: u64 = 100;

/// Oracle protocol version for behavior selection.
///
/// This enum represents the major protocol versions. New variants should be added
/// when there are breaking changes to oracle consensus behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleProtocolVersion {
    /// Original protocol version (legacy behavior).
    ///
    /// This version maintains backward compatibility with existing deployments.
    /// Used before any activation point is reached.
    V0Legacy,

    /// Strict spec compliance version (remediation target).
    ///
    /// This version enables all remediation changes:
    /// - Canonical attestation execution path
    /// - Strict CBE graduation formula
    /// - Normalized epoch tracking
    /// - Aligned slashing semantics
    /// - Hardened API/runtime boundaries
    V1StrictSpec,
}

impl Default for OracleProtocolVersion {
    fn default() -> Self {
        Self::V0Legacy
    }
}

impl OracleProtocolVersion {
    /// Returns true if this version enables strict spec behavior.
    pub fn is_strict_spec(&self) -> bool {
        matches!(self, Self::V1StrictSpec)
    }

    /// Returns true if this version uses legacy behavior.
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::V0Legacy)
    }

    /// Get the protocol version number as u16.
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::V0Legacy => 0,
            Self::V1StrictSpec => 1,
        }
    }

    /// Create from u16, returning None for unknown versions.
    pub fn from_u16(version: u16) -> Option<Self> {
        match version {
            0 => Some(Self::V0Legacy),
            1 => Some(Self::V1StrictSpec),
            _ => None,
        }
    }
}

/// Governance-scheduled protocol activation.
///
/// Represents a pending protocol upgrade that will activate at a specific block height.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingProtocolActivation {
    /// Block height at which the protocol upgrade activates.
    pub activate_at_height: u64,

    /// Target protocol version after activation.
    pub target_version: OracleProtocolVersion,

    /// Block height when this activation was scheduled (for audit trail).
    pub scheduled_at_height: u64,

    /// Governance proposal ID that authorized this activation (optional).
    pub source_proposal_id: Option<[u8; 32]>,
}

/// Protocol version configuration and activation state.
///
/// This struct tracks the current protocol version and any pending activation.
/// It is part of OracleState and is persisted with the blockchain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleProtocolConfig {
    /// Current active protocol version.
    #[serde(default)]
    pub current_version: OracleProtocolVersion,

    /// Pending protocol activation, if scheduled.
    #[serde(default)]
    pub pending_activation: Option<PendingProtocolActivation>,

    /// Height at which current version was activated (for audit trail).
    #[serde(default)]
    pub activated_at_height: u64,
}

impl Default for OracleProtocolConfig {
    fn default() -> Self {
        Self {
            current_version: OracleProtocolVersion::V0Legacy,
            pending_activation: None,
            activated_at_height: 0,
        }
    }
}

impl OracleProtocolConfig {
    /// Create a new protocol config starting at genesis with legacy version.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a config with a specific initial version (for testing).
    #[cfg(test)]
    pub fn with_version(version: OracleProtocolVersion) -> Self {
        Self {
            current_version: version,
            pending_activation: None,
            activated_at_height: 0,
        }
    }

    /// Get the current effective protocol version.
    pub fn current_version(&self) -> OracleProtocolVersion {
        self.current_version
    }

    /// Check if strict spec behavior is active.
    pub fn is_strict_spec_active(&self) -> bool {
        self.current_version.is_strict_spec()
    }

    /// Schedule a protocol upgrade to activate at a future block height.
    ///
    /// # Arguments
    /// * `target_version` - The protocol version to activate
    /// * `activate_at_height` - Block height when upgrade activates (must be > current_height)
    /// * `current_height` - Current block height (for validation)
    /// * `source_proposal_id` - Optional governance proposal ID
    ///
    /// # Errors
    /// Returns error if activate_at_height is not in the future.
    pub fn schedule_activation(
        &mut self,
        target_version: OracleProtocolVersion,
        activate_at_height: u64,
        current_height: u64,
        source_proposal_id: Option<[u8; 32]>,
    ) -> Result<(), ProtocolScheduleError> {
        // Validate activation height is in the future
        if activate_at_height <= current_height {
            return Err(ProtocolScheduleError::InvalidActivationHeight {
                activate_at_height,
                current_height,
            });
        }

        // Enforce minimum lead time for network coordination.
        let min_activation_height =
            current_height.saturating_add(MIN_PROTOCOL_ACTIVATION_LEAD_BLOCKS);
        if activate_at_height < min_activation_height {
            return Err(ProtocolScheduleError::InsufficientLeadTime {
                activate_at_height,
                current_height,
                min_lead_blocks: MIN_PROTOCOL_ACTIVATION_LEAD_BLOCKS,
            });
        }

        // Validate we're not scheduling a downgrade
        if (target_version.as_u16()) < (self.current_version.as_u16()) {
            return Err(ProtocolScheduleError::DowngradeNotAllowed {
                current: self.current_version.as_u16(),
                requested: target_version.as_u16(),
            });
        }

        // Validate we're not scheduling the same version
        if target_version == self.current_version {
            return Err(ProtocolScheduleError::AlreadyActive);
        }

        // Check if there's already a pending activation
        if let Some(ref pending) = self.pending_activation {
            return Err(ProtocolScheduleError::AlreadyScheduled {
                existing_height: pending.activate_at_height,
            });
        }

        self.pending_activation = Some(PendingProtocolActivation {
            activate_at_height,
            target_version,
            scheduled_at_height: current_height,
            source_proposal_id,
        });

        info!(
            "🔮 Oracle protocol upgrade scheduled: v{} -> v{} at height {}",
            self.current_version.as_u16(),
            target_version.as_u16(),
            activate_at_height
        );

        Ok(())
    }

    /// Cancel any pending protocol activation.
    ///
    /// Returns true if an activation was cancelled, false if nothing was pending.
    pub fn cancel_pending_activation(&mut self) -> bool {
        if self.pending_activation.is_some() {
            let pending = self.pending_activation.take().unwrap();
            info!(
                "🔮 Oracle protocol upgrade cancelled (was scheduled for height {})",
                pending.activate_at_height
            );
            true
        } else {
            false
        }
    }

    /// Apply pending activation if the activation height has been reached.
    ///
    /// This should be called at the beginning of block processing for each block.
    ///
    /// # Arguments
    /// * `current_height` - The current block height
    ///
    /// # Returns
    /// * `Some(OracleProtocolVersion)` if activation occurred (new version)
    /// * `None` if no activation occurred
    pub fn apply_pending_activation(
        &mut self,
        current_height: u64,
    ) -> Option<OracleProtocolVersion> {
        if let Some(pending) = self.pending_activation.take() {
            if current_height >= pending.activate_at_height {
                // Activation point reached - apply the upgrade
                let old_version = self.current_version;
                self.current_version = pending.target_version;
                self.activated_at_height = current_height;

                info!(
                    "🔮 Oracle protocol upgraded: v{} -> v{} at height {} (scheduled at {})",
                    old_version.as_u16(),
                    self.current_version.as_u16(),
                    current_height,
                    pending.scheduled_at_height
                );

                Some(self.current_version)
            } else {
                // Not yet time - put it back
                self.pending_activation = Some(pending);
                None
            }
        } else {
            None
        }
    }

    /// Check if there's a pending activation.
    pub fn has_pending_activation(&self) -> bool {
        self.pending_activation.is_some()
    }

    /// Get pending activation details if any.
    pub fn pending_activation(&self) -> Option<&PendingProtocolActivation> {
        self.pending_activation.as_ref()
    }

    /// Get the block height when current version was activated.
    pub fn activated_at_height(&self) -> u64 {
        self.activated_at_height
    }
}

/// Errors that can occur when scheduling protocol activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolScheduleError {
    /// Activation height must be in the future.
    InvalidActivationHeight {
        activate_at_height: u64,
        current_height: u64,
    },

    /// Activation height must be at least the minimum lead-time ahead of current height.
    InsufficientLeadTime {
        activate_at_height: u64,
        current_height: u64,
        min_lead_blocks: u64,
    },

    /// Downgrading protocol version is not allowed.
    DowngradeNotAllowed { current: u16, requested: u16 },

    /// Target version is already active.
    AlreadyActive,

    /// Another activation is already scheduled.
    AlreadyScheduled { existing_height: u64 },
}

impl std::fmt::Display for ProtocolScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidActivationHeight {
                activate_at_height,
                current_height,
            } => write!(
                f,
                "activation height {} must be greater than current height {}",
                activate_at_height, current_height
            ),
            Self::InsufficientLeadTime {
                activate_at_height,
                current_height,
                min_lead_blocks,
            } => write!(
                f,
                "activation height {} must be at least {} blocks ahead of current height {}",
                activate_at_height, min_lead_blocks, current_height
            ),
            Self::DowngradeNotAllowed { current, requested } => write!(
                f,
                "protocol downgrade from v{} to v{} is not allowed",
                current, requested
            ),
            Self::AlreadyActive => write!(f, "target protocol version is already active"),
            Self::AlreadyScheduled { existing_height } => write!(
                f,
                "protocol upgrade already scheduled for height {}",
                existing_height
            ),
        }
    }
}

impl std::error::Error for ProtocolScheduleError {}

/// Feature flags for fine-grained behavior control within a protocol version.
///
/// These flags allow individual remediation features to be toggled independently,
/// providing maximum flexibility for testing and gradual rollout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleFeatureFlags {
    /// Enable canonical attestation execution path (R3)
    pub canonical_attestation_path: bool,

    /// Enable strict CBE graduation formula (R3)
    pub strict_cbe_graduation_formula: bool,

    /// Enable normalized epoch tracking (R4)
    pub normalized_epoch_tracking: bool,

    /// Enable on-chain config for producer policy (R8)
    pub on_chain_producer_policy: bool,

    /// Enable aligned slashing semantics (R1)
    pub aligned_slashing_semantics: bool,

    /// Enable hardened API/runtime boundaries (R9)
    pub hardened_write_boundaries: bool,

    /// Enable shadow mode for parity monitoring (R8)
    pub shadow_mode_parity: bool,
}

impl Default for OracleFeatureFlags {
    fn default() -> Self {
        Self {
            canonical_attestation_path: false,
            strict_cbe_graduation_formula: false,
            normalized_epoch_tracking: false,
            on_chain_producer_policy: false,
            aligned_slashing_semantics: false,
            hardened_write_boundaries: false,
            shadow_mode_parity: false,
        }
    }
}

impl OracleFeatureFlags {
    /// All flags disabled (legacy behavior)
    pub fn all_disabled() -> Self {
        Self::default()
    }

    /// All flags enabled (strict spec behavior)
    pub fn all_enabled() -> Self {
        Self {
            canonical_attestation_path: true,
            strict_cbe_graduation_formula: true,
            normalized_epoch_tracking: true,
            on_chain_producer_policy: true,
            aligned_slashing_semantics: true,
            hardened_write_boundaries: true,
            shadow_mode_parity: true,
        }
    }

    /// Get effective feature flags for a given protocol version.
    pub fn for_version(version: OracleProtocolVersion) -> Self {
        match version {
            OracleProtocolVersion::V0Legacy => Self::all_disabled(),
            OracleProtocolVersion::V1StrictSpec => Self::all_enabled(),
        }
    }
}

// ============================================================================
// ORACLE-R8: Observability, Parity Monitoring, and Rollback Controls
// ============================================================================

/// Parity monitoring metrics for shadow mode comparison.
///
/// Tracks agreement/disagreement between legacy and strict spec execution paths
/// during the shadow period before cutover.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleParityMetrics {
    /// Total attestations processed by both paths.
    pub total_comparisons: u64,
    /// Number of times both paths produced identical results.
    pub agreements: u64,
    /// Number of times paths produced different results.
    pub disagreements: u64,
    /// Number of slash events from legacy path.
    pub legacy_slash_count: u64,
    /// Number of slash events from strict path.
    pub strict_slash_count: u64,
    /// Last epoch where disagreement was detected.
    pub last_disagreement_epoch: Option<u64>,
    /// Block height when metrics were last updated.
    pub last_updated_height: u64,
}

impl OracleParityMetrics {
    /// Record a comparison result between legacy and strict paths.
    pub fn record_comparison(&mut self, agreed: bool, height: u64) {
        self.total_comparisons += 1;
        self.last_updated_height = height;
        if agreed {
            self.agreements += 1;
        } else {
            self.disagreements += 1;
        }
    }

    /// Record a disagreement with epoch information.
    ///
    /// This delegates counter updates to `record_comparison` to ensure
    /// `total_comparisons` and `disagreements` stay in sync.
    pub fn record_disagreement(&mut self, epoch: u64, height: u64) {
        self.record_comparison(false, height);
        self.last_disagreement_epoch = Some(epoch);
    }

    /// Calculate agreement rate as percentage (0-100).
    pub fn agreement_rate_percent(&self) -> f64 {
        if self.total_comparisons == 0 {
            return 100.0;
        }
        (self.agreements as f64 / self.total_comparisons as f64) * 100.0
    }

    /// Check if parity is within acceptable threshold for cutover.
    /// Default threshold: 99.9% agreement rate.
    pub fn is_parity_acceptable(&self, threshold_percent: f64) -> bool {
        self.agreement_rate_percent() >= threshold_percent
    }

    /// Reset all metrics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Divergence alarm configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DivergenceAlarmConfig {
    /// Agreement rate threshold below which alarm triggers (default: 95.0).
    pub alarm_threshold_percent: f64,
    /// Minimum comparisons before alarm can trigger (default: 100).
    pub min_comparisons_before_alarm: u64,
    /// Consecutive disagreements before critical alarm (default: 5).
    pub consecutive_disagreements_threshold: u64,
}

impl Default for DivergenceAlarmConfig {
    fn default() -> Self {
        Self {
            alarm_threshold_percent: 95.0,
            min_comparisons_before_alarm: 100,
            consecutive_disagreements_threshold: 5,
        }
    }
}

/// Rollback control state for emergency protocol version reversal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackControls {
    /// Whether emergency rollback is enabled.
    pub enabled: bool,
    /// The version to rollback to (typically V0Legacy).
    pub rollback_target: OracleProtocolVersion,
    /// Block height at which rollback was triggered (if any).
    pub triggered_at_height: Option<u64>,
    /// Reason for rollback (audit trail).
    pub rollback_reason: Option<String>,
    /// Who authorized the rollback (node operator identifier).
    pub authorized_by: Option<String>,
}

impl Default for RollbackControls {
    fn default() -> Self {
        Self {
            enabled: true, // Rollback is enabled by default for safety
            rollback_target: OracleProtocolVersion::V0Legacy,
            triggered_at_height: None,
            rollback_reason: None,
            authorized_by: None,
        }
    }
}

impl RollbackControls {
    /// Trigger an emergency rollback.
    pub fn trigger_rollback(
        &mut self,
        height: u64,
        reason: String,
        authorized_by: String,
    ) -> OracleProtocolVersion {
        self.triggered_at_height = Some(height);
        self.rollback_reason = Some(reason);
        self.authorized_by = Some(authorized_by);
        self.rollback_target
    }

    /// Check if a rollback has been triggered.
    pub fn is_rollback_triggered(&self) -> bool {
        self.triggered_at_height.is_some()
    }

    /// Clear rollback state (after successful rollback).
    pub fn clear_rollback(&mut self) {
        self.triggered_at_height = None;
        self.rollback_reason = None;
        self.authorized_by = None;
    }
}

/// Oracle observability state containing metrics and controls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct OracleObservabilityState {
    /// Parity monitoring metrics.
    pub parity_metrics: OracleParityMetrics,
    /// Divergence alarm configuration.
    pub divergence_config: DivergenceAlarmConfig,
    /// Rollback controls.
    pub rollback_controls: RollbackControls,
    /// Current alarm status.
    pub alarm_active: bool,
    /// Consecutive disagreements counter.
    pub consecutive_disagreements: u64,
}

impl OracleObservabilityState {
    /// Check and update alarm status based on current metrics.
    pub fn update_alarm_status(&mut self) {
        let metrics = &self.parity_metrics;
        let config = &self.divergence_config;

        if metrics.total_comparisons < config.min_comparisons_before_alarm {
            self.alarm_active = false;
            return;
        }

        let below_threshold = metrics.agreement_rate_percent() < config.alarm_threshold_percent;
        let consecutive_exceeded = self.consecutive_disagreements >= config.consecutive_disagreements_threshold;

        self.alarm_active = below_threshold || consecutive_exceeded;
    }

    /// Record a disagreement and update alarm status.
    ///
    /// Increments the consecutive disagreements counter and delegates
    /// metrics updates to parity_metrics.record_comparison to ensure
    /// total_comparisons stays in sync.
    pub fn record_disagreement(&mut self, epoch: u64, height: u64) {
        self.consecutive_disagreements += 1;
        self.parity_metrics.record_comparison(false, height);
        self.parity_metrics.last_disagreement_epoch = Some(epoch);
        self.parity_metrics.last_updated_height = height;
        self.update_alarm_status();
    }

    /// Record an agreement and reset consecutive counter.
    pub fn record_agreement(&mut self, height: u64) {
        self.consecutive_disagreements = 0;
        self.parity_metrics.record_comparison(true, height);
        self.parity_metrics.last_updated_height = height;
        self.update_alarm_status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_default_is_legacy() {
        let version = OracleProtocolVersion::default();
        assert!(version.is_legacy());
        assert!(!version.is_strict_spec());
    }

    #[test]
    fn protocol_version_u16_roundtrip() {
        assert_eq!(OracleProtocolVersion::V0Legacy.as_u16(), 0);
        assert_eq!(OracleProtocolVersion::V1StrictSpec.as_u16(), 1);

        assert_eq!(
            OracleProtocolVersion::from_u16(0),
            Some(OracleProtocolVersion::V0Legacy)
        );
        assert_eq!(
            OracleProtocolVersion::from_u16(1),
            Some(OracleProtocolVersion::V1StrictSpec)
        );
        assert_eq!(OracleProtocolVersion::from_u16(99), None);
    }

    #[test]
    fn schedule_activation_success() {
        let mut config = OracleProtocolConfig::new();
        assert_eq!(config.current_version(), OracleProtocolVersion::V0Legacy);

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            1000, // activate at height 1000
            100,  // current height is 100
            None,
        );

        assert!(result.is_ok());
        assert!(config.has_pending_activation());
        assert_eq!(
            config.pending_activation().unwrap().target_version,
            OracleProtocolVersion::V1StrictSpec
        );
    }

    #[test]
    fn schedule_activation_requires_future_height() {
        let mut config = OracleProtocolConfig::new();

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            100, // activate at height 100
            100, // current height is 100 (same)
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::InvalidActivationHeight { .. })
        ));

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            50,  // activate at height 50
            100, // current height is 100 (past)
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::InvalidActivationHeight { .. })
        ));
    }

    #[test]
    fn schedule_activation_requires_minimum_lead_time() {
        let mut config = OracleProtocolConfig::new();

        // Exactly one block short of the minimum lead time.
        let result =
            config.schedule_activation(OracleProtocolVersion::V1StrictSpec, 199, 100, None);

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::InsufficientLeadTime {
                activate_at_height: 199,
                current_height: 100,
                min_lead_blocks: MIN_PROTOCOL_ACTIVATION_LEAD_BLOCKS,
            })
        ));

        // Exact lead-time boundary is valid.
        let ok = config.schedule_activation(OracleProtocolVersion::V1StrictSpec, 200, 100, None);
        assert!(ok.is_ok());
    }

    #[test]
    fn schedule_activation_prevents_downgrade() {
        let mut config = OracleProtocolConfig::with_version(OracleProtocolVersion::V1StrictSpec);

        let result = config.schedule_activation(
            OracleProtocolVersion::V0Legacy, // try to downgrade
            1000,
            100,
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::DowngradeNotAllowed {
                current: 1,
                requested: 0
            })
        ));
    }

    #[test]
    fn schedule_activation_prevents_same_version() {
        let mut config = OracleProtocolConfig::new();

        let result = config.schedule_activation(
            OracleProtocolVersion::V0Legacy, // same as current
            1000,
            100,
            None,
        );

        assert!(matches!(result, Err(ProtocolScheduleError::AlreadyActive)));
    }

    #[test]
    fn schedule_activation_prevents_duplicate() {
        let mut config = OracleProtocolConfig::new();

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            2000, // different height
            150,  // current moved forward
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::AlreadyScheduled {
                existing_height: 1000
            })
        ));
    }

    #[test]
    fn apply_pending_activation_at_exact_height() {
        let mut config = OracleProtocolConfig::new();

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        // Before activation height
        let result = config.apply_pending_activation(999);
        assert!(result.is_none());
        assert!(config.has_pending_activation());
        assert_eq!(config.current_version(), OracleProtocolVersion::V0Legacy);

        // At activation height
        let result = config.apply_pending_activation(1000);
        assert_eq!(result, Some(OracleProtocolVersion::V1StrictSpec));
        assert!(!config.has_pending_activation());
        assert_eq!(
            config.current_version(),
            OracleProtocolVersion::V1StrictSpec
        );
        assert_eq!(config.activated_at_height(), 1000);
    }

    #[test]
    fn apply_pending_activation_after_height() {
        let mut config = OracleProtocolConfig::new();

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        // Skip past activation height (node was offline)
        let result = config.apply_pending_activation(1500);
        assert_eq!(result, Some(OracleProtocolVersion::V1StrictSpec));
        assert_eq!(
            config.current_version(),
            OracleProtocolVersion::V1StrictSpec
        );
    }

    #[test]
    fn cancel_pending_activation() {
        let mut config = OracleProtocolConfig::new();

        assert!(!config.cancel_pending_activation()); // nothing to cancel

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        assert!(config.cancel_pending_activation());
        assert!(!config.has_pending_activation());
        assert_eq!(config.current_version(), OracleProtocolVersion::V0Legacy);
    }

    #[test]
    fn feature_flags_for_legacy_version() {
        let flags = OracleFeatureFlags::for_version(OracleProtocolVersion::V0Legacy);
        assert!(!flags.canonical_attestation_path);
        assert!(!flags.strict_cbe_graduation_formula);
        assert!(!flags.normalized_epoch_tracking);
    }

    #[test]
    fn feature_flags_for_strict_spec_version() {
        let flags = OracleFeatureFlags::for_version(OracleProtocolVersion::V1StrictSpec);
        assert!(flags.canonical_attestation_path);
        assert!(flags.strict_cbe_graduation_formula);
        assert!(flags.normalized_epoch_tracking);
        assert!(flags.on_chain_producer_policy);
        assert!(flags.aligned_slashing_semantics);
        assert!(flags.hardened_write_boundaries);
        assert!(flags.shadow_mode_parity);
    }

    #[test]
    fn protocol_config_serialization_roundtrip() {
        let mut config = OracleProtocolConfig::new();
        config
            .schedule_activation(
                OracleProtocolVersion::V1StrictSpec,
                1000,
                100,
                Some([1u8; 32]),
            )
            .unwrap();

        let serialized = bincode::serialize(&config).unwrap();
        let deserialized: OracleProtocolConfig = bincode::deserialize(&serialized).unwrap();

        assert_eq!(config.current_version, deserialized.current_version);
        assert_eq!(config.pending_activation, deserialized.pending_activation);
        assert_eq!(config.activated_at_height, deserialized.activated_at_height);
    }

    // =========================================================================
    // ORACLE-R8: Observability Tests
    // =========================================================================

    #[test]
    fn parity_metrics_calculates_agreement_rate() {
        let mut metrics = OracleParityMetrics::default();
        
        // No comparisons yet - should be 100%
        assert_eq!(metrics.agreement_rate_percent(), 100.0);
        
        // Record some comparisons
        metrics.record_comparison(true, 100);   // agreement
        metrics.record_comparison(true, 101);   // agreement
        metrics.record_comparison(false, 102);  // disagreement
        
        assert_eq!(metrics.total_comparisons, 3);
        assert_eq!(metrics.agreements, 2);
        assert_eq!(metrics.disagreements, 1);
        assert!((metrics.agreement_rate_percent() - 66.67).abs() < 0.1);
    }

    #[test]
    fn parity_metrics_parity_acceptable_threshold() {
        let mut metrics = OracleParityMetrics::default();
        
        // Add 1000 comparisons with 5 disagreements (99.5% agreement)
        for i in 0..995 {
            metrics.record_comparison(true, i);
        }
        for i in 995..1000 {
            metrics.record_comparison(false, i);
        }
        
        // Should not be acceptable at 99.9% threshold
        assert!(!metrics.is_parity_acceptable(99.9));
        // Should be acceptable at 99.0% threshold
        assert!(metrics.is_parity_acceptable(99.0));
    }

    #[test]
    fn rollback_controls_trigger_and_clear() {
        let mut controls = RollbackControls::default();
        
        assert!(!controls.is_rollback_triggered());
        assert!(controls.enabled);
        
        let target = controls.trigger_rollback(
            1000,
            "Divergence alarm triggered".to_string(),
            "operator-1".to_string(),
        );
        
        assert!(controls.is_rollback_triggered());
        assert_eq!(target, OracleProtocolVersion::V0Legacy);
        assert_eq!(controls.triggered_at_height, Some(1000));
        assert_eq!(controls.rollback_reason, Some("Divergence alarm triggered".to_string()));
        assert_eq!(controls.authorized_by, Some("operator-1".to_string()));
        
        controls.clear_rollback();
        assert!(!controls.is_rollback_triggered());
    }

    #[test]
    fn observability_alarm_triggers_on_low_agreement() {
        let mut state = OracleObservabilityState::default();
        state.divergence_config.min_comparisons_before_alarm = 10;
        state.divergence_config.alarm_threshold_percent = 95.0;
        
        // Not enough comparisons yet
        for i in 0..5 {
            state.record_agreement(i);
        }
        assert!(!state.alarm_active);
        
        // Add more comparisons but keep agreement high
        for i in 5..15 {
            state.record_agreement(i);
        }
        assert!(!state.alarm_active);
        
        // Now add many disagreements to drop agreement rate
        for i in 15..25 {
            state.record_disagreement(i, i);
        }
        // Agreement rate is now 15/25 = 60%, below 95% threshold
        assert!(state.alarm_active);
    }

    #[test]
    fn observability_alarm_triggers_on_consecutive_disagreements() {
        let mut state = OracleObservabilityState::default();
        // Set threshold to 0% so only consecutive disagreements can trigger alarm
        state.divergence_config.min_comparisons_before_alarm = 0;
        state.divergence_config.alarm_threshold_percent = 0.0;
        state.divergence_config.consecutive_disagreements_threshold = 3;
        
        // Add some agreements first
        for i in 0..5 {
            state.record_agreement(i);
        }
        assert!(!state.alarm_active);
        
        // Now add consecutive disagreements
        state.record_disagreement(100, 10);
        assert_eq!(state.consecutive_disagreements, 1);
        assert!(!state.alarm_active);
        state.record_disagreement(101, 11);
        assert_eq!(state.consecutive_disagreements, 2);
        assert!(!state.alarm_active);
        state.record_disagreement(102, 12);
        assert_eq!(state.consecutive_disagreements, 3);
        // 3 consecutive disagreements should trigger alarm
        assert!(state.alarm_active);
        
        // One agreement should reset consecutive counter and clear alarm
        state.record_agreement(13);
        assert!(!state.alarm_active);
        assert_eq!(state.consecutive_disagreements, 0);
    }
}
